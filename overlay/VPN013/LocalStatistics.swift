// SPDX-License-Identifier: MIT
import Foundation
import CryptoKit
import Network

/// Read-only fallback for a running provider. Never exports the profile key or
/// raw UAPI. Both processes already own the authenticated private profile key.
struct VPN013LocalStatisticsCredentials {
    enum Failure: Error { case unavailable, invalid }
    static let maximumReply = 32_768
    let ports: [UInt16]
    private let requestKey: SymmetricKey
    private let responseKey: SymmetricKey
    private static let magic = Data("R013ST01".utf8)

    init(secret: Data, id: String, ciphertext: Data) throws {
        guard secret.count == 32, UUID(uuidString: id)?.uuidString == id,
              (28...1_048_604).contains(ciphertext.count) else { throw Failure.invalid }
        let salt = Data(SHA256.hash(data: Data(id.utf8) + ciphertext))
        let material = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret),
            salt: salt, info: Data("vpn013-read-only-statistics-v1".utf8), outputByteCount: 72)
            .withUnsafeBytes { Data($0) }
        requestKey = SymmetricKey(data: material.prefix(32))
        responseKey = SymmetricKey(data: material.dropFirst(32).prefix(32))
        var values: [UInt16] = []
        for i in stride(from: 64, to: 72, by: 2) {
            var port = UInt16(49_152 + ((Int(material[i]) << 8 | Int(material[i + 1])) % 16_384))
            while values.contains(port) { port = port == 65_535 ? 49_152 : port + 1 }
            values.append(port)
        }
        ports = values
    }

    func request(operation: UInt8, nonce: Data) throws -> Data {
        guard [3, 6].contains(operation), nonce.count == 32 else { throw Failure.invalid }
        let body = Self.magic + Data([operation]) + nonce
        return body + Data(HMAC<SHA256>.authenticationCode(for: body, using: requestKey))
    }
    func authenticate(_ frame: Data) -> UInt8? {
        guard frame.count == 73, frame.prefix(8) == Self.magic,
              [3, 6].contains(frame[8]),
              HMAC<SHA256>.isValidAuthenticationCode(frame.suffix(32),
                authenticating: frame.prefix(41), using: requestKey) else { return nil }
        return frame[8]
    }
    func seal(_ data: Data, request: Data) throws -> Data {
        guard authenticate(request) != nil, !data.isEmpty,
              data.count <= Self.maximumReply else { throw Failure.invalid }
        guard let result = try AES.GCM.seal(data, using: responseKey,
            authenticating: request.prefix(41)).combined else { throw Failure.invalid }
        return result
    }
    func open(_ data: Data, request: Data) throws -> Data {
        guard authenticate(request) != nil, (29...(Self.maximumReply + 28)).contains(data.count) else {
            throw Failure.invalid
        }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: responseKey,
            authenticating: request.prefix(41))
    }
}

/// Serial ownership, two admitted sockets, one bounded request per socket.
/// Binding explicitly to 127.0.0.1 prevents access over Wi-Fi/mobile interfaces.
final class VPN013LocalStatisticsServer {
    typealias Read = (UInt8, @escaping (Data?) -> Void) -> Void
    private let credentials: VPN013LocalStatisticsCredentials
    private let read: Read
    private let queue = DispatchQueue(label: "com.vpn013.statistics.listener")
    private var listener: NWListener?
    private var connections: [UUID: NWConnection] = [:]
    private var running = false
    private var stopping = false
    private var stopCompletions: [() -> Void] = []
    private var stoppingOwner: VPN013LocalStatisticsServer?
    private var responded: Set<UUID> = []
    private var portIndex = 0
    private var period = ProcessInfo.processInfo.systemUptime
    private var admitted = 0

    init(credentials: VPN013LocalStatisticsCredentials, read: @escaping Read) {
        self.credentials = credentials; self.read = read
    }
    func start() { queue.async { guard !self.running && !self.stopping else { return }; self.running = true; self.bind() } }
    func stop(completion: @escaping () -> Void) {
        queue.async {
            self.stopCompletions.append(completion); self.stoppingOwner = self
            self.stopping = true; self.running = false
            self.listener?.cancel()
            for connection in self.connections.values { connection.cancel() }
            self.finishStop()
        }
    }
    private func finishStop() {
        guard stopping, listener == nil, connections.isEmpty else { return }
        let callbacks = stopCompletions; stopCompletions.removeAll()
        for callback in callbacks { callback() }
        stoppingOwner = nil
    }
    private func bind() {
        guard running, portIndex < credentials.ports.count else { return }
        let port = NWEndpoint.Port(rawValue: credentials.ports[portIndex])!
        portIndex += 1
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: port)
        parameters.allowLocalEndpointReuse = false
        do {
            let value = try NWListener(using: parameters); listener = value
            value.stateUpdateHandler = { [weak self, weak value] state in
                guard let self = self, let value = value, self.listener === value else { return }
                switch state {
                case .failed:
                    value.cancel()
                case .cancelled:
                    self.listener = nil
                    if self.running { self.bind() } else { self.finishStop() }
                default: break
                }
            }
            value.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
            value.start(queue: queue)
        } catch { bind() }
    }
    private func accept(_ connection: NWConnection) {
        let now = ProcessInfo.processInfo.systemUptime
        if now - period >= 1 { period = now; admitted = 0 }
        guard running, connections.count < 2, admitted < 8,
              case .hostPort(let host, _) = connection.endpoint,
              host == .ipv4(.loopback) else { connection.cancel(); return }
        admitted += 1
        let id = UUID(); connections[id] = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            if case .failed = state { connection.cancel() }
            if case .cancelled = state {
                connection.stateUpdateHandler = nil
                self.responded.remove(id); self.connections.removeValue(forKey: id); self.finishStop()
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 2) { [weak self] in self?.connections[id]?.cancel() }
        connection.receive(minimumIncompleteLength: 73, maximumLength: 73) { [weak self] data, _, _, error in
            guard let self = self, self.running, self.connections[id] != nil,
                  error == nil, let data = data,
                  let operation = self.credentials.authenticate(data) else { connection.cancel(); return }
            self.read(operation) { [weak self] reply in
                guard let self = self else { return }
                self.queue.async {
                    guard self.running, self.connections[id] != nil,
                          self.responded.insert(id).inserted, let reply = reply,
                          let sealed = try? self.credentials.seal(reply, request: data) else {
                        connection.cancel(); return
                    }
                    let size = UInt32(sealed.count)
                    let header = Data([UInt8(size >> 24), UInt8((size >> 16) & 255),
                        UInt8((size >> 8) & 255), UInt8(size & 255)])
                    connection.send(content: header + sealed, contentContext: .finalMessage,
                        isComplete: true, completion: .contentProcessed { error in
                            if error != nil { connection.cancel(); return }
                            connection.receive(minimumIncompleteLength: 1, maximumLength: 1) { _, _, _, _ in connection.cancel() }
                        })
                }
            }
        }
    }
}

/// A forged localhost responder cannot supply metrics: each reply is encrypted
/// and authenticated to this request's random nonce and exact profile revision.
final class VPN013LocalStatisticsRead {
    private let queue = DispatchQueue(label: "com.vpn013.statistics.reader")
    private let credentials: VPN013LocalStatisticsCredentials
    private let request: Data
    private var connection: NWConnection?
    private var portIndex = 0
    private var ended = false
    private var completion: ((Result<Data, Error>) -> Void)?

    init(credentials: VPN013LocalStatisticsCredentials, operation: UInt8) throws {
        self.credentials = credentials
        let nonce = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        request = try credentials.request(operation: operation, nonce: nonce)
    }
    func start(completion: @escaping (Result<Data, Error>) -> Void) {
        queue.async {
            guard self.completion == nil, !self.ended else { return }
            self.completion = completion
            self.queue.asyncAfter(deadline: .now() + 2.5) { self.finish(.failure(VPN013LocalStatisticsCredentials.Failure.unavailable)) }
            self.next()
        }
    }
    func cancel() { queue.async { self.finish(nil) } }
    private func finish(_ result: Result<Data, Error>?) {
        guard !ended else { return }; ended = true
        connection?.cancel(); connection = nil
        let callback = completion; completion = nil
        if let result = result { DispatchQueue.main.async { callback?(result) } }
    }
    private func next() {
        guard !ended else { return }
        connection?.cancel(); connection = nil
        guard portIndex < credentials.ports.count else {
            finish(.failure(VPN013LocalStatisticsCredentials.Failure.unavailable)); return
        }
        let port = NWEndpoint.Port(rawValue: credentials.ports[portIndex])!; portIndex += 1
        let value = NWConnection(host: .ipv4(.loopback), port: port, using: .tcp)
        connection = value
        value.stateUpdateHandler = { [weak self, weak value] state in
            guard let self = self, let value = value, self.connection === value, !self.ended else { return }
            switch state {
            case .ready:
                value.send(content: self.request, completion: .contentProcessed { [weak self, weak value] error in
                    guard let self = self, let value = value, self.connection === value, !self.ended else { return }
                    if error != nil { self.next(); return }
                    self.receiveHeader(value)
                })
            case .failed: self.next()
            default: break
            }
        }
        value.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 0.6) { [weak self, weak value] in
            guard let self = self, let value = value, self.connection === value, !self.ended else { return }
            self.next()
        }
    }
    private func receiveHeader(_ value: NWConnection) {
        value.receive(minimumIncompleteLength: 4, maximumLength: 4) { [weak self, weak value] data, _, _, error in
            guard let self = self, let value = value, self.connection === value, !self.ended else { return }
            guard error == nil, let data = data, data.count == 4 else { self.next(); return }
            let count = data.reduce(0) { ($0 << 8) | Int($1) }
            guard (29...(VPN013LocalStatisticsCredentials.maximumReply + 28)).contains(count) else { self.next(); return }
            value.receive(minimumIncompleteLength: count, maximumLength: count) { [weak self, weak value] body, _, _, error in
                guard let self = self, let value = value, self.connection === value, !self.ended else { return }
                guard error == nil, let body = body, body.count == count,
                      let reply = try? self.credentials.open(body, request: self.request) else { self.next(); return }
                self.finish(.success(reply))
            }
        }
    }
}
