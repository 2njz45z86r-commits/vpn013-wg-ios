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
    private let magic: Data
    let isAutomaticControl: Bool

    init(secret: Data, id: String, ciphertext: Data) throws {
        try self.init(secret: secret, id: id, ciphertext: ciphertext, automaticControl: false)
    }
    static func automaticControl(secret: Data, id: String, ciphertext: Data) throws -> Self {
        try Self(secret: secret, id: id, ciphertext: ciphertext, automaticControl: true)
    }
    private init(secret: Data, id: String, ciphertext: Data, automaticControl: Bool) throws {
        guard secret.count == 32, UUID(uuidString: id)?.uuidString == id,
              (28...1_048_604).contains(ciphertext.count) else { throw Failure.invalid }
        isAutomaticControl = automaticControl
        magic = Data((automaticControl ? "R013AC01" : "R013ST01").utf8)
        let salt = Data(SHA256.hash(data: Data(id.utf8) + ciphertext))
        let material = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret),
            salt: salt, info: Data((automaticControl ? "vpn013-automatic-control-v1" : "vpn013-read-only-statistics-v1").utf8), outputByteCount: 72)
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
        guard allowed(operation), nonce.count == 32 else { throw Failure.invalid }
        let body = magic + Data([operation]) + nonce
        return body + Data(HMAC<SHA256>.authenticationCode(for: body, using: requestKey))
    }
    func authenticate(_ frame: Data) -> UInt8? {
        guard frame.count == 73, frame.prefix(8) == magic,
              allowed(frame[8]),
              HMAC<SHA256>.isValidAuthenticationCode(frame.suffix(32),
                authenticating: frame.prefix(41), using: requestKey) else { return nil }
        return frame[8]
    }
    private func allowed(_ operation: UInt8) -> Bool {
        isAutomaticControl ? [9, 10].contains(operation) : [3, 6, 8].contains(operation)
    }
    static func commandNonce(milliseconds: UInt64, random: Data) throws -> Data {
        guard random.count == 24 else { throw Failure.invalid }
        return Data((0..<8).reversed().map { UInt8((milliseconds >> ($0 * 8)) & 255) }) + random
    }
    func commandStamp(_ frame: Data, now: Date = Date()) -> UInt64? {
        guard isAutomaticControl, authenticate(frame) != nil else { return nil }
        let stamp = frame[9..<17].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let milliseconds = now.timeIntervalSince1970 * 1000
        guard milliseconds.isFinite, abs(Double(stamp) - milliseconds) <= 30_000 else { return nil }
        return stamp
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
    private let command: ((UInt8, UInt64, Data, @escaping (Data?) -> Void) -> Void)?
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
        precondition(!credentials.isAutomaticControl)
        self.credentials = credentials; self.read = read; command = nil
    }
    init(controlCredentials: VPN013LocalStatisticsCredentials,
         command: @escaping (UInt8, UInt64, Data, @escaping (Data?) -> Void) -> Void) {
        precondition(controlCredentials.isAutomaticControl)
        credentials = controlCredentials; read = { _, reply in reply(nil) }; self.command = command
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
            let respond: (Data?) -> Void = { [weak self] reply in
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
            if let command = self.command {
                guard let stamp = self.credentials.commandStamp(data) else { connection.cancel(); return }
                command(operation, stamp, Data(SHA256.hash(data: data)), respond)
            } else { self.read(operation, respond) }
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
        let random = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let nonce = credentials.isAutomaticControl
            ? try VPN013LocalStatisticsCredentials.commandNonce(milliseconds: UInt64(Date().timeIntervalSince1970 * 1000), random: Data(random.prefix(24)))
            : random
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

/// Provider-private, authenticated mode and replay watermark. It is bound to
/// the exact encrypted profile revision; it contains no VPN configuration.
/// Commit before acknowledging/applying a command, including across OS restarts.
final class VPN013AutomaticSessionState {
    private struct Record: Codable {
        var enabled: Bool
        var stamp: UInt64 = 0
        var digest = Data()
    }
    private let url: URL
    private let revision: Data
    private let key: SymmetricKey
    private var record: Record
    var enabled: Bool { record.enabled }

    init(directory: URL, secret: Data, id: String, ciphertext: Data,
         initialEnabled: Bool) throws {
        guard secret.count == 32, UUID(uuidString: id)?.uuidString == id,
              (28...1_048_604).contains(ciphertext.count) else { throw VPN013LocalStatisticsCredentials.Failure.invalid }
        revision = Data(SHA256.hash(data: Data(id.utf8) + ciphertext))
        key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret), salt: revision,
            info: Data("vpn013-provider-automatic-state-v1".utf8), outputByteCount: 32)
        url = directory.appendingPathComponent(id + ".automatic", isDirectory: false)
        record = Record(enabled: initialEnabled)
        if FileManager.default.fileExists(atPath: url.path) {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard attributes[.type] as? FileAttributeType == .typeRegular,
                  let size = attributes[.size] as? NSNumber, size.intValue <= 2048 else {
                throw VPN013LocalStatisticsCredentials.Failure.invalid
            }
            let data = try Data(contentsOf: url)
            guard data.count >= 60 else { throw VPN013LocalStatisticsCredentials.Failure.invalid }
            if data.prefix(32) == revision {
                let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: data.dropFirst(32)),
                    using: key, authenticating: revision)
                record = try JSONDecoder().decode(Record.self, from: plaintext)
                guard record.digest.isEmpty && record.stamp == 0 || record.digest.count == 32 && record.stamp > 0 else {
                    throw VPN013LocalStatisticsCredentials.Failure.invalid
                }
                return
            }
        }
        try save(record)
    }
    /// An exact retry of the most recently committed command is idempotent.
    /// Older/reordered commands cannot revert a later setting.
    func accept(operation: UInt8, stamp: UInt64, digest: Data, now: Date = Date()) throws -> Bool {
        guard [9, 10].contains(operation), digest.count == 32,
              abs(Double(stamp) - now.timeIntervalSince1970 * 1000) <= 30_000 else {
            throw VPN013LocalStatisticsCredentials.Failure.invalid
        }
        let enabled = operation == 10
        if stamp == record.stamp, digest == record.digest, enabled == record.enabled { return enabled }
        guard stamp > record.stamp else { throw VPN013LocalStatisticsCredentials.Failure.invalid }
        let next = Record(enabled: enabled, stamp: stamp, digest: digest)
        try save(next); record = next
        return enabled
    }
    private func save(_ next: Record) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        guard let box = try AES.GCM.seal(JSONEncoder().encode(next), using: key, authenticating: revision).combined else {
            throw VPN013LocalStatisticsCredentials.Failure.invalid
        }
        #if os(iOS)
        try (revision + box).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try (revision + box).write(to: url, options: .atomic)
        #endif
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var excluded = url; try excluded.setResourceValues(values)
    }
}

/// Host-only conservative identity history. Enabling Auto may change the member
/// even if its acknowledgement is lost. Never show the seed as current later.
enum VPN013AutomaticIdentityHistory {
    static func revision(_ ciphertext: Data) -> String { SHA256.hash(data: ciphertext).map { String(format: "%02x", $0) }.joined() }
    static func rememberEnabled(id: String, ciphertext: Data, defaults: UserDefaults = .standard) {
        defaults.set(revision(ciphertext), forKey: "VPN013AutomaticIdentityV1." + id)
    }
    static func required(id: String, ciphertext: Data, initial: Bool, defaults: UserDefaults = .standard) -> Bool {
        initial || defaults.string(forKey: "VPN013AutomaticIdentityV1." + id) == revision(ciphertext)
    }
}
