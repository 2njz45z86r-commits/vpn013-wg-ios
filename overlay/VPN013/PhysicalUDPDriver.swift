// SPDX-License-Identifier: MIT
// Experimental Swift/C/Go transport. Not linked into a released client.
import Foundation
import NetworkExtension

private enum PhysicalDriverRegistry {
    static let lock = NSLock()
    static var next: UInt64 = 0
    // Retain until explicit invalidation and acknowledged socket closure.
    static var drivers: [UInt64: R013UDPDriver] = [:]
    static func find(_ owner: UInt64) -> R013UDPDriver? {
        lock.lock(); defer { lock.unlock() }; return drivers[owner]
    }
}

private func physicalOpen(_ owner: UInt64, _ token: UInt64,
                          _ host: UnsafePointer<CChar>?, _ port: UInt16) -> Int32 {
    guard let host = host, let text = String(validatingUTF8: host), text.count <= 128,
          port != 0, let driver = PhysicalDriverRegistry.find(owner) else { return 1 }
    return driver.open(token: token, host: text, port: port)
}
private func physicalWrite(_ owner: UInt64, _ token: UInt64,
                           _ bytes: UnsafeRawPointer?, _ length: UInt32, _ write: UInt64) {
    guard length <= 65535, (bytes != nil || length == 0),
          let driver = PhysicalDriverRegistry.find(owner) else {
        R013UDPWriteDone(token, write, 1); return
    }
    // C frees its buffer as soon as this callback returns.
    let packet = length == 0 ? Data() : Data(bytes: bytes!, count: Int(length))
    driver.write(token: token, packet: packet, writeID: write)
}
private func physicalCancel(_ owner: UInt64, _ token: UInt64) {
    guard let driver = PhysicalDriverRegistry.find(owner) else {
        // No socket-closed acknowledgement can be invented here.
        R013UDPFailed(token); return
    }
    driver.cancel(token: token)
}
private func driverQuiesced(_ owner: UInt64) {
    PhysicalDriverRegistry.find(owner)?.quiesced()
}

final class R013UDPDriver {
    private enum Route: UInt32 { case physical = 1, throughTunnel = 2 }
    private final class Entry {
        let token: UInt64
        let session: NWUDPSession
        let readLock = NSLock()
        var finished = false
        var observer: NSKeyValueObservation?
        var pending: (UInt64, Data)?
        var writing = false
        var cancelling = false
        var cancelled = false
        init(_ token: UInt64, _ session: NWUDPSession) { self.token = token; self.session = session }
    }
    private weak var provider: NEPacketTunnelProvider?
    private let route: Route
    private let queue = DispatchQueue(label: "com.vpn013.probe.udp", qos: .utility)
    private let queueKey = DispatchSpecificKey<Bool>()
    private var entries: [UInt64: Entry] = [:]
    private var stopping = false
    private var invalidated = false
    private var completions: [() -> Void] = []
    private(set) var driverID: UInt64 = 0
    private var owner: UInt64 = 0

    static func physical(provider: NEPacketTunnelProvider) -> R013UDPDriver? {
        return R013UDPDriver(provider: provider, route: .physical)
    }
    static func throughTunnel(provider: NEPacketTunnelProvider) -> R013UDPDriver? {
        return R013UDPDriver(provider: provider, route: .throughTunnel)
    }
    private init?(provider: NEPacketTunnelProvider, route: Route) {
        self.provider = provider
        self.route = route
        queue.setSpecific(key: queueKey, value: true)
        PhysicalDriverRegistry.lock.lock()
        guard PhysicalDriverRegistry.drivers.count < 2 else {
            PhysicalDriverRegistry.lock.unlock(); return nil
        }
        PhysicalDriverRegistry.next += 1; owner = PhysicalDriverRegistry.next
        PhysicalDriverRegistry.drivers[owner] = self
        PhysicalDriverRegistry.lock.unlock()
        var callbacks = r013_udp_driver()
        callbacks.owner = owner; callbacks.route = route.rawValue; callbacks.open = physicalOpen
        callbacks.write = physicalWrite; callbacks.cancel = physicalCancel
        callbacks.quiesced = driverQuiesced
        driverID = R013RegisterUDPDriver(callbacks)
        if driverID == 0 {
            PhysicalDriverRegistry.lock.lock(); PhysicalDriverRegistry.drivers.removeValue(forKey: owner)
            PhysicalDriverRegistry.lock.unlock(); return nil
        }
    }

    fileprivate func open(token: UInt64, host: String, port: UInt16) -> Int32 {
        let create: () -> Int32 = { [self] in
            guard !stopping, entries.isEmpty, let provider = provider else { return 1 }
            let endpoint = NWHostEndpoint(hostname: host, port: String(port))
            // Fixed per registration; the Go bridge rejects cross-role reuse.
            let created: NWUDPSession?
            switch route {
            case .physical: created = provider.createUDPSession(to: endpoint, from: nil) as NWUDPSession?
            case .throughTunnel: created = provider.createUDPSessionThroughTunnel(to: endpoint, from: nil) as NWUDPSession?
            }
            guard let session = created else { return 1 }
            let entry = Entry(token, session); entries[token] = entry
            session.setReadHandler({ [weak self, weak entry] datagrams, error in
                guard let self = self, let entry = entry else { return }
                if error != nil {
                    self.queue.async { R013UDPFailed(token); self.cancelEntry(entry) }; return
                }
                // Copy into Go's bounded four-packet queue immediately. Do not
                // enqueue unbounded Data captures on a Swift dispatch queue.
                entry.readLock.lock(); defer { entry.readLock.unlock() }
                guard !entry.finished else { return }
                for packet in (datagrams ?? []).prefix(1) where packet.count <= 65535 {
                    packet.withUnsafeBytes { raw in
                        r013_deliver_buffer(token, raw.baseAddress, UInt32(raw.count))
                    }
                }
            }, maxDatagrams: 1)
            entry.observer = session.observe(\.state, options: [.initial, .new]) { [weak self, weak entry] _, _ in
                guard let self = self, let entry = entry else { return }
                self.queue.async { self.stateChanged(entry) }
            }
            return 0
        }
        if DispatchQueue.getSpecific(key: queueKey) == true { return create() }
        return queue.sync(execute: create)
    }

    fileprivate func write(token: UInt64, packet: Data, writeID: UInt64) {
        queue.async { [self] in
            guard let entry = entries[token], !entry.cancelling,
                  entry.pending == nil, !entry.writing else {
                R013UDPWriteDone(token, writeID, 1); return
            }
            entry.pending = (writeID, packet); pump(entry)
        }
    }
    private func pump(_ entry: Entry) {
        guard !entry.cancelling, !entry.writing, entry.session.state == .ready,
              let (writeID, packet) = entry.pending else { return }
        entry.pending = nil; entry.writing = true
        entry.session.writeDatagram(packet) { [weak self, weak entry] error in
            guard let self = self, let entry = entry else { return }
            self.queue.async {
                entry.writing = false
                R013UDPWriteDone(entry.token, writeID, error == nil ? 0 : 1)
                if error != nil { R013UDPFailed(entry.token); self.cancelEntry(entry) }
                self.finishIfClosed(entry)
            }
        }
    }
    private func stateChanged(_ entry: Entry) {
        switch entry.session.state {
        case .ready: pump(entry)
        case .failed: R013UDPFailed(entry.token); cancelEntry(entry)
        case .cancelled: entry.cancelled = true; finishIfClosed(entry)
        default: break
        }
    }
    fileprivate func cancel(token: UInt64) {
        queue.async { [self] in
            guard let entry = entries[token] else { return }
            cancelEntry(entry)
        }
    }
    private func cancelEntry(_ entry: Entry) {
        guard !entry.cancelling else { return }
        entry.cancelling = true
        if let (writeID, _) = entry.pending { entry.pending = nil; R013UDPWriteDone(entry.token, writeID, 1) }
        entry.session.cancel()
        if entry.session.state == .cancelled { entry.cancelled = true }
        finishIfClosed(entry)
    }
    private func finishIfClosed(_ entry: Entry) {
        guard entries[entry.token] === entry, entry.cancelled, !entry.writing else { return }
        entry.readLock.lock(); entry.finished = true; entry.readLock.unlock()
        entry.observer?.invalidate(); entry.observer = nil
        entries.removeValue(forKey: entry.token)
        // Both NWUDPSession.cancelled and write completion are now observed.
        R013UDPDidClose(entry.token)
        finishInvalidation()
    }
    func invalidate(completed: @escaping () -> Void) {
        queue.async { [self] in
            if invalidated { completed(); return }
            stopping = true; completions.append(completed)
            for entry in Array(entries.values) { cancelEntry(entry) }
            finishInvalidation()
        }
    }
    fileprivate func quiesced() {
        // Handles the race where invalidation sees an in-flight Go Open but
        // no Swift entry yet. A rejected Open later releases native bookkeeping
        // and signals this callback; no polling or invented close ack is needed.
        queue.async { [self] in finishInvalidation() }
    }
    private func finishInvalidation() {
        guard stopping, entries.isEmpty, R013UnregisterUDPDriver(driverID) == 0 else { return }
        invalidated = true
        PhysicalDriverRegistry.lock.lock(); PhysicalDriverRegistry.drivers.removeValue(forKey: owner)
        PhysicalDriverRegistry.lock.unlock()
        let callbacks = completions; completions.removeAll()
        for completed in callbacks { completed() }
    }
}
