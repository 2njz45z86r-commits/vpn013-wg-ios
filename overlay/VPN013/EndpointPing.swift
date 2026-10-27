// SPDX-License-Identifier: MIT
import Foundation
import Darwin

enum EndpointPingResult: Equatable {
    case milliseconds(Double)
    case noReply
    case unresolved
    case unavailable
    case cancelled

    var text: String {
        switch self {
        case .milliseconds(let value): return "\(max(1, Int(value.rounded()))) мс"
        case .noReply: return "Нет ответа"
        case .unresolved: return "Ошибка DNS"
        case .unavailable: return "Недоступно"
        case .cancelled: return "Отменено"
        }
    }
}

/// Echo requests carry a fresh nonce. A reflected request, unrelated reply or
/// malformed IP header must never turn into a successful measurement.
enum EndpointPingPacket {
    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            sum += UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count { sum += UInt32(bytes[index]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum)
    }

    static func request(ipv6: Bool, nonce: [UInt8]) -> [UInt8] {
        var bytes: [UInt8] = [ipv6 ? 128 : 8, 0, 0, 0, 0x01, 0x13, 0, 1] + nonce
        if !ipv6 {
            let value = checksum(bytes)
            bytes[2] = UInt8(value >> 8); bytes[3] = UInt8(value & 0xff)
        }
        return bytes
    }

    static func matchesReply(_ bytes: [UInt8], ipv6: Bool, nonce: [UInt8]) -> Bool {
        var offset = 0
        if !ipv6, bytes.first.map({ $0 >> 4 == 4 }) == true {
            guard bytes.count >= 20, bytes[9] == 1 else { return false }
            offset = Int(bytes[0] & 15) * 4
            guard offset >= 20, offset + 8 <= bytes.count else { return false }
        } else if ipv6, bytes.first.map({ $0 >> 4 == 6 }) == true {
            guard bytes.count >= 40, bytes[6] == 58 else { return false }
            offset = 40
        }
        guard bytes.count == offset + 8 + nonce.count,
              bytes[offset] == (ipv6 ? 129 : 0), bytes[offset + 1] == 0,
              bytes[offset + 6] == 0, bytes[offset + 7] == 1,
              Array(bytes[(offset + 8)...]) == nonce else { return false }
        // Darwin may assign the echo identifier itself. Source filtering comes
        // from the connected socket; sequence, type and nonce authenticate this reply.
        return ipv6 || checksum(Array(bytes[offset...])) == 0
    }
}

final class EndpointPingCancellation {
    private let lock = NSLock()
    private var stopped = false
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return stopped }
    func cancel() { lock.lock(); stopped = true; lock.unlock() }
}

/// Unprivileged ICMP datagram sockets, as in Apple's SimplePing approach.
/// No WireGuard key, VPN configuration or credential is sent. This measures the
/// address over the current OS route, not the health of the AWG service/UDP port.
enum EndpointPingProbe {
    static func measure(host: String, timeout: TimeInterval = 3,
                        cancellation: EndpointPingCancellation) -> EndpointPingResult {
        if cancellation.isCancelled { return .cancelled }
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return .unresolved }
        defer { freeaddrinfo(first) }
        if cancellation.isCancelled { return .cancelled }
        var addresses: [(Int32, Data)] = []
        var current: UnsafeMutablePointer<addrinfo>? = first
        while let info = current {
            let entry = info.pointee
            if (entry.ai_family == AF_INET || entry.ai_family == AF_INET6), let address = entry.ai_addr,
               !addresses.contains(where: { $0.0 == entry.ai_family }) {
                addresses.append((entry.ai_family, Data(bytes: address, count: Int(entry.ai_addrlen))))
            }
            current = entry.ai_next
        }
        guard !addresses.isEmpty else { return .unresolved }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var failure = EndpointPingResult.unavailable
        for (index, address) in addresses.enumerated() {
            if cancellation.isCancelled { return .cancelled }
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { break }
            let budget = remaining / Double(addresses.count - index)
            let measured = echo(address: address, timeout: budget, cancellation: cancellation)
            if case .milliseconds = measured { return measured }
            if measured == .cancelled { return measured }
            if measured == .noReply { failure = .noReply }
        }
        return failure
    }

    private static func echo(address: (Int32, Data), timeout: TimeInterval,
                             cancellation: EndpointPingCancellation) -> EndpointPingResult {
        let ipv6 = address.0 == AF_INET6
        let descriptor = socket(address.0, SOCK_DGRAM, ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP)
        guard descriptor >= 0 else { return .unavailable }
        defer { close(descriptor) }
        let connected = address.1.withUnsafeBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return -1 }
            return connect(descriptor, base.assumingMemoryBound(to: sockaddr.self), socklen_t(raw.count))
        }
        guard connected == 0 else { return .unavailable }
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else { return .unavailable }
        let nonce = Array(UUID().uuidString.utf8)
        let packet = EndpointPingPacket.request(ipv6: ipv6, nonce: nonce)
        let started = ProcessInfo.processInfo.systemUptime
        let sent = packet.withUnsafeBytes { send(descriptor, $0.baseAddress, $0.count, 0) }
        guard sent == packet.count else { return .unavailable }
        while ProcessInfo.processInfo.systemUptime - started < timeout {
            if cancellation.isCancelled { return .cancelled }
            var item = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let remaining = max(1, min(100, Int((timeout - (ProcessInfo.processInfo.systemUptime - started)) * 1000)))
            let ready = poll(&item, 1, Int32(remaining))
            if ready < 0 { if errno == EINTR { continue }; return .unavailable }
            if ready == 0 { continue }
            if item.revents & Int16(POLLIN) == 0 { return .unavailable }
            var bytes = [UInt8](repeating: 0, count: 2048)
            let count = bytes.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, 0) }
            if count < 0 { if errno == EAGAIN || errno == EINTR { continue }; return .unavailable }
            if EndpointPingPacket.matchesReply(Array(bytes.prefix(count)), ipv6: ipv6, nonce: nonce) {
                return .milliseconds((ProcessInfo.processInfo.systemUptime - started) * 1000)
            }
        }
        return .noReply
    }
}

/// A bounded batch never activates/deactivates a VPN or edits a stored profile.
/// All presentation callbacks run on main; cancellation ignores late DNS replies.
final class EndpointPingCoordinator {
    private let queue: OperationQueue = {
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 3
        queue.qualityOfService = .userInitiated
        return queue
    }()
    private var token: EndpointPingCancellation?
    private var watchdog: DispatchWorkItem?
    private var generation = UUID()

    func cancel() {
        token?.cancel(); token = nil; queue.cancelAllOperations()
        watchdog?.cancel(); watchdog = nil; generation = UUID()
    }

    func start(hosts: [String], update: @escaping (String, EndpointPingResult) -> Void,
               completion: @escaping () -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        cancel()
        let unique = Array(Set(hosts)).sorted()
        guard !unique.isEmpty else { completion(); return }
        let token = EndpointPingCancellation(); self.token = token
        let stamp = generation
        var pending = Set(unique)
        func finish(_ host: String, _ result: EndpointPingResult) {
            guard self.generation == stamp, pending.remove(host) != nil else { return }
            update(host, result)
            if pending.isEmpty {
                self.watchdog?.cancel(); self.watchdog = nil
                self.token = nil; completion()
            }
        }
        for host in unique {
            queue.addOperation { [weak self] in
                guard !token.isCancelled else { return }
                #if DEBUG && targetEnvironment(simulator)
                // Keep only the explicit cancellation UI fixture pending. A
                // fast ICMP rejection must not finish before XCTest can tap
                // Stop. No measurement is invented; release builds omit this.
                if ProcessInfo.processInfo.arguments.contains("--vpn013-test-hold-ping-for-cancellation") {
                    let until = ProcessInfo.processInfo.systemUptime + 40
                    while !token.isCancelled && ProcessInfo.processInfo.systemUptime < until {
                        Thread.sleep(forTimeInterval: 0.02)
                    }
                    guard !token.isCancelled else { return }
                }
                #endif
                let result = EndpointPingProbe.measure(host: host, cancellation: token)
                DispatchQueue.main.async {
                    guard self?.generation == stamp else { return }
                    finish(host, result)
                }
            }
        }
        let timeout = DispatchWorkItem { [weak self] in
            guard let self = self, self.generation == stamp else { return }
            token.cancel(); self.queue.cancelAllOperations()
            for host in Array(pending) { finish(host, .unavailable) }
        }
        watchdog = timeout
        DispatchQueue.main.asyncAfter(deadline: .now() + 45, execute: timeout)
    }

    deinit { token?.cancel(); queue.cancelAllOperations(); watchdog?.cancel() }
}
