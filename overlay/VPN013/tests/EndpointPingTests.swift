import Foundation

@main
struct EndpointPingTests {
    static var checks = 0
    static func check(_ condition: @autoclosure () -> Bool, _ message: String) {
        checks += 1
        precondition(condition(), message)
    }

    static func reply(ipv6: Bool, nonce: [UInt8]) -> [UInt8] {
        var bytes = EndpointPingPacket.request(ipv6: ipv6, nonce: nonce)
        bytes[0] = ipv6 ? 129 : 0
        bytes[2] = 0; bytes[3] = 0
        if !ipv6 {
            let sum = EndpointPingPacket.checksum(bytes)
            bytes[2] = UInt8(sum >> 8); bytes[3] = UInt8(sum & 0xff)
        }
        return bytes
    }

    static func wait(until predicate: () -> Bool, seconds: TimeInterval = 6) {
        let deadline = Date().addingTimeInterval(seconds)
        while !predicate() && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
        check(predicate(), "Asynchronous test timed out")
    }

    static func main() {
        let hosts: [String?] = ["slow.example", "fast.example", "blocked.example", "fast.example", nil, "invalid.example"]
        check(EndpointPingRanking.order(hosts: hosts, measurements: [:]) == [0, 1, 2, 3, 4, 5], "No echo replies preserve all fallback candidates")
        let timings: [String: EndpointPingResult] = ["slow.example": .milliseconds(120), "fast.example": .milliseconds(20),
            "blocked.example": .noReply, "invalid.example": .milliseconds(.nan)]
        check(EndpointPingRanking.order(hosts: hosts, measurements: timings) == [1, 3, 0, 2, 4, 5], "Fastest real timing wins; equal timings and unavailable hosts remain stable")
        for invalid in [Double.infinity, -1] {
            check(EndpointPingRanking.order(hosts: ["a", "b"], measurements: ["a": .milliseconds(invalid), "b": .milliseconds(0)]) == [1, 0], "Invalid timing is never treated as a measurement")
        }
        check(EndpointPingRanking.order(hosts: [], measurements: timings).isEmpty, "Empty input is safe")
        let nonce = Array(UUID().uuidString.utf8)
        for ipv6 in [false, true] {
            let request = EndpointPingPacket.request(ipv6: ipv6, nonce: nonce)
            check(!EndpointPingPacket.matchesReply(request, ipv6: ipv6, nonce: nonce), "Reflected request is not a reply")
            let valid = reply(ipv6: ipv6, nonce: nonce)
            check(EndpointPingPacket.matchesReply(valid, ipv6: ipv6, nonce: nonce), "Matching echo reply")
            check(!EndpointPingPacket.matchesReply(valid, ipv6: ipv6, nonce: [9]), "Wrong nonce rejected")
            for length in 0..<valid.count {
                check(!EndpointPingPacket.matchesReply(Array(valid.prefix(length)), ipv6: ipv6, nonce: nonce), "Truncated reply rejected")
            }
            var wrongSequence = valid; wrongSequence[7] = 2
            check(!EndpointPingPacket.matchesReply(wrongSequence, ipv6: ipv6, nonce: nonce), "Wrong sequence rejected")
            var errorPacket = valid; errorPacket[1] = 1
            check(!EndpointPingPacket.matchesReply(errorPacket, ipv6: ipv6, nonce: nonce), "Nonzero code rejected")
        }
        var ipv4 = [UInt8](repeating: 0, count: 20)
        ipv4[0] = 0x45; ipv4[9] = 1
        check(EndpointPingPacket.matchesReply(ipv4 + reply(ipv6: false, nonce: nonce), ipv6: false, nonce: nonce), "Darwin IPv4 header skipped")
        ipv4[0] = 0x4f
        check(!EndpointPingPacket.matchesReply(ipv4 + reply(ipv6: false, nonce: nonce), ipv6: false, nonce: nonce), "Invalid IHL rejected")
        let cancelled = EndpointPingCancellation(); cancelled.cancel()
        check(EndpointPingProbe.measure(host: "127.0.0.1", cancellation: cancelled) == .cancelled, "Cancelled probe sends no packet")
        for address in ["127.0.0.1", "::1"] {
            let result = EndpointPingProbe.measure(host: address, cancellation: EndpointPingCancellation())
            guard case .milliseconds(let value) = result else { preconditionFailure("Actual loopback ICMP failed: \(address) \(result)") }
            check(value.isFinite && value >= 0 && value < 3000, "Real ICMP response timed")
            print("Actual loopback ICMP \(address): \(result.text)")
        }
        check(EndpointPingProbe.measure(host: "vpn013-ping-test.invalid", cancellation: EndpointPingCancellation()) == .unresolved, "DNS failure is explicit")
        let coordinator = EndpointPingCoordinator()
        var done = false
        var updates = 0
        coordinator.start(hosts: ["127.0.0.1", "127.0.0.1"], update: { _, result in
            check(Thread.isMainThread, "Updates on main thread")
            if case .milliseconds = result { updates += 1 }
        }, completion: { check(Thread.isMainThread, "Completion on main thread"); done = true })
        wait(until: { done })
        check(updates == 1, "Duplicate addresses probed once")
        var stale = false
        coordinator.start(hosts: ["192.0.2.1"], update: { _, _ in stale = true }, completion: { stale = true })
        coordinator.cancel()
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        check(!stale, "Cancelled generation cannot update UI")
        print("Endpoint ping checks passed: \(checks); real IPv4/IPv6 ICMP, malformed/reflected replies, DNS errors, cancellation, deduplication")
    }
}
