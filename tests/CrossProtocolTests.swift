import Foundation

@main enum CrossProtocolTests {
    static func main() {
        var checks = 0
        func expect(_ value: @autoclosure () -> Bool, _ label: String) {
            precondition(value(), label); checks += 1
        }
        for count in 1...120 {
            var state = CrossProtocolSelection(count: count)
            expect(state.failed(networkAvailable: false) == .waitForNetwork, "offline does not consume candidates")
            expect(state.visited == [0], "offline keeps visited set")
            for index in 1..<count { expect(state.failed(networkAvailable: true) == .tryGroup(index), "every group tried exactly once") }
            expect(state.failed(networkAvailable: true) == .exhausted, "finite exhaustion")
            state.enabled = false
            expect(state.failed(networkAvailable: true) == .paused, "disabled stops traversal")
            state.verifiedTraffic(); state.enabled = true
            if count > 1 { expect(state.failed(networkAvailable: true) == .tryGroup(0), "verified traffic resets recovery cycle") }
            state.stop(); expect(state.failed(networkAvailable: true) == .stopped, "manual stop is final")
        }
        let failure = NSError(domain: "synthetic", code: 1)
        var events: [String] = [], starts: [(Error?) -> Void] = [], stops: [(Error?) -> Void] = []
        var completion: [Bool] = [], ended = 0
        let coordinator = CrossProtocolCoordinator(count: 4, enabled: true, start: { index, enabled, done in
            events.append("start\(index):\(enabled)"); starts.append(done)
        }, stop: { done in events.append("stop"); stops.append(done) }, pause: { enabled in events.append("auto:\(enabled)") }, ended: { _ in ended += 1 })
        coordinator.start { completion.append($0 == nil) }
        starts[0](failure)
        expect(events == ["start0:true", "stop"], "do not start next before stop confirmation")
        stops.removeFirst()(nil)
        expect(events.last == "start1:true", "next engine starts only after stop")
        starts[1](nil); starts[1](failure)
        expect(completion == [true] && coordinator.phase == .running(1), "duplicate start callback ignored")
        coordinator.networkAvailable = false
        expect(!coordinator.failed(), "offline must not skip protocol")
        coordinator.networkAvailable = true; coordinator.setEnabled(false)
        expect(!coordinator.failed() && coordinator.phase == .running(1), "pause retains current engine")
        coordinator.setEnabled(true); coordinator.verifiedTraffic()
        expect(coordinator.failed(), "negative traffic advances")
        expect(coordinator.phase == .switching(0), "fresh cycle revisits initial group")
        coordinator.stop { events.append("user-stopped") }
        let startCount = starts.count
        while !stops.isEmpty { stops.removeFirst()(nil) }
        starts[0](nil)
        expect(starts.count == startCount && coordinator.phase == .stopped, "late callbacks cannot revive stopped VPN")
        expect(ended == 0, "manual stop does not invent exhausted error")

        var errors = 0, finished = 0
        let bad = CrossProtocolCoordinator(count: 2, enabled: true, start: { _, _, done in done(failure) },
            stop: { done in done(nil) }, pause: { _ in }, ended: { _ in errors += 1 })
        bad.start { if $0 != nil { finished += 1 } }
        expect(bad.phase == .stopped && finished == 1 && errors == 0, "all startup failures complete once with error")

        var blockedStarts = 0
        let blocked = CrossProtocolCoordinator(count: 2, enabled: true, start: { _, _, done in blockedStarts += 1; done(nil) },
            stop: { done in done(failure) }, pause: { _ in }, ended: { _ in errors += 1 })
        blocked.start { _ in }; _ = blocked.failed()
        expect(blockedStarts == 1 && blocked.phase == .stopped, "failed stop cannot launch competing engine")
        print("Cross-protocol policy and lifecycle: \(checks) checks passed; finite coverage1...120, offline, pause, stop fences and failure injection; no VPN traffic simulated as success")
    }
}
