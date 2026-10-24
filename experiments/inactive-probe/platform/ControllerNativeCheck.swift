// SPDX-License-Identifier: MIT
// Production controller ABI test with synthetic platform UDP, not an iPhone.
import Foundation

private let lock = NSLock()
private var physicalOpens = 0
private var currentOpens = 0
private var writes = 0
private var closes = 0
private func open(_ owner: UInt64, _ session: UInt64, _ host: UnsafePointer<CChar>?, _ port: UInt16) -> Int32 {
    lock.lock(); defer { lock.unlock() }
    guard owner == 2, let host = host, String(cString: host) == "127.0.0.1", port == 12345 else { physicalOpens += 1; return 1 }
    currentOpens += 1; return 0
}
private func write(_ owner: UInt64, _ session: UInt64, _ raw: UnsafeRawPointer?, _ length: UInt32, _ number: UInt64) {
    guard let raw = raw, length >= 12, length < 1232 else { R013UDPWriteDone(session, number, 1); return }
    var reply = Data(bytes: raw, count: Int(length)); reply[2] |= 0x80; reply[3] = (reply[3] & 0xf0) | 3
    lock.lock(); writes += 1; lock.unlock()
    let owned = reply
    DispatchQueue.global().asyncAfter(deadline: .now() + 0.005) {
        owned.withUnsafeBytes { r013_deliver_buffer(session, $0.baseAddress, UInt32($0.count)) }
        R013UDPWriteDone(session, number, 0)
    }
}
private func cancel(_ owner: UInt64, _ session: UInt64) {
    DispatchQueue.global().asyncAfter(deadline: .now() + 0.03) {
        lock.lock(); closes += 1; lock.unlock(); R013UDPDidClose(session)
    }
}
private func withBytes<T>(_ data: Data, _ call: (UnsafeMutableRawPointer?, UInt32) -> T) -> T {
    var owned = data
    return owned.withUnsafeMutableBytes { call($0.baseAddress, UInt32($0.count)) }
}
private func spin(file: StaticString = #filePath, line: UInt = #line, until condition: () -> Bool) {
    let deadline = Date().addingTimeInterval(4)
    while !condition() && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.005)) }
    precondition(condition(), "main-queue coordinator did not complete", file: file, line: line)
}

@main struct ControllerNativeCheck {
    static func main() throws {
        var driver = r013_udp_driver(); driver.owner = 1; driver.route = 1
        driver.open = open; driver.write = write; driver.cancel = cancel
        let physical = R013RegisterUDPDriver(driver); precondition(physical != 0)
        driver.owner = 2; driver.route = 2
        let current = R013RegisterUDPDriver(driver); precondition(current != 0)
        precondition(R013ProbeCreate(current, physical) == 0, "swapped routes accepted")
        let controller = R013ProbeCreate(physical, current); precondition(controller != 0)
        let extra = R013ProbeCreate(physical, current); precondition(extra != 0)
        precondition(R013ProbeCreate(physical, current) == 0, "unbounded controller registry")
        precondition(R013ProbeRelease(extra) == 0)
        let config = "private_key=" + String(repeating: "11", count: 32) + "\npublic_key=" + String(repeating: "22", count: 32) + "\nendpoint=127.0.0.1:12345\nallowed_ip=0.0.0.0/0\n"
        let transition = R013ProbeBeginChange(controller); precondition(transition != 0)
        precondition(withBytes(Data(config.utf8)) { R013ProbeCommitChange(controller, transition, 1, $0, $1) } == 0)
        let input = R013ProbeInput(auto_active: true, resolver: "127.0.0.1:12345", start_index: 0,
                                   candidates: [R013ProbeSnapshot(id: "same-active-peer", config: config, source: "10.13.0.2")])
        let wire = try JSONEncoder().encode(input)
        let operation = withBytes(wire) { R013ProbeStartScan(controller, $0, $1) }; precondition(operation != 0)
        precondition(withBytes(wire) { R013ProbeStartScan(controller, $0, $1) } == 0, "overlapping scan accepted")
        var result: R013ProbeStatus?
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline {
            var out = Data(count: 65536)
            let size = out.withUnsafeMutableBytes { R013ProbePollScan(controller, operation, $0.baseAddress, UInt32($0.count)) }
            precondition(size > 0)
            result = try JSONDecoder().decode(R013ProbeStatus.self, from: out.prefix(Int(size)))
            if result?.status != "pending" { break }; Thread.sleep(forTimeInterval: 0.005)
        }
        precondition(result?.status == "complete" && result?.rows?.first?.status == "active_identity_skipped")
        precondition(result?.before?.samples == 3 && result?.after?.method == "dns-udp-challenge-v1")
        precondition(result?.choice_id == nil, "active identity selected as candidate")
        precondition(R013ProbeCancelScan(controller, operation) == 0)
        precondition(R013ProbeRelease(controller) == 0)
        precondition(R013ProbeBeginChange(controller) == 0, "released handle reused")
        lock.lock(); let counts = (physicalOpens,currentOpens,writes,closes); lock.unlock()
        precondition(counts.0 == 0 && counts.1 == 2 && counts.2 == 8 && counts.3 == 2)
        #if R013_PROBE_TESTING
        let coordinator = R013ProbeCoordinator(physical: physical, throughTunnel: current)!
        var initial: R013PrimaryPermit?
        var superseded = false
        coordinator.beginPrimaryChange { precondition($0 == nil); superseded = true }
        coordinator.beginPrimaryChange { initial = $0 }
        spin { initial != nil && superseded }
        precondition(initial!.commit(.active(uapi: config)))
        precondition(!initial!.commit(.idle), "permit committed twice")
        var measured = 0
        coordinator.metrics = { status in precondition(status.status == "complete"); measured += 1 }
        var freshInput = input
        coordinator.startHourly(input: { freshInput }, apply: { _,_,_ in preconditionFailure("active peer must never be selected") })
        coordinator.runNowForTesting()
        spin { measured == 1 }
        lock.lock(); let beforeEditOpens = currentOpens; lock.unlock()
        coordinator.runNowForTesting()
        spin { lock.lock(); defer { lock.unlock() }; return currentOpens > beforeEditOpens }
        freshInput = R013ProbeInput(auto_active: true, resolver: input.resolver, start_index: 0,
                                   candidates: [R013ProbeSnapshot(id: input.candidates[0].id, config: config + "\n", source: input.candidates[0].source)])
        spin { lock.lock(); defer { lock.unlock() }; return currentOpens == beforeEditOpens + 2 && closes == currentOpens && !coordinator.measuringForTesting }
        precondition(measured == 1, "edited profile received old snapshot metrics")
        freshInput = input
        lock.lock(); let beforeCancelOpens = currentOpens; lock.unlock()
        coordinator.runNowForTesting()
        spin { lock.lock(); defer { lock.unlock() }; return currentOpens > beforeCancelOpens }
        let dueBeforeChange = coordinator.nextHourForTesting
        var change: R013PrimaryPermit?
        coordinator.beginPrimaryChange { change = $0 }
        spin { change != nil }
        // Permit arrived only after actual delayed UDP cancellation acknowledgement.
        lock.lock(); let drained = currentOpens == closes; lock.unlock()
        precondition(drained && measured == 1, "cancelled result leaked or primary changed before drain")
        precondition(change!.commit(.idle))
        coordinator.resumeAfterPrimaryChange()
        precondition(coordinator.nextHourForTesting == dueBeforeChange, "path/member change postponed the next hour")
        coordinator.stopHourly()
        precondition(coordinator.nextHourForTesting == nil, "manual stop retained an hourly schedule")
        var released = false
        coordinator.shutdown { precondition($0); released = true }
        spin { released }
        print("PASS Swift main-queue coordinator: fresh typed metrics, one-shot permit, cancellation before primary change, real close drain, stop and explicit release; test trigger replaces one-hour wait, no physical iOS claim")
        #endif
        precondition(R013UnregisterUDPDriver(physical) == 0 && R013UnregisterUDPDriver(current) == 0)
        print("PASS production C controller: fixed routes, actual-state commit, bounded async scan/poll, active exclusion before physical UDP, equal before/after DNS, cancellation, delayed closure and release; synthetic current path only")
    }
}
