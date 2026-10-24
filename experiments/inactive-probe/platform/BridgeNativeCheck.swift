// SPDX-License-Identifier: MIT
// Native ABI test uses synthetic callbacks; it never claims NEProvider routing.
import Foundation

private let testLock = NSLock()
private var testOpened = 0
private var testWritten = 0
private var testClosed = 0
private var testSession: UInt64 = 0
private var testQuiesced = 0

private func testOpen(_ owner: UInt64, _ session: UInt64,
                      _ host: UnsafePointer<CChar>?, _ port: UInt16) -> Int32 {
    guard owner == 13 || owner == 14, let host = host, String(cString: host) == "127.0.0.1", port == 12345 else { return 1 }
    testLock.lock(); testOpened += 1; testSession = session; testLock.unlock(); return 0
}
private func testWrite(_ owner: UInt64, _ session: UInt64,
                       _ raw: UnsafeRawPointer?, _ count: UInt32, _ writeID: UInt64) {
    guard let raw = raw, count <= 64 else { R013UDPWriteDone(session, writeID, 1); return }
    var output = Data(bytes: raw, count: Int(count))
    if owner == 14 && output.count >= 12 { output[2] |= 0x80; output[3] = (output[3] & 0xf0) | 3 }
    let copied = output
    testLock.lock(); testWritten += 1; testLock.unlock()
    // Deliberately asynchronous: original C storage is gone before callbacks.
    DispatchQueue.global().async {
        copied.withUnsafeBytes { bytes in r013_deliver_buffer(session, bytes.baseAddress, UInt32(bytes.count)) }
        R013UDPWriteDone(session, writeID, 0)
        R013UDPWriteDone(session, writeID, 0) // Duplicate completion must be harmless.
    }
}
private func testIdle(_ owner: UInt64) {
    testLock.lock(); testQuiesced += 1; testLock.unlock()
}
private func testCancel(_ owner: UInt64, _ session: UInt64) {
    DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(30)) {
        testLock.lock(); testClosed += 1; testLock.unlock()
        R013UDPDidClose(session)
        R013UDPDidClose(session)
    }
}

@main struct BridgeNativeCheck {
    static func main() {
        var callbacks = r013_udp_driver()
        callbacks.owner = 13; callbacks.route = 1; callbacks.open = testOpen
        callbacks.write = testWrite; callbacks.cancel = testCancel
        callbacks.quiesced = testIdle
        let driver = R013RegisterUDPDriver(callbacks)
        precondition(driver != 0)
        precondition(R013BridgeDNSExercise(driver) != 0, "physical driver accepted for current-tunnel baseline")
        let started = Date()
        precondition(R013BridgeExercise(driver) == 0, "native callback exercise failed")
        precondition(Date().timeIntervalSince(started) >= 0.02, "close returned before delayed acknowledgement")
        testLock.lock(); let counts = (testOpened, testWritten, testClosed, testSession); testLock.unlock()
        precondition(counts.0 == 1 && counts.1 == 1 && counts.2 == 1)
        precondition(R013UnregisterUDPDriver(driver) == 0)
        precondition(R013BridgeExercise(driver) != 0, "removed driver reused")
        // Late callbacks for a destroyed numeric handle cannot affect a new bind.
        let late = Data([9]); late.withUnsafeBytes { r013_deliver_buffer(counts.3, $0.baseAddress, 1) }
        R013UDPWriteDone(counts.3, 1, 0); R013UDPDidClose(counts.3)
        callbacks.owner = 14; callbacks.route = 2
        let virtual = R013RegisterUDPDriver(callbacks); precondition(virtual != 0)
        precondition(R013BridgeExercise(virtual) != 0, "virtual driver accepted for a candidate engine")
        precondition(R013BridgeDNSExercise(virtual) == 0, "native current DNS method failed")
        precondition(R013UnregisterUDPDriver(virtual) == 0)
        // A failed in-flight Open still emits native-quiescence, which lets a
        // stopping Swift owner retry unregistering after its earlier refusal.
        callbacks.owner = 15; callbacks.route = 1
        let rejected = R013RegisterUDPDriver(callbacks); precondition(rejected != 0)
        precondition(R013BridgeExercise(rejected) != 0)
        precondition(R013UnregisterUDPDriver(rejected) == 0)
        testLock.lock(); let final = (testOpened,testWritten,testClosed,testQuiesced); testLock.unlock()
        precondition(final.0 == 2 && final.1 == 5 && final.2 == 2 && final.3 == 3)
        print("PASS native Swift/C/Go copied datagram, asynchronous write acknowledgement, delayed actual close, duplicate/late callback rejection, fixed physical/virtual roles, current DNS baseline and failed-Open quiescence; synthetic transport only")
    }
}
