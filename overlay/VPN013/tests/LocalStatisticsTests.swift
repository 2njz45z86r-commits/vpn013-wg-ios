// SPDX-License-Identifier: MIT
import Foundation
import CryptoKit
import Network

@main enum LocalStatisticsTests {
    static var checks = 0
    static func expect(_ value: @autoclosure () throws -> Bool, _ text: String) {
        checks += 1
        guard (try? value()) == true else { fatalError(text) }
    }
    static func wait(_ seconds: TimeInterval = 5, _ value: () -> Bool) {
        let until = Date().addingTimeInterval(seconds)
        while !value() && Date() < until { RunLoop.current.run(until: Date().addingTimeInterval(0.005)) }
        expect(value(), "native callback failed to finish within bounded fixture deadline")
    }
    static func credentials(_ byte: UInt8 = 1) throws -> VPN013LocalStatisticsCredentials {
        try VPN013LocalStatisticsCredentials(secret: Data(repeating: byte, count: 32),
            id: "8B1F212E-1195-4320-9CE7-6B21F208C43B", ciphertext: Data(repeating: 3, count: 40))
    }
    static func main() throws {
        let key = try credentials(), other = try credentials(2)
        let request = try key.request(operation: 6, nonce: Data(repeating: 4, count: 32))
        let nextRequest = try key.request(operation: 6, nonce: Data(repeating: 5, count: 32))
        let sample = Data("{\"received\":42,\"sent\":77,\"handshake\":1000}".utf8)
        let same = try credentials()
        expect(key.ports == same.ports, "same profile derives same bounded ports")
        expect(Set(key.ports).count == 4 && key.ports.allSatisfy { $0 >= 49152 }, "four unique high ports")
        expect(key.authenticate(request) == 6, "authentic fixed read request")
        let crossRead = try key.request(operation: 11, nonce: Data(repeating: 7, count: 32))
        expect(key.authenticate(crossRead) == 11, "cross-protocol status is a fixed authenticated read operation")
        let separateControl = try VPN013LocalStatisticsCredentials.automaticControl(secret: Data(repeating: 1, count: 32),
            id: "8B1F212E-1195-4320-9CE7-6B21F208C43B", ciphertext: Data(repeating: 3, count: 40))
        expect(separateControl.authenticate(crossRead) == nil, "status frame can never authorize mode control")
        expect(other.authenticate(request) == nil, "different profile key denied")
        expect(key.authenticate(Data()) == nil, "empty request denied")
        expect(key.authenticate(request + Data([0])) == nil, "oversized request denied")
        var changed = request; changed[8] = 0
        expect(key.authenticate(changed) == nil, "raw UAPI and writes never admitted")
        changed = request; changed[45] ^= 1
        expect(key.authenticate(changed) == nil, "forged authenticator denied")
        let encrypted = try key.seal(sample, request: request)
        expect((try? key.open(encrypted, request: request)) == sample, "authenticated measured fields round trip")
        expect((try? key.open(encrypted, request: nextRequest)) == nil, "old response rejected for fresh nonce")
        expect((try? other.open(encrypted, request: request)) == nil, "other profile cannot read counters")
        changed = encrypted; changed[changed.count - 1] ^= 1
        expect((try? key.open(changed, request: request)) == nil, "tampered response rejected")
        expect((try? key.seal(Data(repeating: 0, count: 32769), request: request)) == nil, "bounded provider reply")
        expect((try? key.request(operation: 0, nonce: Data(repeating: 1, count: 32))) == nil, "no raw config command")
        expect((try? key.request(operation: 7, nonce: Data(repeating: 1, count: 32))) == nil, "no unknown command")
        expect((try? VPN013LocalStatisticsCredentials(secret: Data(), id: "invalid", ciphertext: Data())) == nil,
            "missing profile material fails closed")
        let edited = try VPN013LocalStatisticsCredentials(secret: Data(repeating: 1, count: 32),
            id: "8B1F212E-1195-4320-9CE7-6B21F208C43B", ciphertext: Data(repeating: 9, count: 40))
        expect(edited.authenticate(request) == nil, "edited profile revision invalidates authentication")

        let lock = NSLock(); var reads = 0
        let server = VPN013LocalStatisticsServer(credentials: key) { operation, reply in
            lock.lock(); reads += 1; lock.unlock()
            reply(operation == 6 ? sample : nil)
        }
        server.start()
        // Only native loopback transport; fixture values are explicitly test data.
        RunLoop.current.run(until: Date().addingTimeInterval(0.15))
        var invalidClosed = false
        let invalid = NWConnection(host: .ipv4(.loopback),
            port: NWEndpoint.Port(rawValue: key.ports[0])!, using: .tcp)
        let invalidQueue = DispatchQueue(label: "vpn013.fixture.unauthorized")
        var invalidFrame = request; invalidFrame[45] ^= 1
        invalid.stateUpdateHandler = { state in
            if case .ready = state {
                invalid.send(content: invalidFrame, completion: .contentProcessed { _ in
                    invalid.receive(minimumIncompleteLength: 1, maximumLength: 1) { data, _, complete, error in
                        DispatchQueue.main.async {
                            expect(data == nil || data!.isEmpty, "unauthorized socket receives no data")
                            invalidClosed = complete || error != nil
                        }
                    }
                })
            }
        }
        invalid.start(queue: invalidQueue); wait { invalidClosed }; invalid.cancel()
        lock.lock(); let unauthorizedReads = reads; lock.unlock()
        expect(unauthorizedReads == 0, "unauthenticated real socket never reads the engine")

        var cancelledCallback = false
        let cancelled = try VPN013LocalStatisticsRead(credentials: key, operation: 6)
        cancelled.cancel()
        cancelled.start { _ in cancelledCallback = true }
        RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        expect(!cancelledCallback, "cancelled reader cannot report a later result")
        var result: Result<Data, Error>?
        let client = try VPN013LocalStatisticsRead(credentials: key, operation: 6)
        client.start { result = $0 }
        wait { result != nil }
        expect((try? result?.get()) == sample, "actual native TCP transfers authenticated fixture metrics")
        lock.lock(); let count = reads; lock.unlock()
        expect(count == 1, "one bounded request reads provider exactly once")
        var stopped = false
        server.stop { DispatchQueue.main.async { stopped = true } }
        wait { stopped }
        result = nil
        let afterStop = try VPN013LocalStatisticsRead(credentials: key, operation: 6)
        afterStop.start { result = $0 }
        wait { result != nil }
        if case .success? = result { fatalError("stopped provider returned invented metrics") }

        // Occupy the first derived port with a forged responder. The real
        // listener must use the next one; the client must reject the forgery.
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: key.ports[0])!)
        parameters.allowLocalEndpointReuse = false
        let forged = try NWListener(using: parameters)
        let queue = DispatchQueue(label: "vpn013.fixture.forged")
        var ready = false
        forged.stateUpdateHandler = { state in if case .ready = state { DispatchQueue.main.async { ready = true } } }
        forged.newConnectionHandler = { connection in
            connection.start(queue: queue)
            connection.receive(minimumIncompleteLength: 73, maximumLength: 73) { _, _, _, _ in
                connection.send(content: Data([0, 0, 0, 1, 0]), completion: .contentProcessed { _ in connection.cancel() })
            }
        }
        forged.start(queue: queue); wait { ready }
        let second = VPN013LocalStatisticsServer(credentials: key) { _, reply in reply(sample) }
        second.start(); RunLoop.current.run(until: Date().addingTimeInterval(0.15))
        result = nil
        let collision = try VPN013LocalStatisticsRead(credentials: key, operation: 6)
        collision.start { result = $0 }; wait { result != nil }
        expect((try? result?.get()) == sample, "port collision and forged localhost response cannot corrupt metrics")
        stopped = false; second.stop { DispatchQueue.main.async { stopped = true } }; wait { stopped }
        forged.cancel()
        try checkAutomaticControl(key)
        print("Authenticated native statistics transport checks passed: \(checks); synthetic values only, not physical iPhone proof")
    }

    static func checkAutomaticControl(_ statistics: VPN013LocalStatisticsCredentials) throws {
        let secret = Data(repeating: UInt8(1), count: 32), ciphertext = Data(repeating: UInt8(3), count: 40)
        let id = "8B1F212E-1195-4320-9CE7-6B21F208C43B"
        let control = try VPN013LocalStatisticsCredentials.automaticControl(secret: secret, id: id, ciphertext: ciphertext)
        let stamp = UInt64(Date().timeIntervalSince1970 * 1000)
        let now = Date(timeIntervalSince1970: Double(stamp) / 1000)
        let nonce = try VPN013LocalStatisticsCredentials.commandNonce(milliseconds: stamp, random: Data(repeating: 7, count: 24))
        let request = try control.request(operation: 9, nonce: nonce)
        expect(statistics.authenticate(request) == nil, "read-only keys cannot admit an Auto command")
        expect(control.authenticate(try statistics.request(operation: 8, nonce: nonce)) == nil, "control keys cannot admit statistics")
        expect((try? control.request(operation: 6, nonce: nonce)) == nil, "control cannot read counters or configuration")
        expect((try? statistics.request(operation: 10, nonce: nonce)) == nil, "read-only channel cannot write mode")
        expect(control.commandStamp(request, now: now) == stamp, "fresh authenticated timestamp admitted")
        expect(control.commandStamp(request, now: now.addingTimeInterval(31)) == nil, "expired command rejected")
        expect(control.commandStamp(request, now: now.addingTimeInterval(-31)) == nil, "future command rejected")
        expect(Set(statistics.ports) != Set(control.ports), "control uses separate derived binding")
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("vpn013-auto-fixture-" + UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        func state(_ cipher: Data = ciphertext, initial: Bool = true) throws -> VPN013AutomaticSessionState {
            try VPN013AutomaticSessionState(directory: directory, secret: secret, id: id,
                ciphertext: cipher, initialEnabled: initial)
        }
        let session = try state(), digest = Data(SHA256.hash(data: request))
        expect(session.enabled, "new revision uses explicit initial setting")
        expect(try session.accept(operation: 9, stamp: stamp, digest: digest, now: now) == false, "authenticated disable persists")
        let restored = try state()
        expect(!restored.enabled, "OS restart restores paused mode without changing profile ciphertext")
        expect(try restored.accept(operation: 9, stamp: stamp, digest: digest, now: now) == false, "exact latest retry is idempotent")
        expect((try? restored.accept(operation: 10, stamp: stamp, digest: digest, now: now)) == nil, "same serial cannot be used for opposite command")
        let later = Data(repeating: UInt8(11), count: 32)
        expect(try restored.accept(operation: 10, stamp: stamp + 1, digest: later, now: now), "later command can resume")
        let restarted = try state()
        expect(restarted.enabled, "resumed mode survives OS restart")
        expect((try? restarted.accept(operation: 9, stamp: stamp, digest: digest, now: now)) == nil, "old captured command cannot revert a later setting after restart")
        expect((try? restarted.accept(operation: 0, stamp: stamp + 2, digest: later, now: now)) == nil, "no raw/config command")
        expect((try? restarted.accept(operation: 9, stamp: stamp + 2, digest: Data(), now: now)) == nil, "bounded authenticated digest required")
        expect((try? restarted.accept(operation: 9, stamp: stamp + 2, digest: later, now: now.addingTimeInterval(31))) == nil, "state also rejects stale queue delivery")
        let attributes = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent(id + ".automatic").path)
        expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "mode journal private permissions")
        let otherCipher = Data(repeating: UInt8(9), count: 40)
        expect(!(try state(otherCipher, initial: false)).enabled, "new authenticated profile revision gets its own mode")
        let damaged = directory.appendingPathComponent(id + ".automatic")
        var bytes = try Data(contentsOf: damaged); bytes[bytes.count - 1] ^= 1; try bytes.write(to: damaged)
        expect((try? state(otherCipher)) == nil, "tampered mode journal fails closed")
        _ = try state() // A new valid encrypted revision can replace the retired one.

        let defaultsName = "VPN013IdentityFixture." + UUID().uuidString
        guard let defaults = UserDefaults(suiteName: defaultsName) else { fatalError("fixture defaults") }
        defer { defaults.removePersistentDomain(forName: defaultsName) }
        expect(!VPN013AutomaticIdentityHistory.required(id: id, ciphertext: ciphertext, initial: false, defaults: defaults), "fresh manual mode can retain manual endpoint")
        VPN013AutomaticIdentityHistory.rememberEnabled(id: id, ciphertext: ciphertext, defaults: defaults)
        expect(VPN013AutomaticIdentityHistory.required(id: id, ciphertext: ciphertext, initial: false, defaults: defaults), "lost enable acknowledgement still requires actual member")
        expect(!VPN013AutomaticIdentityHistory.required(id: id, ciphertext: otherCipher, initial: false, defaults: defaults), "new manual activation resets only its revision")

        let server = VPN013LocalStatisticsServer(controlCredentials: control) { operation, serial, commandDigest, reply in
            DispatchQueue.main.async {
                do { _ = try session.accept(operation: operation, stamp: serial, digest: commandDigest); reply(Data([1])) }
                catch { reply(nil) }
            }
        }
        server.start(); RunLoop.current.run(until: Date().addingTimeInterval(0.15))
        var result: Result<Data, Error>?
        let read = try VPN013LocalStatisticsRead(credentials: control, operation: 10)
        read.start { result = $0 }; wait { result != nil }
        expect((try? result?.get()) == Data([1]) && session.enabled, "real authenticated TCP command changes only fixture mode")
        var stopped = false; server.stop { DispatchQueue.main.async { stopped = true } }; wait { stopped }
    }
}
