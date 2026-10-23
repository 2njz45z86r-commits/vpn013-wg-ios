import Foundation
import CryptoKit

@main struct PrivateStorageTests {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let app = PrivateTunnelStore(directory: root.appendingPathComponent("app"))
        let ext = PrivateTunnelStore(directory: root.appendingPathComponent("extension"))
        let stranger = PrivateTunnelStore(directory: root.appendingPathComponent("other-app"))
        var checks = 0
        func check(_ value: @autoclosure () throws -> Bool) throws { let passed = try value(); precondition(passed); checks += 1 }
        func fails(_ work: () throws -> Void) { do { try work(); preconditionFailure("Expected failure") } catch { checks += 1 } }
        let plain = Data("synthetic-config:PrivateKey=fixture-only;13 countries".utf8)
        let envelope = try app.seal(plain)
        try check(envelope.ciphertext != plain)
        try check(envelope.ciphertext.range(of: plain) == nil)
        try check(try app.open(envelope) == plain)
        fails { _ = try ext.open(envelope) }
        fails { _ = try stranger.open(envelope) }
        let bootstrap = try app.key(for: envelope.id)
        try ext.receive(bootstrap, for: envelope)
        try check(try ext.open(envelope) == plain)
        let restarted = PrivateTunnelStore(directory: root.appendingPathComponent("extension"))
        try check(try restarted.open(envelope) == plain) // OS restart without foreground options.
        try check(try Data(contentsOf: root.appendingPathComponent("extension/" + envelope.id + ".key")).count == 32)
        fails { try stranger.receive(Data(repeating: 0, count: 32), for: envelope) }
        fails { try stranger.receive(Data(repeating: 0, count: 31), for: envelope) }
        var damaged = envelope.ciphertext; damaged[damaged.startIndex] ^= 1
        fails { _ = try ext.open(.init(id: envelope.id, ciphertext: damaged)) }
        fails { try stranger.receive(bootstrap, for: .init(id: UUID().uuidString, ciphertext: envelope.ciphertext)) }
        fails { _ = try app.key(for: "../../outside") }
        fails { _ = try app.seal(Data(repeating: 1, count: PrivateTunnelStore.maximumBytes + 1)) }
        let wrongKey = SymmetricKey(size: .bits256)
        let aad = Data(("VPN013-private-v1:" + envelope.id).utf8)
        let forged = try AES.GCM.seal(plain, using: wrongKey, authenticating: aad).combined!
        let wrongBytes = wrongKey.withUnsafeBytes { Data($0) }
        fails { try ext.receive(wrongBytes, for: .init(id: envelope.id, ciphertext: forged)) }
        try check(try ext.open(envelope) == plain) // Failed replacement did not damage saved key.
        for i in 0..<13 {
            let body = Data(("synthetic-country-" + String(i)).utf8)
            let next = try app.seal(body, reusing: envelope.id)
            try check(next.id == envelope.id)
            try check(next.ciphertext != envelope.ciphertext)
            try check(try restarted.open(next) == body)
        }
        app.remove(envelope.id)
        fails { _ = try app.open(envelope) }
        try check(try restarted.open(envelope) == plain) // Separate private containers.
        print("PrivateTunnelStore: \(checks) checks passed; encryption, isolation, bootstrap, restart, tamper, deletion")
    }
}
