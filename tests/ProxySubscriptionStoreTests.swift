// Actual host-only crypto store and roster model, no networking/system VPN.
import Foundation
@main struct ProxySubscriptionStoreTests {
    static func main() throws {
        var checks = 0
        func expect(_ condition: Bool) { checks += 1; precondition(condition, "Subscription ownership invariant") }
        func rejects(_ body: () throws -> Void) { do { try body(); preconditionFailure("Accepted invalid subscription state") } catch { checks += 1 } }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("VPN013-roster-test-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) } // Only this owned random directory.
        let store = ProxySubscriptionStore(directory: directory)
        expect(try store.load().isEmpty)
        let uri = "vless://00000000-0000-4000-8000-000000000001@node.example.invalid:443?type=ws&security=tls&sni=node.example.invalid#Country"
        let prototype = try ProxyProfile.fromURI(uri, source: .happ)
        func roster(_ count: Int) -> [ProxyProfile] { (0..<count).map { index in var p = prototype; p.id = UUID(); p.name = "Country \(index)"; p.host = "node\(index).example.invalid"; return p } }
        let record = ProxySubscriptionRecord(id: UUID(), kind: .happ, url: URL(string: "https://subscription.example.invalid/private-test-token")!, members: [], checkedAt: nil)
        let ten = try record.replacing(with: roster(10))
        try store.save([ten]); expect(try store.load() == [ten])
        let twenty = try ten.replacing(with: roster(20))
        expect(twenty.members.count == 20 && Array(twenty.members.prefix(10).map { $0.id }) == ten.members.map { $0.id })
        let fifteen = try twenty.replacing(with: roster(15))
        expect(fifteen.members.count == 15 && Array(twenty.members.prefix(15).map { $0.id }) == fifteen.members.map { $0.id })
        let manuallyRemaining = Array(fifteen.members.dropFirst(3))
        let restored = try fifteen.replacing(with: roster(15))
        expect(restored.members.count == 15 && manuallyRemaining.count == 12 && restored.members.map { $0.id } == fifteen.members.map { $0.id })
        var rotated = roster(15); rotated[2].userID = UUID()
        let rotation = try fifteen.replacing(with: rotated)
        expect(rotation.members[2].id == fifteen.members[2].id && rotation.members[2].userID != fifteen.members[2].userID)
        var foreign = roster(1); foreign[0].source = .blacktemple
        rejects { _ = try fifteen.replacing(with: foreign) }
        rejects { _ = try fifteen.replacing(with: []) }
        let black = ProxySubscriptionRecord(id: UUID(), kind: .blacktemple, url: URL(string: "https://black.example.invalid/private-test-token")!, members: foreign, checkedAt: nil)
        try store.save([fifteen, black]); expect(try store.load() == [fifteen, black])
        let file = directory.appendingPathComponent("proxy-subscriptions-v1.encrypted")
        let bytes = try Data(contentsOf: file)
        let text = String(decoding: bytes, as: UTF8.self)
        expect(!text.contains("private-test-token") && !text.contains("node0.example.invalid") && !text.contains(prototype.userID.uuidString.lowercased()))
        let permissions = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        expect(permissions?.intValue == 0o600)
        var tampered = bytes; tampered[tampered.count / 2] ^= 1; try tampered.write(to: file)
        rejects { _ = try store.load() }
        rejects { try store.save([ten]) }
        expect(try Data(contentsOf: file) == tampered)
        print("Subscription roster and encrypted storage: \(checks) checks passed; synthetic data only")
    }
}
