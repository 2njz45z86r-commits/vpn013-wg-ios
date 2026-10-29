// Pure host-ownership/persistence contracts. No system VPN, encryption claim,
// external requests, real profiles or credentials. Actual AES tests run apart.
import Foundation
import NetworkExtension

enum FixtureError: Error { case injected }
struct TunnelConfiguration {
    let name: String?
    let body: String
    init(fromWgQuickConfig text: String, called name: String) throws { self.name = name; body = text }
    func asWgQuickConfig() -> String { body }
}
struct AutoTunnelProfile: Codable {
    struct Candidate: Codable { let name: String; let config: String }
    let candidates: [Candidate]
    init(configurations: [TunnelConfiguration]) throws { candidates = configurations.map { Candidate(name: $0.name ?? "Fixture", config: $0.body) } }
    func validatedConfigurations() throws -> [TunnelConfiguration] {
        guard (1...30).contains(candidates.count) else { throw FixtureError.injected }
        return try candidates.map { try TunnelConfiguration(fromWgQuickConfig: $0.config, called: $0.name) }
    }
}
struct PrivateTunnelPayload: Codable {
    var configuration = ""
    var automatic: AutoTunnelProfile?
    var builtinAutomatic: AutoTunnelProfile?
    var proxy: Data?
    var crossProtocol: CrossProtocolPlan?
}
struct PrivateTunnelStore {
    struct Envelope { let id: String; let ciphertext: Data }
    static let current = Self(), idKey = "fixtureID", dataKey = "fixtureData"
    func seal(_ data: Data, reusing id: String) throws -> Envelope { Envelope(id: id, ciphertext: data) }
}
final class NETunnelProviderProtocol: NSObject, NSCopying {
    var providerBundleIdentifier: String?
    var serverAddress: String?
    var providerConfiguration: [String: Any]?
    var privateEnvelope: PrivateTunnelStore.Envelope? {
        guard let id = providerConfiguration?[PrivateTunnelStore.idKey] as? String,
              let data = providerConfiguration?[PrivateTunnelStore.dataKey] as? Data else { return nil }
        return .init(id: id, ciphertext: data)
    }
    func privatePayload() throws -> PrivateTunnelPayload? {
        guard let data = privateEnvelope?.ciphertext else { return nil }
        return try JSONDecoder().decode(PrivateTunnelPayload.self, from: data)
    }
    func copy(with zone: NSZone? = nil) -> Any {
        let value = NETunnelProviderProtocol(); value.providerBundleIdentifier = providerBundleIdentifier
        value.serverAddress = serverAddress; value.providerConfiguration = providerConfiguration; return value
    }
}
final class FixtureConnection { var status: NEVPNStatus = .disconnected }
final class NETunnelProviderManager {
    static var records: [NETunnelProviderManager] = []
    let connection = FixtureConnection()
    var protocolConfiguration: NSObject?
    var localizedDescription: String?
    var saveError: Error?
    var saves = 0
    static func loadAllFromPreferences(completionHandler: @escaping ([NETunnelProviderManager]?, Error?) -> Void) { completionHandler(records, nil) }
    func saveToPreferences(completionHandler: @escaping (Error?) -> Void) { saves += 1; completionHandler(saveError) }
}

@main enum CrossProtocolPlanTests {
    static func main() throws {
        var checks = 0
        func expect(_ value: @autoclosure () -> Bool, _ label: String) { precondition(value(), label); checks += 1 }
        let previousAuto = UserDefaults.standard.object(forKey: VPN013AutomaticMode.preferenceKey)
        defer { UserDefaults.standard.set(previousAuto, forKey: VPN013AutomaticMode.preferenceKey) }
        VPN013AutomaticMode.setEnabled(true)
        func profile(_ kind: VPN013ConnectionKind) throws -> ProxyProfile {
            try ProxyProfile.fromURI("vless://00000000-0000-4000-8000-000000000001@one.example.invalid:443?type=tcp&security=tls&sni=one.example.invalid#Fixture", source: kind)
        }
        func manager(_ payload: PrivateTunnelPayload, provider: String = "fixture.app.network-extension") throws -> NETunnelProviderManager {
            let value = NETunnelProviderProtocol(); value.providerBundleIdentifier = provider; value.serverAddress = "Fixture"
            value.providerConfiguration = [PrivateTunnelStore.idKey: UUID().uuidString, PrivateTunnelStore.dataKey: try JSONEncoder().encode(payload)]
            let manager = NETunnelProviderManager(); manager.protocolConfiguration = value; manager.localizedDescription = "Fixture"; return manager
        }
        let happ = try profile(.happ), incy = try profile(.incy), black = try profile(.blacktemple)
        let primary = try manager(PrivateTunnelPayload(proxy: JSONEncoder().encode(ProxyTunnelPayload(profile: happ))))
        let duplicate = try manager(PrivateTunnelPayload(proxy: JSONEncoder().encode(ProxyTunnelPayload(profile: happ))))
        let extra = try manager(PrivateTunnelPayload(proxy: JSONEncoder().encode(ProxyTunnelPayload(profile: profile(.happ)))))
        let foreign = try manager(PrivateTunnelPayload(proxy: JSONEncoder().encode(ProxyTunnelPayload(profile: black))), provider: "foreign.app.network-extension")
        let secondary = try manager(PrivateTunnelPayload(proxy: JSONEncoder().encode(ProxyTunnelPayload(profile: incy))))
        let last = try manager(PrivateTunnelPayload(proxy: JSONEncoder().encode(ProxyTunnelPayload(profile: black))))
        let proto = primary.protocolConfiguration as! NETunnelProviderProtocol
        try CrossProtocolPlan.attach(to: proto, managers: [primary, duplicate, foreign, last, secondary, extra])
        let plan = try proto.privatePayload()!.crossProtocol!
        expect(plan.groups.map { $0.kind } == [.happ, .happ, .incy, .blacktemple], "own section first, foreign excluded, repeated member deduplicated")
        expect(plan.groups[0].proxy?.profile == happ, "primary retained exactly")
        expect(plan.groups[1].proxy?.profile.id != happ.id, "other own configuration retained")
        var permitted: CrossProtocolPlan.MutationPermit?
        var completed = false, rejected = false
        func drain(_ test: () -> Bool) {
            let until = Date().addingTimeInterval(3)
            while !test() && Date() < until { RunLoop.current.run(until: Date().addingTimeInterval(0.005)) }
            precondition(test(), "fixture callback timeout")
        }
        NETunnelProviderManager.records = [primary, foreign]
        primary.connection.status = .connected
        CrossProtocolPlan.prepareMutation(appID: "fixture.app") { result in
            if case .failure = result { rejected = true }; completed = true
        }
        drain { completed }
        expect(rejected && primary.saves == 0 && !CrossProtocolPlan.changingSources, "active plan cannot be changed or deleted")
        primary.connection.status = .disconnected; completed = false
        CrossProtocolPlan.prepareMutation(appID: "fixture.app") { result in
            if case .success(let permit) = result { permitted = permit }; completed = true
        }
        drain { completed }
        expect(permitted != nil && CrossProtocolPlan.changingSources, "permit covers caller's entire asynchronous edit")
        let cleared = try proto.privatePayload()
        expect(cleared != nil && cleared?.crossProtocol == nil, "inactive recovery snapshot removed before mutation")
        let restored = try JSONDecoder().decode(ProxyTunnelPayload.self, from: cleared!.proxy!)
        expect(restored.profile == happ, "original connection retained")
        expect(foreign.saves == 0, "other app managers never modified")
        var busyDenied = false
        CrossProtocolPlan.prepareMutation(appID: "fixture.app") { result in if case .failure = result { busyDenied = true } }
        expect(busyDenied, "second edit cannot race permit")
        permitted?.release(); expect(!CrossProtocolPlan.changingSources, "permit released")
        completed = false; var nextPermit: CrossProtocolPlan.MutationPermit?
        CrossProtocolPlan.prepareMutation(appID: "fixture.app") { result in if case .success(let permit) = result { nextPermit = permit }; completed = true }
        drain { completed }; permitted?.release()
        expect(CrossProtocolPlan.changingSources, "repeated release cannot unlock a newer operation"); nextPermit?.release()
        try CrossProtocolPlan.attach(to: proto, managers: [primary, secondary]); primary.saveError = FixtureError.injected
        let old = proto.privateEnvelope!.ciphertext; completed = false; rejected = false
        CrossProtocolPlan.prepareMutation(appID: "fixture.app") { result in if case .failure = result { rejected = true }; completed = true }
        drain { completed }
        expect(rejected && !CrossProtocolPlan.changingSources, "OS save failure releases permission without executing source edit")
        expect((primary.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope?.ciphertext == old, "uncertain save retains original in-memory envelope")
        let runtime = CrossProtocolRuntime(schema: 1, kind: .happ, name: "Fixture", endpoint: nil, phase: "Checking", received: nil, sent: nil, handshake: nil, automaticEnabled: true, trafficVerified: false)
        let encodedRuntime = try JSONEncoder().encode(runtime)
        expect(CrossProtocolRuntime.read(encodedRuntime) != nil, "bounded runtime accepted")
        expect(CrossProtocolRuntime.read(Data(repeating: 0, count: 32769)) == nil, "oversized runtime rejected")
        print("Cross-protocol ownership and mutation: \(checks) checks passed; synthetic preferences only, no system VPN or real credentials")
    }
}
