import Foundation

@main struct ClientUpdateTests {
    static func main() throws {
        var count = 0
        func check(_ value: @autoclosure () throws -> Bool) throws { let passed = try value(); precondition(passed); count += 1 }
        func fails(_ work: () throws -> Void) { do { try work(); preconditionFailure("Expected rejection") } catch { count += 1 } }
        func snapshot(_ servers: [ClientServer], order: String = "012345abcdef", complete: Bool = true) -> ClientSnapshot {
            let revision = ClientUpdateProtocol.digest(servers.map { $0.id+"\n"+$0.name+"\n"+$0.config+"\n" }.joined())
            return ClientSnapshot(schema:1,kind:"vpn013-awg",orderID:order,expiry:2_000_000_000_000,revision:revision,complete:complete,servers:servers)
        }
        let a = ClientServer(id:"germany",name:"Germany",config:"synthetic-fixture-configuration-A")
        let b = ClientServer(id:"finland",name:"Finland",config:"synthetic-fixture-configuration-B")
        let valid = snapshot([a,b])
        try valid.validate()
        try check(valid.revision == "9f0f12eb4cfeb200bd29ce6650d12c6c6addf0ed3fb477c4c1a63d8eb3cf51c4") // Python server interoperability fixture.
        try check(ClientUpdateProtocol.validToken(String(repeating:"A",count:43)))
        for token in ["",String(repeating:"A",count:42),String(repeating:"A",count:44),String(repeating:"/",count:43)] {
            try check(!ClientUpdateProtocol.validToken(token))
        }
        let document = ClientAccessDocument(schema:1,kind:"vpn013-access",capability:String(repeating:"A",count:43),snapshot:valid)
        let bytes = try JSONEncoder().encode(document)
        let renewal = "https://t.me/vpn013_com_bot?start=trial_" + String(repeating: "C", count: 43)
        let trial = ClientTrialMetadata(durationSeconds: 259200, renewalURL: renewal)
        try trial.validate(); count += 1
        for url in [renewal + "&extra=1", renewal + "#x", renewal.replacingOccurrences(of: "https", with: "http"), "https://t.me/other?start=trial_" + String(repeating: "C", count: 43), "https://vpn013.com/"] {
            fails { try ClientTrialMetadata(durationSeconds: 259200, renewalURL: url).validate() }
        }
        fails { try ClientTrialMetadata(durationSeconds: 3600, renewalURL: renewal).validate() }
        let info = ClientNativeTrialInfo(schema: 1, kind: "vpn013-native-trial", app: "vpn013-wg", orderID: valid.orderID, state: "active", issuedAt: 1_900_000_000_000, expiresAt: 1_900_259_200_000, serverTime: 1_900_000_001_000, durationSeconds: 259200, isTrial: true, renewalURL: renewal)
        try info.validate(); count += 1
        var fresh = ClientNativeTrialState.fresh(); try check(ClientUpdateProtocol.validToken(fresh.requestID)); fresh.ticket = String(repeating: "A", count: 43); fresh.info = info
        let trialDoc = ClientAccessDocument(schema: 1, kind: "vpn013-access", capability: document.capability, snapshot: valid, trial: trial)
        try check(try ClientAccessDocument.decode(JSONEncoder().encode(trialDoc)).trial?.renewalURL == renewal)
        try check(try ClientAccessDocument.decode(bytes).snapshot.servers == [a,b])
        fails { _ = try ClientAccessDocument.decode(Data("{}".utf8)) }
        fails { _ = try ClientAccessDocument.decode(Data(repeating:32,count:1_048_577)) }
        fails { try snapshot([]).validate() }
        fails { try snapshot([a,a]).validate() }
        fails { try snapshot([a,b],complete:false).validate() }
        fails { try snapshot([a,b],order:"foreign-order").validate() }
        fails { try valid.validate(orderID:"aaaaaaaaaaaa") }
        fails { try snapshot([ClientServer(id:"../admin",name:"A",config:"x")]).validate() }
        fails { try snapshot([ClientServer(id:"a",name:"bad\nname",config:"x")]).validate() }
        fails { try snapshot([ClientServer(id:"a",name:"A",config:String(repeating:"x",count:65_537))]).validate() }
        let thirty = (0..<30).map { ClientServer(id:"node\($0)",name:"Server \($0)",config:"synthetic \($0)") }
        try snapshot(thirty).validate(); count += 1
        fails { try snapshot(thirty + [ClientServer(id:"extra",name:"Extra",config:"synthetic")]).validate() }
        fails { try ClientSnapshot(schema:1,kind:"vpn013-awg",orderID:valid.orderID,expiry:valid.expiry,revision:String(repeating:"0",count:64),complete:true,servers:valid.servers).validate() }
        let plan = try ClientRosterPlan(previousIDs:["germany","retired"],snapshot:valid)
        try check(plan.added.map { $0.id } == ["finland"])
        try check(plan.retained.map { $0.id } == ["germany"])
        try check(plan.removedIDs == ["retired"])
        let release = ClientAppRelease(schema:1,app:"vpn013-wg",platform:"ios",version:"1.4.0",build:9,downloadURL:"https://github.com/2njz45z86r-commits/vpn013-wg-ios/releases/download/unsigned-test/VPN013AWG-unsigned.ipa",sha256:String(repeating:"a",count:64),notes:"Synthetic release")
        try release.validate()
        for address in [
            "https://t.me/vpn013_com_bot?start=download_vpn013_ios",
            release.downloadURL + "?next=https://example.com",
            release.downloadURL + "#fragment",
            release.downloadURL.replacingOccurrences(of:"github.com/",with:"github.com:8443/"),
            release.downloadURL.replacingOccurrences(of:"github.com/",with:"user@github.com/"),
            release.downloadURL.replacingOccurrences(of:"github.com/",with:"github.com.example.com/"),
            release.downloadURL.replacingOccurrences(of:"https://",with:"http://"),
            release.downloadURL.replacingOccurrences(of:"2njz45z86r-commits/vpn013-wg-ios",with:"other/project")
        ] {
            fails { try ClientAppRelease(schema:1,app:"vpn013-wg",platform:"ios",version:release.version,build:release.build,downloadURL:address,sha256:release.sha256,notes:"Synthetic release").validate() }
        }
        try check(release.isNewer(version:"1.3.1",build:8))
        try check(release.isNewer(version:"1.4.0",build:8))
        try check(!release.isNewer(version:"1.4.0",build:9))
        try check(!release.isNewer(version:"1.5.0",build:1))
        try check(!release.isNewer(version:"1.10.0",build:1))
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at:root) }
        let store = ClientRegistryStore(directory:root)
        try check(try store.load().bindings.isEmpty)
        var registry = ClientRegistry()
        registry.bindings[valid.orderID] = ClientBinding(document:document,profileIDs:["germany":UUID().uuidString],baseline:["germany":"hash"],pending:valid,lastCheck:Date())
        registry.nativeTrial = fresh
        try store.save(registry)
        try check(try store.load().bindings[valid.orderID]?.document.capability == document.capability)
        let encrypted = try Data(contentsOf:root.appendingPathComponent("client-subscriptions-v1.enc"))
        try check(encrypted.range(of:Data(document.capability.utf8)) == nil)
        try check(encrypted.range(of:Data(a.config.utf8)) == nil)
        try check(encrypted.range(of:Data(renewal.utf8)) == nil)
        try check(try store.load().nativeTrial?.requestID == fresh.requestID)
        registry.bindings[valid.orderID]?.pending = nil
        try store.save(registry)
        try check(try store.load().bindings[valid.orderID]?.pending == nil)
        print("Client updates: \(count) checks passed; identity, complete roster, bounds, digest, version, encrypted persistence")
    }
}
