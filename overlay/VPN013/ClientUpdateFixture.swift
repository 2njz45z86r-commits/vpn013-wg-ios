// SPDX-License-Identifier: MIT
#if DEBUG && targetEnvironment(simulator)
import Foundation

enum ClientUpdateFixture {
    static func run(manager: TunnelsManager, completion: @escaping (String) -> Void) {
        let coordinator = ClientUpdateCoordinator.shared
        let manual = manager.mapTunnels { $0 }.filter { !$0.isVPN013Automatic }
        guard manual.count == 2, let original = manual.first?.tunnelConfiguration,
              let originalID = manual.first?.persistentProfileIdentifier,
              let foreignID = manual.last?.persistentProfileIdentifier,
              let foreign = manual.last?.tunnelConfiguration else { completion("Fixture setup failed"); return }
        let generated = MockTunnels.createMockTunnels().compactMap { $0.tunnelConfiguration }
        guard generated.count == 2 else { completion("Fixture generation failed"); return }
        func document(_ servers: [ClientServer]) -> ClientAccessDocument {
            let digest = ClientUpdateProtocol.digest(servers.map { $0.id+"\n"+$0.name+"\n"+$0.config+"\n" }.joined())
            return .init(schema:1,kind:"vpn013-access",capability:String(repeating:"A",count:43),snapshot:.init(schema:1,kind:"vpn013-awg",orderID:"012345abcdef",expiry:2_000_000_000_000,revision:digest,complete:true,servers:servers))
        }
        let a = ClientServer(id:"a",name:manual.first!.name,config:original.asWgQuickConfig())
        let b = ClientServer(id:"b",name:"Managed B",config:generated[0].asWgQuickConfig())
        let c = ClientServer(id:"c",name:"Managed C",config:generated[1].asWgQuickConfig())
        coordinator.importDocument(document([a,b]),manager:manager) { error in
            if let error = error { completion("First import: " + error.localizedDescription); return }
            let sources = manager.mapTunnels { $0 }.filter { !$0.isVPN013Automatic }
            let retainedID = coordinator.registry.bindings["012345abcdef"]?.profileIDs["b"]
            do {
                let configs = sources.compactMap { $0.tunnelConfiguration }
                let auto = try AutoTunnelProfile(configurations:configs)
                let configuration = TunnelConfiguration(name:"Авто · 3 сервера",interface:configs[0].interface,peers:configs[0].peers)
                manager.add(tunnelConfiguration:configuration,automaticProfile:auto) { result in
                    guard case .success(let tunnel) = result else { completion("Auto creation failed"); return }
                    coordinator.rememberAuto(tunnel,sources:sources)
                    coordinator.importDocument(document([b,c]),manager:manager) { error in
                        if let error = error { completion("Refresh: " + error.localizedDescription); return }
                        let all = manager.mapTunnels { $0 }
                        guard !all.contains(where:{ $0.persistentProfileIdentifier == originalID }),
                              all.first(where:{ $0.persistentProfileIdentifier == foreignID })?.tunnelConfiguration?.asWgQuickConfig() == foreign.asWgQuickConfig(),
                              coordinator.registry.bindings["012345abcdef"]?.profileIDs["b"] == retainedID,
                              coordinator.registry.bindings["012345abcdef"]?.profileIDs.count == 2,
                              all.first(where:{ $0.isVPN013Automatic })?.automaticServerCount == 3 else {
                            completion("Synchronization invariant failed"); return
                        }
                        completion("Проверено: добавление, удаление, ключи, сторонний профиль и Авто · 3 сервера")
                    }
                }
            } catch { completion(error.localizedDescription) }
        }
    }
}
#endif
