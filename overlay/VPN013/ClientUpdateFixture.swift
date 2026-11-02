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
        func document(_ servers: [ClientServer], order: String = "012345abcdef") -> ClientAccessDocument {
            let digest = ClientUpdateProtocol.digest(servers.map { $0.id+"\n"+$0.name+"\n"+$0.config+"\n" }.joined())
            return .init(schema:1,kind:"vpn013-access",capability:String(repeating:"A",count:43),snapshot:.init(schema:1,kind:"vpn013-awg",orderID:order,expiry:2_000_000_000_000,revision:digest,complete:true,servers:servers))
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
                        // Exercise actual manager deletion with the same server revision,
                        // then supplier growth/shrink while keeping foreign and Auto members.
                        let servers = (1...20).map { index in
                            ClientServer(id:"node\(index)",name:"Managed \(index)",config:generated[index % generated.count].asWgQuickConfig())
                        }
                        func assertRoster(_ count: Int) -> Bool {
                            let actual = manager.mapTunnels { $0 }
                            guard let binding = coordinator.registry.bindings["012345abcdef"],
                                  binding.profileIDs.count == count,
                                  actual.count == count + 2,
                                  actual.first(where:{ $0.persistentProfileIdentifier == foreignID })?.tunnelConfiguration?.asWgQuickConfig() == foreign.asWgQuickConfig(),
                                  actual.first(where:{ $0.isVPN013Automatic })?.automaticServerCount == count+1 else { return false }
                            return ClientRosterPlan.mappingComplete(binding.profileIDs,snapshot:binding.document.snapshot,
                                availableProfileIDs:Set(actual.compactMap { $0.persistentProfileIdentifier }))
                        }
                        func apply(_ count: Int, _ done: @escaping () -> Void) {
                            coordinator.importDocument(document(Array(servers.prefix(count))),manager:manager) { error in
                                guard error == nil, assertRoster(count) else { completion("Roster \(count) failed: " + (error?.localizedDescription ?? "invariant")); return }
                                done()
                            }
                        }
                        func eraseManaged(_ ids: [String], _ done: @escaping () -> Void) {
                            guard let first = ids.first else { done(); return }
                            guard let item = manager.mapTunnels(transform: { $0 }).first(where:{ $0.persistentProfileIdentifier == first }) else { completion("Deletion fixture missing"); return }
                            manager.remove(tunnel:item) { error in
                                guard error == nil else { completion("Deletion failed"); return }
                                eraseManaged(Array(ids.dropFirst()),done)
                            }
                        }
                        apply(10) {
                            let first = coordinator.registry.bindings["012345abcdef"]!.profileIDs.values.sorted().first!
                            eraseManaged([first]) {
                                apply(10) {
                                    let ids = Array(coordinator.registry.bindings["012345abcdef"]!.profileIDs.values)
                                    eraseManaged(ids) {
                                        apply(10) { apply(20) { apply(15) { apply(15) {
                                            let order = "fedcba987654"
                                            let raw = generated[0].asWgQuickConfig().replacingOccurrences(of: "[Peer]", with: "I1 = <t>\n[Peer]")
                                            let ambiguous = ClientServer(id: "legacy", name: "Synthetic ambiguous", config: raw)
                                            let doc = document([ambiguous], order: order)
                                            let before = manager.mapTunnels { $0.persistentProfileIdentifier }.compactMap { $0 }.sorted()
                                            coordinator.importDocument(doc, manager: manager) { error in
                                                guard let failure = error as? ClientUpdateError, case .versionChoiceRequired = failure,
                                                      coordinator.registry.bindings[order] == nil,
                                                      manager.mapTunnels(transform: { $0.persistentProfileIdentifier }).compactMap({ $0 }).sorted() == before else {
                                                    completion("Ambiguous managed import changed profiles without a choice"); return
                                                }
                                                coordinator.importDocument(doc, manager: manager, awgVersionChoices: ["legacy": true]) { error in
                                                    guard error == nil, let binding = coordinator.registry.bindings[order],
                                                          binding.awgVersionChoices?["legacy"] == true,
                                                          let id = binding.profileIDs["legacy"],
                                                          manager.mapTunnels(transform: { $0 }).first(where: { $0.persistentProfileIdentifier == id })?.tunnelConfiguration?.interface.legacyAWG15 == true else {
                                                        completion("Managed 1.5 choice was not applied"); return
                                                    }
                                                    coordinator.importDocument(doc, manager: manager) { error in
                                                        guard error == nil, coordinator.registry.bindings[order]?.profileIDs["legacy"] == id,
                                                              coordinator.registry.bindings[order]?.awgVersionChoices?["legacy"] == true,
                                                              manager.mapTunnels(transform: { $0 }).first(where: { $0.persistentProfileIdentifier == foreignID })?.tunnelConfiguration?.asWgQuickConfig() == foreign.asWgQuickConfig() else {
                                                            completion("Managed choice was not retained on update"); return
                                                        }
                                                        let changedRaw = raw.replacingOccurrences(of: ":4444", with: ":4445")
                                                        guard changedRaw != raw else { completion("Endpoint fixture did not change"); return }
                                                        let changed = ClientServer(id: "legacy", name: "Synthetic ambiguous", config: changedRaw)
                                                        let changedDocument = document([changed], order: order)
                                                        coordinator.importDocument(changedDocument, manager: manager) { error in
                                                            guard let failure = error as? ClientUpdateError, case .versionChoiceRequired = failure,
                                                                  manager.mapTunnels(transform: { $0 }).first(where: { $0.persistentProfileIdentifier == id })?.tunnelConfiguration?.interface.legacyAWG15 == true else {
                                                                completion("Changed ambiguous config reused a stale version choice"); return
                                                            }
                                                            coordinator.importDocument(changedDocument, manager: manager, awgVersionChoices: ["legacy": false]) { error in
                                                                guard error == nil, coordinator.registry.bindings[order]?.awgVersionChoices?["legacy"] == false,
                                                                      let temporary = manager.mapTunnels(transform: { $0 }).first(where: { $0.persistentProfileIdentifier == id }),
                                                                      temporary.tunnelConfiguration?.interface.legacyAWG15 == false else {
                                                                    completion("New managed version choice was not applied"); return
                                                                }
                                                                manager.remove(tunnel: temporary) { error in
                                                                    guard error == nil else { completion("Managed choice cleanup failed"); return }
                                                                    do { try coordinator.unbind(order: order) }
                                                                    catch { completion("Managed choice registry cleanup failed"); return }
                                                                    completion("Проверено: добавление, удаление, ключи, сторонний профиль и Авто · 3 сервера; восстановление удалённых, 10→20→15, Авто · 16 серверов")
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } } } }
                                    }
                                }
                            }
                        }
                    }
                }
            } catch { completion(error.localizedDescription) }
        }
    }
}
#endif
