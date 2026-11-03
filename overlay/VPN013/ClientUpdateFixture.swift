// SPDX-License-Identifier: MIT
#if DEBUG && targetEnvironment(simulator)
import Foundation
import NetworkExtension

enum ClientUpdateFixture {
    static func run(manager: TunnelsManager, completion: @escaping (String) -> Void) {
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-ownership-corrupt") {
            ClientOwnershipFixture.runCorrupt(manager: manager, completion: completion)
            return
        }
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-ownership") {
            ClientOwnershipFixture.runNormal(manager: manager, completion: completion)
            return
        }
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

// Simulator-only regression harness. Uses synthetic mock configurations and an
// isolated simulator; it never opens a real customer configuration.
enum ClientOwnershipFixture {
    private static var seeded = false
    private static let order = "012345abcdef"
    private static func document(_ servers: [ClientServer]) -> ClientAccessDocument {
        let revision = ClientUpdateProtocol.digest(servers.map { $0.id + "\n" + $0.name + "\n" + $0.config + "\n" }.joined())
        return .init(schema: 1, kind: "vpn013-access", capability: String(repeating: "A", count: 43),
                     snapshot: .init(schema: 1, kind: "vpn013-awg", orderID: order,
                                     expiry: 2_000_000_000_000, revision: revision, complete: true, servers: servers))
    }
    private static func inventory(_ manager: TunnelsManager) -> [String: String]? {
        let all = manager.mapTunnels { $0 }.filter { !$0.isVPN013Automatic }
        var result: [String: String] = [:]
        for tunnel in all {
            guard let id = tunnel.persistentProfileIdentifier, let config = tunnel.tunnelConfiguration,
                  result[id] == nil else { return nil }
            result[id] = ClientUpdateProtocol.digest(config.asWgQuickConfig())
        }
        return result
    }
    private static func preserves(_ original: [String: String], _ current: [String: String]?) -> Bool {
        guard let current = current else { return false }
        return original.allSatisfy { current[$0.key] == $0.value }
    }
    static func seedCorruptRegistryOnce(_ providers: [NETunnelProviderManager]) {
        guard !seeded else { return }; seeded = true
        precondition(providers.count >= 2, "Synthetic simulator profiles required")
        let tunnel = TunnelContainer(tunnel: providers[0])
        guard let id = tunnel.persistentProfileIdentifier, let config = tunnel.tunnelConfiguration else {
            preconditionFailure("Synthetic simulator profile identity missing")
        }
        let raw = config.asWgQuickConfig()
        let a = ClientServer(id: "a", name: "Synthetic A", config: raw)
        let b = ClientServer(id: "b", name: "Synthetic B", config: raw)
        var registry = ClientRegistry()
        var binding = ClientBinding(document: document([a, b]))
        // Corruption: two server entries own the same profile. Pending update
        // removes 'a', which would delete the profile still referenced by 'b'.
        binding.profileIDs = ["a": id, "b": id]
        binding.baseline = ["a": ClientUpdateProtocol.digest(raw), "b": ClientUpdateProtocol.digest(raw)]
        binding.pending = document([b]).snapshot
        registry.bindings[order] = binding
        do { try ClientRegistryStore().save(registry) }
        catch { preconditionFailure("Could not seed synthetic registry: \(error)") }
    }
    static func runCorrupt(manager: TunnelsManager, completion: @escaping (String) -> Void) {
        let coordinator = ClientUpdateCoordinator.shared
        guard let before = inventory(manager), before.count >= 2,
              let binding = coordinator.registry.bindings[order], binding.pending != nil,
              binding.profileIDs["a"] == binding.profileIDs["b"],
              let pending = binding.pending, pending.servers.map({ $0.id }) == ["b"] else {
            completion("Ownership corrupt setup failed"); return
        }
        coordinator.applyPending(manager: manager) { applyError in
            guard applyError != nil, inventory(manager) == before else {
                completion("Ownership corrupt pending modified profiles"); return
            }
            let attempted = ClientAccessDocument(schema: 1, kind: "vpn013-access", capability: binding.document.capability, snapshot: pending)
            coordinator.importDocument(attempted, manager: manager) { importError in
                guard importError != nil, inventory(manager) == before,
                      coordinator.registry.bindings[order]?.pending != nil else {
                    completion("Ownership corrupt import modified profiles"); return
                }
                completion("OWNERSHIP_CORRUPT_REJECTED_PROFILES_PRESERVED")
            }
        }
    }
    static func runNormal(manager: TunnelsManager, completion: @escaping (String) -> Void) {
        let coordinator = ClientUpdateCoordinator.shared
        guard let first = manager.mapTunnels(transform: { $0 }).first,
              let original = first.tunnelConfiguration, inventory(manager)?.count == 2 else {
            completion("Ownership normal setup failed"); return
        }
        let duplicate = TunnelConfiguration(name: "Synthetic duplicate", interface: original.interface, peers: original.peers)
        manager.add(tunnelConfiguration: duplicate) { addResult in
            guard case .success = addResult, let before = inventory(manager), before.count == 3 else {
                completion("Ownership duplicate setup failed"); return
            }
            let a = ClientServer(id: "a", name: "Synthetic A", config: original.asWgQuickConfig())
            let b = ClientServer(id: "b", name: "Synthetic B", config: original.asWgQuickConfig())
            coordinator.importDocument(document([a, b]), manager: manager) { error in
                guard error == nil, let binding = coordinator.registry.bindings[order],
                      let aid = binding.profileIDs["a"], let bid = binding.profileIDs["b"],
                      aid != bid, before[aid] == nil, before[bid] == nil,
                      preserves(before, inventory(manager)) else {
                    completion("Ownership duplicate import modified existing profiles"); return
                }
                coordinator.importDocument(document([b]), manager: manager) { refreshError in
                    guard refreshError == nil, let after = inventory(manager), preserves(before, after),
                          after[aid] == nil, after[bid] != nil,
                          coordinator.registry.bindings[order]?.profileIDs["b"] == bid else {
                        completion("Ownership removal changed unrelated profile"); return
                    }
                    completion("OWNERSHIP_IMPORT_REMOVE_PROFILES_PRESERVED")
                }
            }
        }
    }
}
#endif
