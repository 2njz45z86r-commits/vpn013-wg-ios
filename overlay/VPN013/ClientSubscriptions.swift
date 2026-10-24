// SPDX-License-Identifier: MIT
import Foundation

struct ClientBinding: Codable {
    var document: ClientAccessDocument
    var profileIDs: [String: String] = [:]
    var baseline: [String: String] = [:]
    var pending: ClientSnapshot?
    var lastCheck: Date?
}

struct ClientAutoBinding: Codable {
    var profileID: String
    var sources: [String]
}

struct ClientRegistry: Codable {
    var version = 1
    var bindings: [String: ClientBinding] = [:]
    var automatic: [ClientAutoBinding] = []
}

/// Capabilities and cached configurations stay encrypted in this app's sandbox.
/// This uses the same no-App-Group storage that supports the existing ESign setup.
final class ClientRegistryStore {
    private struct DiskEnvelope: Codable { let id: String; let ciphertext: Data }
    let directory: URL
    init(directory: URL = PrivateTunnelStore.defaultDirectory) { self.directory = directory }
    private var file: URL { directory.appendingPathComponent("client-subscriptions-v1.enc") }
    func load() throws -> ClientRegistry {
        guard FileManager.default.fileExists(atPath: file.path) else { return ClientRegistry() }
        let bytes = try Data(contentsOf: file, options: .mappedIfSafe)
        guard bytes.count <= 1_500_000 else { throw ClientUpdateError.invalidDocument }
        let envelope = try JSONDecoder().decode(DiskEnvelope.self, from: bytes)
        let data = try PrivateTunnelStore(directory: directory).open(.init(id: envelope.id, ciphertext: envelope.ciphertext))
        let registry = try JSONDecoder().decode(ClientRegistry.self, from: data)
        guard registry.version == 1 else { throw ClientUpdateError.invalidDocument }
        return registry
    }
    func save(_ registry: ClientRegistry) throws {
        let store = PrivateTunnelStore(directory: directory)
        let old = (try? Data(contentsOf: file)).flatMap { try? JSONDecoder().decode(DiskEnvelope.self, from: $0) }
        let data = try JSONEncoder().encode(registry)
        let envelope = try store.seal(data, reusing: old?.id)
        let output = try JSONEncoder().encode(DiskEnvelope(id: envelope.id, ciphertext: envelope.ciphertext))
        #if os(iOS)
        try output.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try output.write(to: file, options: .atomic)
        #endif
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var url = file; try url.setResourceValues(values)
    }
}

#if os(iOS)
import UIKit

final class ClientUpdateCoordinator {
    static let shared = ClientUpdateCoordinator()
    static let changed = Notification.Name("VPN013ClientUpdatesChanged")
    private let store = ClientRegistryStore()
    private(set) var registry = ClientRegistry()
    private(set) var status = "Проверка при открытии приложения, не чаще раза в сутки."
    private(set) var release: ClientAppRelease?
    private(set) var busy = false
    private var loadingError: Error?
    private var attemptedAt: Date?
    private var lastPendingAttempt: Date?
    weak var presenter: UIViewController?

    private init() {
        do { registry = try store.load() }
        catch { loadingError = error; status = "Не удалось открыть защищённые привязки. Импортируйте ZIP из бота заново." }
        #if DEBUG && targetEnvironment(simulator)
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-sync") {
            registry = ClientRegistry(); loadingError = nil
            try? store.save(registry)
        }
        #endif
    }
    private func publish(_ message: String) {
        status = message
        NotificationCenter.default.post(name: Self.changed, object: nil)
    }
    private func save() throws { guard loadingError == nil else { throw loadingError! }; try store.save(registry) }
    private func quietForTests() -> Bool {
        #if targetEnvironment(simulator)
        return ProcessInfo.processInfo.arguments.contains(where: { $0.hasPrefix("--vpn013-test") })
        #else
        return false
        #endif
    }
    func tick(manager: TunnelsManager?, presenter: UIViewController) {
        self.presenter = presenter
        guard !busy, !quietForTests(), let manager = manager, loadingError == nil else { return }
        let now = Date()
        if registry.bindings.values.contains(where: { $0.pending != nil }), !manager.mapTunnels(transform: { $0.status != .inactive || $0.isActivateOnDemandEnabled }).contains(true),
           lastPendingAttempt == nil || now.timeIntervalSince(lastPendingAttempt!) > 60 {
            lastPendingAttempt = now
            applyPending(manager: manager) { _ in }
            return
        }
        let success = UserDefaults.standard.object(forKey: "VPN013LastClientUpdateCheck") as? Date
        guard (success == nil || now.timeIntervalSince(success!) >= 86_400),
              attemptedAt == nil || now.timeIntervalSince(attemptedAt!) > 900 else { return }
        check(manager: manager, manual: false)
    }
    func check(manager: TunnelsManager, manual: Bool) {
        guard !busy else { return }
        guard loadingError == nil else { publish("Защищённое хранилище недоступно. Прежние профили сохранены."); return }
        busy = true; attemptedAt = Date(); publish("Проверяем обновления…")
        ClientHTTPTask.request(path: "/client/releases/vpn013-wg/ios") { [weak self] result in
            guard let self = self else { return }
            var appMessage: String
            switch result {
            case .success(let data):
                do {
                    let value = try JSONDecoder().decode(ClientAppRelease.self, from: data); try value.validate()
                    let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
                    let build = Int(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0") ?? 0
                    self.release = value.isNewer(version: version, build: build) ? value : nil
                    appMessage = self.release.map { "Доступна версия \($0.version). Скачайте IPA в боте, подпишите и установите." } ?? "Установлена актуальная версия."
                    UserDefaults.standard.set(Date(), forKey: "VPN013LastClientUpdateCheck")
                } catch { appMessage = ClientUpdateError.invalidResponse.localizedDescription }
            case .failure: appMessage = ClientUpdateError.network.localizedDescription
            }
            let orders = Array(self.registry.bindings.keys).sorted()
            self.fetch(orders: orders, index: 0, errors: []) { errors in
                self.busy = false
                self.publish(appMessage + (errors.isEmpty ? "" : "\n\n" + errors.joined(separator: "\n")))
                self.applyPending(manager: manager) { applyError in
                    if let applyError = applyError { self.publish(self.status + "\n\n" + applyError.localizedDescription) }
                    if manual || self.release != nil { self.showResult() }
                }
            }
        }
    }
    private func fetch(orders: [String], index: Int, errors: [String], completion: @escaping ([String]) -> Void) {
        guard index < orders.count else { completion(errors); return }
        let order = orders[index]
        guard let binding = registry.bindings[order] else { completion(errors); return }
        ClientHTTPTask.request(path: "/client/awg/" + order, capability: binding.document.capability) { [weak self] result in
            guard let self = self else { return }
            var failures = errors
            do {
                let data = try result.get()
                let snapshot = try JSONDecoder().decode(ClientSnapshot.self, from: data)
                try snapshot.validate(orderID: order)
                guard snapshot.expiry > Int64(Date().timeIntervalSince1970 * 1000) else { throw ClientUpdateError.accessEnded }
                _ = try self.configurations(snapshot)
                self.registry.bindings[order]?.lastCheck = Date()
                if snapshot.revision != binding.document.snapshot.revision || snapshot.expiry != binding.document.snapshot.expiry || !self.mappingComplete(binding, snapshot: snapshot) {
                    self.registry.bindings[order]?.pending = snapshot
                }
                try self.save()
            } catch { failures.append("Заявка №" + order + ": " + (error as? ClientUpdateError ?? .network).localizedDescription) }
            self.fetch(orders: orders, index: index + 1, errors: failures, completion: completion)
        }
    }
    private func mappingComplete(_ binding: ClientBinding, snapshot: ClientSnapshot) -> Bool {
        Set(binding.profileIDs.keys) == Set(snapshot.servers.map { $0.id })
    }
    private func configurations(_ snapshot: ClientSnapshot) throws -> [String: TunnelConfiguration] {
        try snapshot.validate()
        var result: [String: TunnelConfiguration] = [:]
        for server in snapshot.servers {
            let config = try TunnelConfiguration(fromWgQuickConfig: server.config, called: server.name)
            guard !config.peers.isEmpty, config.peers.allSatisfy({ $0.endpoint != nil }) else { throw ClientUpdateError.invalidDocument }
            result[server.id] = config
        }
        return result
    }
    func importDocument(_ document: ClientAccessDocument, manager: TunnelsManager, completion: @escaping (Error?) -> Void) {
        guard !busy else { completion(ClientUpdateError.busy); return }
        do {
            try document.validate(); _ = try configurations(document.snapshot)
            guard document.snapshot.expiry > Int64(Date().timeIntervalSince1970 * 1000) else { throw ClientUpdateError.accessEnded }
            guard loadingError == nil else { throw ClientUpdateError.invalidDocument }
            let order = document.snapshot.orderID
            var binding = registry.bindings[order] ?? ClientBinding(document: document)
            binding.document = document; binding.pending = document.snapshot
            // Explicit ZIP import can bind exact, unclaimed existing configurations.
            let claimed = Set(registry.bindings.values.flatMap { $0.profileIDs.values })
            let all = manager.mapTunnels { $0 }
            for server in document.snapshot.servers where binding.profileIDs[server.id] == nil {
                let canonical = try TunnelConfiguration(fromWgQuickConfig: server.config, called: server.name).asWgQuickConfig()
                let matches = all.filter { !$0.isVPN013Automatic && !claimed.contains($0.persistentProfileIdentifier ?? "") && $0.tunnelConfiguration?.asWgQuickConfig() == canonical }
                if matches.count == 1, let id = matches[0].persistentProfileIdentifier {
                    binding.profileIDs[server.id] = id; binding.baseline[server.id] = ClientUpdateProtocol.digest(canonical)
                }
            }
            registry.bindings[order] = binding; try save()
            applyPending(manager: manager, completion: completion)
        } catch { completion(error) }
    }
    func rememberAuto(_ tunnel: TunnelContainer, sources: [TunnelContainer]) {
        guard let id = tunnel.persistentProfileIdentifier else { return }
        registry.automatic.removeAll { $0.profileID == id }
        registry.automatic.append(.init(profileID: id, sources: sources.compactMap { $0.persistentProfileIdentifier }))
        do { try save() } catch { publish("Не удалось сохранить связь Авто с обновлениями. Создайте Авто заново.") }
    }
    private func inferOldAuto(manager: TunnelsManager) {
        let all = manager.mapTunnels { $0 }
        for tunnel in all where tunnel.isVPN013Automatic {
            guard let id = tunnel.persistentProfileIdentifier, !registry.automatic.contains(where: { $0.profileID == id }), let profile = tunnel.automaticProfileForUpdates else { continue }
            var members: [String] = []
            for candidate in profile.candidates {
                let canonical = (try? TunnelConfiguration(fromWgQuickConfig: candidate.config, called: candidate.name))?.asWgQuickConfig()
                let matches = all.filter { !$0.isVPN013Automatic && $0.tunnelConfiguration?.asWgQuickConfig() == canonical }
                if matches.count == 1, let member = matches[0].persistentProfileIdentifier { members.append(member) }
            }
            if members.count == profile.candidates.count { registry.automatic.append(.init(profileID: id, sources: members)) }
        }
    }
    func applyPending(manager: TunnelsManager, completion: @escaping (Error?) -> Void) {
        guard !busy else { completion(ClientUpdateError.busy); return }
        let orders = registry.bindings.keys.filter { registry.bindings[$0]?.pending != nil }.sorted()
        guard !orders.isEmpty else { completion(nil); return }
        guard !manager.mapTunnels(transform: { $0.status != .inactive || $0.isActivateOnDemandEnabled }).contains(true) else { completion(ClientUpdateError.activeVPN); return }
        busy = true; manager.beginManagedUpdate(); inferOldAuto(manager: manager)
        func next(_ index: Int) {
            guard index < orders.count else {
                busy = false; manager.endManagedUpdate(); publish(status + "\nСостав серверов обновлён."); completion(nil); return
            }
            apply(order: orders[index], manager: manager) { error in
                if let error = error { self.busy = false; manager.endManagedUpdate(); completion(error) }
                else { next(index + 1) }
            }
        }
        next(0)
    }
    private func apply(order: String, manager: TunnelsManager, completion: @escaping (Error?) -> Void) {
        guard let binding = registry.bindings[order], let snapshot = binding.pending else { completion(nil); return }
        let configs: [String: TunnelConfiguration]
        let plan: ClientRosterPlan
        do {
            configs = try configurations(snapshot)
            plan = try ClientRosterPlan(previousIDs: Set(binding.profileIDs.keys), snapshot: snapshot)
            guard snapshot.expiry > Int64(Date().timeIntervalSince1970 * 1000) else { throw ClientUpdateError.accessEnded }
            for (serverID, id) in binding.profileIDs {
                guard let current = manager.mapTunnels(transform: { $0 }).first(where: { $0.persistentProfileIdentifier == id }), let config = current.tunnelConfiguration else { continue }
                guard binding.baseline[serverID] == ClientUpdateProtocol.digest(config.asWgQuickConfig()) else { throw ClientUpdateError.localChanges(current.name) }
            }
            for server in plan.retained {
                guard let id = binding.profileIDs[server.id], let current = manager.mapTunnels(transform: { $0 }).first(where: { $0.persistentProfileIdentifier == id }), let config = current.tunnelConfiguration else { continue }
                guard binding.baseline[server.id] == ClientUpdateProtocol.digest(config.asWgQuickConfig()),
                      Self.keyMaterial(config.asWgQuickConfig()) == Self.keyMaterial(server.config) else { throw ClientUpdateError.localChanges(current.name) }
            }
            try save() // Persist intent before touching any system VPN preferences.
        } catch { completion(error); return }
        let oldIDs = Set(binding.profileIDs.values)
        func saveProgress() throws { try self.save() }
        func update(_ index: Int) {
            guard index < snapshot.servers.count else { updateAutos(); return }
            let server = snapshot.servers[index]
            guard let config = configs[server.id] else { completion(ClientUpdateError.invalidDocument); return }
            let all = manager.mapTunnels { $0 }
            let current = registry.bindings[order]?.profileIDs[server.id].flatMap { id in all.first { $0.persistentProfileIdentifier == id } }
            let named: TunnelConfiguration
            if let current = current { named = TunnelConfiguration(name: current.name, interface: config.interface, peers: config.peers) }
            else {
                var name = server.name; var counter = 1
                while all.contains(where: { $0.name == name }) { name = server.name + " · " + order.prefix(4) + "-\(counter)"; counter += 1 }
                named = TunnelConfiguration(name: name, interface: config.interface, peers: config.peers)
            }
            func recorded(_ tunnel: TunnelContainer) {
                guard let id = tunnel.persistentProfileIdentifier else { completion(ClientUpdateError.invalidResponse); return }
                registry.bindings[order]?.profileIDs[server.id] = id
                registry.bindings[order]?.baseline[server.id] = ClientUpdateProtocol.digest(named.asWgQuickConfig())
                do { try saveProgress(); update(index + 1) } catch { completion(error) }
            }
            if let current = current {
                if current.tunnelConfiguration?.asWgQuickConfig() == named.asWgQuickConfig() { recorded(current) }
                else { manager.modify(tunnel: current, tunnelConfiguration: named, onDemandOption: current.onDemandOption) { error in
                    if let error = error { completion(error) } else { recorded(current) }
                } }
            } else { manager.add(tunnelConfiguration: named) { result in
                switch result { case .success(let tunnel): recorded(tunnel); case .failure(let error): completion(error) }
            } }
        }
        func updateAutos() {
            let removed = Set(plan.removedIDs.compactMap { registry.bindings[order]?.profileIDs[$0] })
            let newMembers = snapshot.servers.compactMap { registry.bindings[order]?.profileIDs[$0.id] }
            let relevant = registry.automatic.indices.filter { !Set(registry.automatic[$0].sources).isDisjoint(with: oldIDs) }
            func nextAuto(_ index: Int) {
                guard index < relevant.count else { remove(0); return }
                let recordIndex = relevant[index]
                let record = registry.automatic[recordIndex]
                let all = manager.mapTunnels { $0 }
                guard let tunnel = all.first(where: { $0.persistentProfileIdentifier == record.profileID }) else { nextAuto(index + 1); return }
                var sourceIDs = record.sources.filter { !removed.contains($0) }
                for id in newMembers where !sourceIDs.contains(id) { sourceIDs.append(id) }
                let members = sourceIDs.compactMap { id in all.first { $0.persistentProfileIdentifier == id }?.tunnelConfiguration }
                do {
                    guard members.count == sourceIDs.count, (1...30).contains(members.count), let first = members.first else { throw ClientUpdateError.invalidResponse }
                    let profile = try AutoTunnelProfile(configurations: members)
                    let config = TunnelConfiguration(name: "Авто · " + AutoTunnelProfile.serverCountLabel(members.count), interface: first.interface, peers: first.peers)
                    manager.modify(tunnel: tunnel, tunnelConfiguration: config, onDemandOption: tunnel.onDemandOption, automaticProfile: profile) { error in
                        if let error = error { completion(error); return }
                        self.registry.automatic[recordIndex].sources = sourceIDs
                        do { try saveProgress(); nextAuto(index + 1) } catch { completion(error) }
                    }
                } catch { completion(error) }
            }
            nextAuto(0)
        }
        func remove(_ index: Int) {
            guard index < plan.removedIDs.count else {
                registry.bindings[order]?.document = ClientAccessDocument(schema: 1, kind: "vpn013-access", capability: binding.document.capability, snapshot: snapshot)
                registry.bindings[order]?.pending = nil
                do { try saveProgress(); completion(nil) } catch { completion(error) }
                return
            }
            let serverID = plan.removedIDs[index]
            let tunnel = registry.bindings[order]?.profileIDs[serverID].flatMap { id in manager.mapTunnels { $0 }.first { $0.persistentProfileIdentifier == id } }
            func removed() {
                registry.bindings[order]?.profileIDs.removeValue(forKey: serverID)
                registry.bindings[order]?.baseline.removeValue(forKey: serverID)
                do { try saveProgress(); remove(index + 1) } catch { completion(error) }
            }
            if let tunnel = tunnel { manager.remove(tunnel: tunnel) { error in if let error = error { completion(error) } else { removed() } } }
            else { removed() }
        }
        update(0)
    }
    private static func keyMaterial(_ config: String) -> [String] {
        config.components(separatedBy: .newlines).compactMap { line in
            let pair = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard pair.count == 2, ["privatekey", "publickey", "presharedkey"].contains(pair[0].lowercased()) else { return nil }
            return pair[0].lowercased() + "=" + pair[1]
        }.sorted()
    }
    func unbind(order: String) throws {
        guard !busy else { throw ClientUpdateError.busy }
        registry.bindings.removeValue(forKey: order); try save(); publish("Обновления заявки отключены. Конфигурации сохранены.")
    }
    private func showResult() {
        guard let presenter = presenter, presenter.presentedViewController == nil else { return }
        let alert = UIAlertController(title: release == nil ? "Обновления" : "Доступно обновление", message: status, preferredStyle: .alert)
        if release != nil { alert.addAction(UIAlertAction(title: "Перейти в бот", style: .default) { _ in UIApplication.shared.open(ClientUpdateProtocol.botURL) }) }
        alert.addAction(UIAlertAction(title: "Понятно", style: .cancel)); presenter.present(alert, animated: true)
    }
}
#endif
