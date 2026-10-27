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
    var nativeTrial: ClientNativeTrialState? = nil
    var renewalsAwaitingReturn: [String: Int64]? = nil
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
        guard bytes.count <= 6_000_000 else { throw ClientUpdateError.invalidDocument }
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
    private var subscriptionMessages: [String] = []
    weak var presenter: UIViewController?

    private init() {
        do { registry = try store.load() }
        catch { loadingError = error; status = "Не удалось открыть защищённые привязки. Импортируйте ZIP из бота заново." }
        #if DEBUG && targetEnvironment(simulator)
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-sync") || ProcessInfo.processInfo.arguments.contains(where: { $0.hasPrefix("--vpn013-test-native-trial") }) {
            registry = ClientRegistry(); loadingError = nil
            try? store.save(registry)
        }
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-direct-download") {
            release = ClientAppRelease(schema: 1, app: "vpn013-wg", platform: "ios", version: "99.0.0", build: 999,
                downloadURL: "https://github.com/2njz45z86r-commits/vpn013-wg-ios/releases/download/unsigned-test/VPN013AWG-unsigned.ipa",
                sha256: String(repeating: "a", count: 64), notes: "Synthetic UI fixture; no external transfer")
            status = "Доступна тестовая версия 99.0.0."
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
        NativeTrialCoordinator.shared.tick(manager: manager, presenter: presenter)
        guard !busy else { return }
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
        busy = true; attemptedAt = Date(); subscriptionMessages = []; publish("Проверяем обновления…")
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
                    appMessage = self.release.map { "Доступна версия \($0.version). Нажмите «Скачать IPA» для прямой загрузки, затем подпишите и установите файл." } ?? "Установлена актуальная версия."
                    UserDefaults.standard.set(Date(), forKey: "VPN013LastClientUpdateCheck")
                } catch { appMessage = ClientUpdateError.invalidResponse.localizedDescription }
            case .failure: appMessage = ClientUpdateError.network.localizedDescription
            }
            let orders = Array(self.registry.bindings.keys).sorted()
            self.fetch(orders: orders, index: 0, errors: [], manager: manager) { errors in
                self.busy = false
                self.publish(([appMessage] + self.subscriptionMessages + errors).joined(separator: "\n\n"))
                self.applyPending(manager: manager) { applyError in
                    if let applyError = applyError { self.publish(self.status + "\n\n" + applyError.localizedDescription) }
                    if manual || self.release != nil { self.showResult() }
                }
            }
        }
    }
    private func fetch(orders: [String], index: Int, errors: [String], manager: TunnelsManager, completion: @escaping ([String]) -> Void) {
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
                if snapshot.revision != binding.document.snapshot.revision || snapshot.expiry != binding.document.snapshot.expiry || !self.mappingComplete(binding, snapshot: snapshot, manager: manager) {
                    self.registry.bindings[order]?.pending = snapshot
                }
                let formatter = DateFormatter(); formatter.dateStyle = .short; formatter.timeStyle = .short
                let expiry = formatter.string(from: Date(timeIntervalSince1970: Double(snapshot.expiry) / 1000))
                self.subscriptionMessages.append("Подписка №\(order): \(snapshot.servers.count) серверов. Действует до \(expiry).")
                try self.save()
            } catch { failures.append("Заявка №" + order + ": " + (error as? ClientUpdateError ?? .network).localizedDescription) }
            self.fetch(orders: orders, index: index + 1, errors: failures, manager: manager, completion: completion)
        }
    }
    private func mappingComplete(_ binding: ClientBinding, snapshot: ClientSnapshot, manager: TunnelsManager) -> Bool {
        let available = Set(manager.mapTunnels { $0.persistentProfileIdentifier }.compactMap { $0 })
        return ClientRosterPlan.mappingComplete(binding.profileIDs, snapshot: snapshot, availableProfileIDs: available)
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
            let newMembers = snapshot.servers.compactMap { registry.bindings[order]?.profileIDs[$0.id] }
            let relevant = registry.automatic.indices.filter { !Set(registry.automatic[$0].sources).isDisjoint(with: oldIDs) }
            func nextAuto(_ index: Int) {
                guard index < relevant.count else { remove(0); return }
                let recordIndex = relevant[index]
                let record = registry.automatic[recordIndex]
                let all = manager.mapTunnels { $0 }
                guard let tunnel = all.first(where: { $0.persistentProfileIdentifier == record.profileID }) else { nextAuto(index + 1); return }
                // Replace this order's complete contribution, including locally deleted IDs.
                var sourceIDs = record.sources.filter { !oldIDs.contains($0) }
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
                registry.bindings[order]?.document = ClientAccessDocument(schema: 1, kind: "vpn013-access", capability: binding.document.capability, snapshot: snapshot, trial: binding.document.trial)
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
    func nativeTrialState() throws -> ClientNativeTrialState {
        guard loadingError == nil else { throw ClientUpdateError.invalidDocument }
        if let value = registry.nativeTrial { return value }
        let value = ClientNativeTrialState.fresh(); registry.nativeTrial = value; try save(); return value
    }
    func saveNativeTrial(_ value: ClientNativeTrialState) throws {
        guard ClientUpdateProtocol.validToken(value.requestID), value.ticket == nil || ClientUpdateProtocol.validToken(value.ticket!) else { throw ClientUpdateError.invalidDocument }
        try value.info?.validate(previous: registry.nativeTrial?.info)
        registry.nativeTrial = value; try save()
    }
    func rememberRenewal(_ order: String) throws {
        guard ClientUpdateProtocol.validID(order) else { throw ClientUpdateError.invalidDocument }
        if registry.renewalsAwaitingReturn == nil { registry.renewalsAwaitingReturn = [:] }
        registry.renewalsAwaitingReturn?[order] = registry.bindings[order]?.document.snapshot.expiry ?? registry.nativeTrial?.info?.expiresAt ?? 0
        try save()
    }
    func refreshRenewal(order: String, manager: TunnelsManager, completion: @escaping () -> Void) {
        guard !busy, registry.bindings[order] != nil else { completion(); return }
        busy = true
        fetch(orders: [order], index: 0, errors: [], manager: manager) { _ in
            self.busy = false
            let binding = self.registry.bindings[order]
            let expiry = binding?.pending?.expiry ?? binding?.document.snapshot.expiry ?? 0
            if let old = self.registry.renewalsAwaitingReturn?[order], expiry > old {
                self.registry.renewalsAwaitingReturn?.removeValue(forKey: order); try? self.save()
            }
            self.applyPending(manager: manager) { _ in completion() }
        }
    }
    private func showResult() {
        guard let presenter = presenter, presenter.presentedViewController == nil else { return }
        let alert = UIAlertController(title: release == nil ? "Обновления" : "Доступно обновление", message: status, preferredStyle: .alert)
        if let release = release { alert.addAction(UIAlertAction(title: "Скачать IPA", style: .default) { [weak presenter] _ in
            guard let presenter = presenter else { return }
            ClientReleaseDownload.open(release, from: presenter)
        }) }
        alert.addAction(UIAlertAction(title: "Понятно", style: .cancel)); presenter.present(alert, animated: true)
    }
}
#endif
