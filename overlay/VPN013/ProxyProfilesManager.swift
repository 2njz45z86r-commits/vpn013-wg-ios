// SPDX-License-Identifier: MIT
import Foundation
import NetworkExtension

enum ProxyOperationError: LocalizedError {
    case busy, stopFirst, unreadable, switching, system, automaticLimit
    var errorDescription: String? {
        switch self {
        case .busy: return "Дождитесь завершения текущего действия."
        case .stopFirst: return "Сначала выключите это подключение."
        case .unreadable: return "Не удалось прочитать защищённый профиль. Исходные профили сохранены."
        case .switching: return "Предыдущее подключение не отключилось. Проверьте раздел VPN в настройках iPhone."
        case .system: return "iOS не завершила действие с VPN. Повторите попытку и разрешите добавление VPN в системном окне."
        case .automaticLimit: return "Для Авто доступно до 30 серверов в одном разделе. Выключите Авто для ручного подключения при большем списке."
        }
    }
}

final class ProxyProfilesManager {
    struct Entry {
        let manager: NETunnelProviderManager
        var value: ProxyTunnelPayload
        var status: NEVPNStatus {
            #if targetEnvironment(simulator) && DEBUG
            if ProcessInfo.processInfo.arguments.contains("--vpn013-test-proxy-connected-missing") { return .connected }
            #endif
            return manager.connection.status
        }
        var inOperation: Bool { [.connected, .connecting, .reasserting, .disconnecting].contains(status) }
    }
    static let shared = ProxyProfilesManager()
    private(set) var entries: [Entry] = []
    var changed: (() -> Void)?
    var reportError: ((Error) -> Void)?
    private(set) var working = false {
        didSet { NotificationCenter.default.post(name: AutomaticModeRow.availabilityChanged, object: nil) }
    }
    private var activation: UUID?
    private var switchingTimer: Timer?
    private var statusObserver: NSObjectProtocol?
    private var configurationObserver: NSObjectProtocol?
    private let subscriptions = ProxySubscriptionStore()
    private var subscriptionDownload: ProxySubscriptionDownload?
    private var localReads: [UUID: VPN013LocalStatisticsRead] = [:]
    private var automaticControl: VPN013LocalStatisticsRead?
    #if targetEnvironment(simulator) && DEBUG
    private var simulator = true
    #else
    private var simulator = false
    #endif

    init() {
        statusObserver = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in self?.changed?() }
        configurationObserver = NotificationCenter.default.addObserver(forName: .NEVPNConfigurationChange, object: nil, queue: .main) { [weak self] _ in self?.reload() }
    }
    deinit {
        if let token = statusObserver { NotificationCenter.default.removeObserver(token) }
        if let token = configurationObserver { NotificationCenter.default.removeObserver(token) }
        switchingTimer?.invalidate()
        automaticControl?.cancel(); localReads.values.forEach { $0.cancel() }
    }
    func reload() {
        guard !simulator, !working else { changed?(); return }
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self = self, !self.working else { return }
                guard error == nil else { self.reportError?(ProxyOperationError.system); return }
                var result = [Entry](); var unreadable = false
                for manager in managers ?? [] {
                    guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol, proto.isVPN013Proxy else { continue }
                    do { result.append(Entry(manager: manager, value: try proto.proxyPayload())) }
                    catch { unreadable = true } // Never delete a profile because its key is unavailable.
                }
                self.entries = result.sorted { $0.value.profile.name.localizedStandardCompare($1.value.profile.name) == .orderedAscending }
                self.changed?()
                if unreadable { self.reportError?(ProxyOperationError.unreadable) }
            }
        }
    }
    func add(_ profiles: [ProxyProfile], completion: @escaping (Error?) -> Void) {
        guard !working else { completion(ProxyOperationError.busy); return }
        working = true; changed?()
        var remaining = profiles
        func next() {
            guard !remaining.isEmpty else { self.working = false; self.changed?(); completion(nil); return }
            let profile = remaining.removeFirst()
            let duplicate = self.entries.contains { entry in
                var candidate = profile; candidate.id = entry.value.profile.id
                return candidate == entry.value.profile
            }
            if duplicate { next(); return }
            var value = ProxyTunnelPayload(profile: profile)
            #if targetEnvironment(simulator) && DEBUG
            if ProcessInfo.processInfo.arguments.contains("--vpn013-test-proxy-connected-missing") {
                var reserve = profile; reserve.id = UUID(); reserve.name = "Reserve"; reserve.host = "reserve.example.invalid"
                value.automaticCandidates = [profile, reserve]; value.automaticEnabled = true
            }
            #endif
            let manager = NETunnelProviderManager()
            do { manager.protocolConfiguration = try NETunnelProviderProtocol.proxyProtocol(value) }
            catch { self.working = false; self.changed?(); completion(ProxyOperationError.unreadable); return }
            manager.localizedDescription = profile.source.title + " · " + profile.name; manager.isEnabled = true
            self.persist(manager) { error in
                if let error = error {
                    // An OS save error may have an unknown persistence outcome.
                    // Keep its key so a late save never produces an orphan profile.
                    self.working = false; self.changed?(); completion(error); return
                }
                self.entries.append(Entry(manager: manager, value: value)); next()
            }
        }
        next()
    }
    func installSubscription(_ url: URL, profiles: [ProxyProfile], kind: VPN013ConnectionKind, completion: @escaping (Error?) -> Void) {
        guard !working else { completion(ProxyOperationError.busy); return }
        guard !entries.contains(where: { $0.inOperation }) else { completion(ProxyOperationError.stopFirst); return }
        do {
            guard VPN013SubscriptionRequest.isSecure(url), url.absoluteString.utf8.count <= 16_384 else { throw ProxyProfileError.invalid }
            let records = try subscriptions.load()
            let old = records.first { $0.url == url && $0.kind == kind } ?? ProxySubscriptionRecord(id: UUID(), kind: kind, url: url, members: [], checkedAt: nil)
            let desired = try old.replacing(with: profiles)
            working = true
            synchronize(desired) { error in self.working = false; self.changed?(); completion(error) }
        } catch { completion(error is ProxyProfileError ? error : ProxyOperationError.unreadable) }
    }
    /// No implicit periodic HTTP, device reset, expiry extension or URL rotation.
    /// A pull refresh explicitly fetches each saved source of this section.
    func refreshSubscriptions(_ kind: VPN013ConnectionKind, completion: @escaping (Error?) -> Void) {
        guard !working else { completion(ProxyOperationError.busy); return }
        guard !entries.contains(where: { $0.inOperation }) else { completion(ProxyOperationError.stopFirst); return }
        let records: [ProxySubscriptionRecord]
        do { records = try subscriptions.load().filter { $0.kind == kind } }
        catch { completion(ProxyOperationError.unreadable); return }
        guard !records.isEmpty else { reload(); completion(nil); return }
        working = true; changed?()
        var remaining = records
        func finish(_ error: Error?) { self.subscriptionDownload = nil; self.working = false; self.changed?(); completion(error) }
        func next() {
            guard !remaining.isEmpty else { finish(nil); return }
            let record = remaining.removeFirst()
            let identifier: String
            do { identifier = try VPN013SubscriptionIdentity.identifier(for: record.url.host!, directory: PrivateTunnelStore.defaultDirectory) }
            catch { finish(ProxySubscriptionError.identity); return }
            let download = ProxySubscriptionDownload(); self.subscriptionDownload = download
            download.start(record.url, kind: kind, identifier: identifier) { result in
                switch result {
                case .failure(let error): finish(error)
                case .success(let data):
                    DispatchQueue.global(qos: .userInitiated).async {
                        let parsed = Result { try record.replacing(with: ProxyImport.profiles(data, source: kind)) }
                        DispatchQueue.main.async {
                            switch parsed {
                            case .failure(let error): finish(error is ProxyProfileError ? error : ProxyOperationError.unreadable)
                            case .success(let desired): self.synchronize(desired) { error in if let error = error { finish(error) } else { next() } }
                            }
                        }
                    }
                }
            }
        }
        next()
    }
    /// The encrypted desired roster is a recovery journal. Persist additions and
    /// updates before removing retired members. A system save failure is visible;
    /// the next refresh converges the partial OS state to that same owned roster.
    /// Unrelated/manual profiles never match solely by a display name.
    private func synchronize(_ desired: ProxySubscriptionRecord, completion: @escaping (Error?) -> Void) {
        do {
            guard !entries.contains(where: { $0.inOperation }) else { throw ProxyOperationError.stopFirst }
            var records = try subscriptions.load()
            records.removeAll { $0.id == desired.id }; records.append(desired)
            try subscriptions.save(records)
        } catch { completion(error is ProxyOperationError ? error : ProxyOperationError.unreadable); return }
        var pending = desired.members
        func finish(_ error: Error?) { self.changed?(); completion(error) }
        func retireNext() {
            let ids = Set(desired.members.map { $0.id })
            guard let entry = self.entries.first(where: { $0.value.subscriptionID == desired.id && !ids.contains($0.value.profile.id) }) else {
                do {
                    var records = try self.subscriptions.load()
                    if let index = records.firstIndex(where: { $0.id == desired.id }) { records[index].checkedAt = Date() }
                    try self.subscriptions.save(records); finish(nil)
                } catch { finish(ProxyOperationError.unreadable) }; return
            }
            let done: (Error?) -> Void = { error in
                DispatchQueue.main.async {
                    guard error == nil else { finish(ProxyOperationError.system); return }
                    (entry.manager.protocolConfiguration as? NETunnelProviderProtocol)?.destroyConfigurationReference()
                    self.entries.removeAll { $0.value.subscriptionID == desired.id && $0.value.profile.id == entry.value.profile.id }; retireNext()
                }
            }
            if self.simulator { done(nil) } else { entry.manager.removeFromPreferences(completionHandler: done) }
        }
        func saveNext() {
            guard !pending.isEmpty else { retireNext(); return }
            let profile = pending.removeFirst()
            let existing = self.entries.first { $0.value.subscriptionID == desired.id && $0.value.profile.id == profile.id }
            let manager = existing?.manager ?? NETunnelProviderManager()
            let old = manager.protocolConfiguration as? NETunnelProviderProtocol
            var value = ProxyTunnelPayload(profile: profile, routing: existing?.value.routing ?? ProxyRoutingPolicy())
            value.subscriptionID = desired.id
            do { manager.protocolConfiguration = try NETunnelProviderProtocol.proxyProtocol(value, previous: old) }
            catch { finish(ProxyOperationError.unreadable); return }
            manager.localizedDescription = profile.source.title + " · " + profile.name; manager.isEnabled = true
            self.persist(manager) { error in
                if error != nil { manager.protocolConfiguration = old; finish(ProxyOperationError.system); return }
                if let index = self.entries.firstIndex(where: { $0.value.subscriptionID == desired.id && $0.value.profile.id == profile.id }) { self.entries[index].value = value }
                else { self.entries.append(Entry(manager: manager, value: value)) }
                saveNext()
            }
        }
        saveNext()
    }
    private func persist(_ manager: NETunnelProviderManager, completion: @escaping (Error?) -> Void) {
        if simulator { completion(nil); return }
        manager.saveToPreferences { error in
            DispatchQueue.main.async { completion(error == nil ? nil : ProxyOperationError.system) }
        }
    }
    func update(_ entry: Entry, routing: ProxyRoutingPolicy, completion: @escaping (Error?) -> Void) {
        guard !working else { completion(ProxyOperationError.busy); return }
        guard !entry.inOperation else { completion(ProxyOperationError.stopFirst); return }
        var value = entry.value; value.routing = routing
        let old = entry.manager.protocolConfiguration as? NETunnelProviderProtocol
        do {
            entry.manager.protocolConfiguration = try NETunnelProviderProtocol.proxyProtocol(value, previous: old)
        } catch { completion(error); return }
        working = true
        persist(entry.manager) { error in
            self.working = false
            if error != nil { entry.manager.protocolConfiguration = old }
            if error == nil, let index = self.entries.firstIndex(where: { $0.value.profile.id == value.profile.id }) { self.entries[index].value = value }
            self.changed?(); completion(error)
        }
    }
    func remove(_ entry: Entry, completion: @escaping (Error?) -> Void) {
        guard !working else { completion(ProxyOperationError.busy); return }
        guard !entry.inOperation else { completion(ProxyOperationError.stopFirst); return }
        working = true
        let done: (Error?) -> Void = { error in
            DispatchQueue.main.async {
                self.working = false
                if error == nil {
                    (entry.manager.protocolConfiguration as? NETunnelProviderProtocol)?.destroyConfigurationReference()
                    self.entries.removeAll { $0.value.profile.id == entry.value.profile.id }
                }
                self.changed?(); completion(error == nil ? nil : ProxyOperationError.system)
            }
        }
        if simulator { done(nil) } else { entry.manager.removeFromPreferences(completionHandler: done) }
    }
    func toggle(_ entry: Entry) {
        if entry.inOperation || activation != nil {
            activation = nil; switchingTimer?.invalidate(); switchingTimer = nil
            entry.manager.connection.stopVPNTunnel(); working = false; changed?(); return
        }
        guard !working else { reportError?(ProxyOperationError.busy); return }
        if simulator { reportError?(ProxyOperationError.system); return }
        let token = UUID(); activation = token; working = true; changed?()
        do {
            var value = entry.value
            let sources = [entry.value.profile] + entries.filter { $0.value.profile.id != entry.value.profile.id && $0.value.profile.source == entry.value.profile.source }.map { $0.value.profile }
            if VPN013AutomaticMode.enabled(), sources.count > 30 { throw ProxyOperationError.automaticLimit }
            value.automaticCandidates = sources.count <= 30 ? sources : [entry.value.profile]
            value.automaticEnabled = VPN013AutomaticMode.enabled()
            let previous = entry.manager.protocolConfiguration as? NETunnelProviderProtocol
            entry.manager.protocolConfiguration = try NETunnelProviderProtocol.proxyProtocol(value, previous: previous)
            if let index = entries.firstIndex(where: { $0.value.profile.id == entry.value.profile.id }) { entries[index].value = value }
        } catch { activationFailed(token, error: error); return }
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            DispatchQueue.main.async {
                guard self.activation == token else { return }
                guard error == nil else { self.activationFailed(token, error: ProxyOperationError.system); return }
                let others = (managers ?? []).filter { manager in
                    guard let appID = Bundle.main.bundleIdentifier,
                          let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                          proto.providerBundleIdentifier == appID + ".network-extension" else { return false }
                    return proto.privateEnvelope?.id != (entry.manager.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope?.id &&
                        [.connected, .connecting, .disconnecting, .reasserting].contains(manager.connection.status)
                }
                for other in others { other.connection.stopVPNTunnel() }
                let cutoff = DispatchTime.now() + .seconds(20)
                func attempt() {
                    guard self.activation == token else { return }
                    if others.contains(where: { ![.disconnected, .invalid].contains($0.connection.status) }) {
                        if DispatchTime.now() >= cutoff { self.activationFailed(token, error: ProxyOperationError.switching) }
                        return
                    }
                    self.switchingTimer?.invalidate(); self.switchingTimer = nil
                    entry.manager.isEnabled = true
                    self.persist(entry.manager) { error in
                        guard self.activation == token else { return }
                        guard error == nil else { self.activationFailed(token, error: ProxyOperationError.system); return }
                        entry.manager.loadFromPreferences { error in
                            DispatchQueue.main.async {
                                guard self.activation == token else { return }
                                do {
                                    guard error == nil, let proto = entry.manager.protocolConfiguration as? NETunnelProviderProtocol,
                                          let envelope = proto.privateEnvelope,
                                          let session = entry.manager.connection as? NETunnelProviderSession else { throw ProxyOperationError.unreadable }
                                    let key = try PrivateTunnelStore.current.key(for: envelope.id)
                                    try session.startTunnel(options: [PrivateTunnelStore.startKey: key as NSData])
                                    self.activation = nil; self.working = false; self.changed?()
                                } catch { self.activationFailed(token, error: ProxyOperationError.system) }
                            }
                        }
                    }
                }
                self.switchingTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { _ in attempt() }
                attempt()
            }
        }
    }
    private func activationFailed(_ token: UUID, error: Error) {
        guard activation == token else { return }
        activation = nil; working = false; switchingTimer?.invalidate(); switchingTimer = nil
        changed?(); reportError?(error)
    }
    func traffic(_ entry: Entry, completion: @escaping (ProxyTraffic?) -> Void) {
        guard entry.status == .connected, let session = entry.manager.connection as? NETunnelProviderSession else { completion(nil); return }
        let envelope = (entry.manager.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope
        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-proxy-connected-missing") { completion(nil); return }
        #endif
        let token = UUID(); var ended = false; var localStarted = false
        let finish: (Data?) -> Void = { data in
            guard !ended else { return }; ended = true
            self.localReads.removeValue(forKey: token)?.cancel()
            guard let current = self.entries.first(where: { $0.value.profile.id == entry.value.profile.id }), current.status == .connected,
                  let before = envelope, let now = (current.manager.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope,
                  before.id == now.id, before.ciphertext == now.ciphertext else { completion(nil); return }
            completion(data.flatMap { ProxyTraffic.validated($0, payload: current.value) })
        }
        let local = {
            guard !ended, !localStarted else { return }; localStarted = true
            guard let envelope = envelope, let secret = try? PrivateTunnelStore.current.key(for: envelope.id),
                  let credentials = try? VPN013LocalStatisticsCredentials(secret: secret, id: envelope.id, ciphertext: envelope.ciphertext),
                  let read = try? VPN013LocalStatisticsRead(credentials: credentials, operation: 8) else { finish(nil); return }
            self.localReads[token] = read
            read.start { finish(try? $0.get()) }
        }
        do { try session.sendProviderMessage(Data([8])) { data in DispatchQueue.main.async {
            if let data = data, ProxyTraffic.validated(data, payload: entry.value) != nil { finish(data) }
            else { local() }
        } } } catch { local() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35, execute: local)
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { finish(nil) }
    }
    func applyAutomaticPreference(completion: @escaping (Error?) -> Void) {
        guard let index = entries.firstIndex(where: { $0.status == .connected }) else { completion(nil); return }
        guard !working else { completion(ProxyOperationError.busy); return }
        let entry = entries[index]; let enabled = VPN013AutomaticMode.enabled()
        guard let envelope = (entry.manager.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope,
              let secret = try? PrivateTunnelStore.current.key(for: envelope.id),
              let credentials = try? VPN013LocalStatisticsCredentials.automaticControl(secret: secret,
                id: envelope.id, ciphertext: envelope.ciphertext),
              let read = try? VPN013LocalStatisticsRead(credentials: credentials, operation: enabled ? 10 : 9) else {
            completion(ProxyOperationError.system); return
        }
        working = true
        automaticControl = read
        read.start { result in
            self.automaticControl = nil
            let index = self.entries.firstIndex { $0.value.profile.id == entry.value.profile.id && $0.status == .connected &&
                ($0.manager.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope?.ciphertext == envelope.ciphertext }
            let accepted = (try? result.get()) == Data([1]) && index != nil
            if accepted, let index = index { self.entries[index].value.automaticEnabled = enabled }
            self.working = false; self.changed?(); completion(accepted ? nil : ProxyOperationError.system)
        }
    }
}
