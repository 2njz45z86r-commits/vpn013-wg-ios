// SPDX-License-Identifier: MIT
import Foundation
import NetworkExtension

enum ProxyOperationError: LocalizedError {
    case busy, stopFirst, unreadable, switching, system
    var errorDescription: String? {
        switch self {
        case .busy: return "Дождитесь завершения текущего действия."
        case .stopFirst: return "Сначала выключите это подключение."
        case .unreadable: return "Не удалось прочитать защищённый профиль. Исходные профили сохранены."
        case .switching: return "Предыдущее подключение не отключилось. Проверьте раздел VPN в настройках iPhone."
        case .system: return "iOS не завершила действие с VPN. Повторите попытку и разрешите добавление VPN в системном окне."
        }
    }
}

final class ProxyProfilesManager {
    struct Entry {
        let manager: NETunnelProviderManager
        var value: ProxyTunnelPayload
        var status: NEVPNStatus { manager.connection.status }
        var inOperation: Bool { [.connected, .connecting, .reasserting, .disconnecting].contains(status) }
    }
    static let shared = ProxyProfilesManager()
    private(set) var entries: [Entry] = []
    var changed: (() -> Void)?
    var reportError: ((Error) -> Void)?
    private(set) var working = false
    private var activation: UUID?
    private var switchingTimer: Timer?
    private var statusObserver: NSObjectProtocol?
    private var configurationObserver: NSObjectProtocol?
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
            let value = ProxyTunnelPayload(profile: profile)
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
                let cutoff = Date().addingTimeInterval(20)
                func attempt() {
                    guard self.activation == token else { return }
                    if others.contains(where: { ![.disconnected, .invalid].contains($0.connection.status) }) {
                        if Date() >= cutoff { self.activationFailed(token, error: ProxyOperationError.switching) }
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
        do {
            try session.sendProviderMessage(Data([0x53, 0x50, 1])) { data in
                let value = data.flatMap { $0.count < 1024 ? try? JSONDecoder().decode(ProxyTraffic.self, from: $0) : nil }
                DispatchQueue.main.async { completion(value) }
            }
        } catch { completion(nil) }
    }
}
