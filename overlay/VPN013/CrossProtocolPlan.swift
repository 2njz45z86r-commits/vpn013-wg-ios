// SPDX-License-Identifier: MIT
import Foundation
import NetworkExtension
import CryptoKit

enum CrossProtocolError: LocalizedError {
    case invalid, tooMany, exhausted, busy, stopFirst
    var errorDescription: String? {
        switch self {
        case .invalid: return "Не удалось проверить резервные конфигурации. Исходные профили сохранены."
        case .tooMany: return "Для общего Авто доступно до 120 совместимых подключений. Уменьшите список или выключите Авто."
        case .exhausted: return "Ни одна загруженная конфигурация не подтвердила VPN-трафик. Проверьте интернет, срок доступа и обновите ключ в кабинете провайдера."
        case .busy: return "Дождитесь завершения изменения конфигураций."
        case .stopFirst: return "Сначала выключите общее Авто, затем измените или удалите конфигурацию."
        }
    }
}

struct CrossProtocolRuntime: Codable {
    let schema: Int
    let kind: VPN013ConnectionKind
    let name: String
    let endpoint: String?
    let phase: String
    let received: UInt64?
    let sent: UInt64?
    let handshake: Date?
    let automaticEnabled: Bool
    let trafficVerified: Bool
    static func read(_ data: Data) -> Self? {
        guard data.count <= 32_768, let value = try? JSONDecoder().decode(Self.self, from: data), value.schema == 1,
              !value.name.isEmpty, value.name.utf8.count <= 256, value.phase.utf8.count <= 256,
              (value.endpoint?.utf8.count ?? 0) <= 512,
              value.handshake.map({ $0.timeIntervalSince1970.isFinite && $0.timeIntervalSince1970 >= 0 && $0 <= Date().addingTimeInterval(60) }) ?? true else { return nil }
        return value
    }
}

/// Stored only inside the existing authenticated encrypted tunnel envelope.
/// Each group retains its own full routing/configuration. Never follow a
/// provider URL, issue a key or modify the imported source during recovery.
struct CrossProtocolPlan: Codable {
    static private(set) var changingSources = false
    final class MutationPermit {
        private var released = false
        func release() {
            dispatchPrecondition(condition: .onQueue(.main))
            guard !released else { return }; released = true; CrossProtocolPlan.changingSources = false
            NotificationCenter.default.post(name: Notification.Name("VPN013AutomaticAvailabilityChanged"), object: nil)
        }
    }
    /// Before editing/deleting sources, remove inactive recovery snapshots from
    /// every owned manager. Otherwise an OS-direct start could use a deleted
    /// profile copied into an old plan. The caller holds the permit until its
    /// actual source edit completes; app starts are blocked for that duration.
    static func prepareMutation(appID: String? = Bundle.main.bundleIdentifier,
                                completion: @escaping (Result<MutationPermit, Error>) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !changingSources else { completion(.failure(CrossProtocolError.busy)); return }
        guard let appID = appID else { completion(.failure(CrossProtocolError.invalid)); return }
        changingSources = true; let permit = MutationPermit()
        NotificationCenter.default.post(name: Notification.Name("VPN013AutomaticAvailabilityChanged"), object: nil)
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            DispatchQueue.main.async {
                let finish: (Error?) -> Void = { error in
                    if let error = error { permit.release(); completion(.failure(error)) }
                    else { completion(.success(permit)) }
                }
                guard error == nil else { finish(CrossProtocolError.invalid); return }
                var pending = (managers ?? []).filter { item in
                    guard let proto = item.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                    return proto.providerBundleIdentifier == appID + ".network-extension" && (try? proto.privatePayload()?.crossProtocol) != nil
                }
                guard !pending.contains(where: { [.connected, .connecting, .reasserting, .disconnecting].contains($0.connection.status) }) else { finish(CrossProtocolError.stopFirst); return }
                func next() {
                    guard !pending.isEmpty else { finish(nil); return }
                    let manager = pending.removeFirst()
                    guard [.disconnected, .invalid].contains(manager.connection.status),
                          let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                          let envelope = proto.privateEnvelope, var payload = try? proto.privatePayload() else { finish(CrossProtocolError.stopFirst); return }
                    let previous = proto.copy() as? NETunnelProviderProtocol
                    do { payload.crossProtocol = nil; try store(payload, in: proto, id: envelope.id) }
                    catch { finish(CrossProtocolError.invalid); return }
                    manager.saveToPreferences { error in
                        DispatchQueue.main.async {
                            if error != nil { manager.protocolConfiguration = previous; finish(CrossProtocolError.invalid) }
                            else { next() }
                        }
                    }
                }
                next()
            }
        }
    }
    struct Group: Codable {
        var kind: VPN013ConnectionKind
        var name: String
        var awg: AutoTunnelProfile?
        var proxy: ProxyTunnelPayload?
        var count: Int { awg?.candidates.count ?? proxy?.candidates.count ?? 0 }
        func validate() throws {
            guard !name.isEmpty, name.utf8.count <= 256, (1...30).contains(count) else { throw CrossProtocolError.invalid }
            if kind == .amneziawg {
                guard proxy == nil, let awg = awg else { throw CrossProtocolError.invalid }
                _ = try awg.validatedConfigurations()
            } else {
                guard awg == nil, let proxy = proxy, proxy.profile.source == kind else { throw CrossProtocolError.invalid }
                try proxy.validate()
            }
        }
    }
    let version: Int
    let groups: [Group]
    static func matchingProxyCandidates(primary: ProxyTunnelPayload, others: [ProxyTunnelPayload]) -> [ProxyProfile] {
        [primary.profile] + others.filter {
            $0.profile.id != primary.profile.id && $0.profile.source == primary.profile.source && $0.routing == primary.routing
        }.map { $0.profile }
    }
    func validate() throws {
        guard version == 1, (1...120).contains(groups.count), groups.reduce(0, { $0 + $1.count }) <= 120 else { throw CrossProtocolError.tooMany }
        for group in groups { try group.validate() }
    }

    /// All inputs are already local, owned VPN013 managers. The primary group
    /// is tried first, then its section, then other imported sections.
    static func attach(to primary: NETunnelProviderProtocol, managers: [NETunnelProviderManager]) throws {
        guard let envelope = primary.privateEnvelope, var payload = try primary.privatePayload() else { throw CrossProtocolError.invalid }
        guard VPN013AutomaticMode.enabled() else { payload.crossProtocol = nil; try store(payload, in: primary, id: envelope.id); return }
        func group(_ value: PrivateTunnelPayload, name: String, includeCandidates: Bool = false) throws -> Group {
            if let data = value.proxy {
                var proxy = try JSONDecoder().decode(ProxyTunnelPayload.self, from: data)
                if !includeCandidates { proxy.automaticCandidates = nil }
                proxy.automaticEnabled = true
                let result = Group(kind: proxy.profile.source, name: proxy.profile.name, proxy: proxy)
                try result.validate(); return result
            }
            let awg: AutoTunnelProfile
            if let existing = (includeCandidates ? value.builtinAutomatic : nil) ?? value.automatic { awg = existing }
            else { awg = try AutoTunnelProfile(configurations: [TunnelConfiguration(fromWgQuickConfig: value.configuration, called: name)]) }
            let result = Group(kind: .amneziawg, name: name, awg: awg)
            try result.validate(); return result
        }
        let first = try group(payload, name: primary.serverAddress ?? "AmneziaWG", includeCandidates: true)
        var remaining: [Group] = []
        for manager in managers {
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  proto.providerBundleIdentifier == primary.providerBundleIdentifier,
                  proto.privateEnvelope?.id != envelope.id,
                  let value = try? proto.privatePayload(),
                  let candidate = try? group(value, name: manager.localizedDescription ?? "AmneziaWG") else { continue }
            remaining.append(candidate)
        }
        let order = [first.kind] + [VPN013ConnectionKind.amneziawg, .happ, .incy, .blacktemple].filter { $0 != first.kind }
        remaining = remaining.enumerated().sorted {
            let left = order.firstIndex(of: $0.element.kind) ?? order.count
            let right = order.firstIndex(of: $1.element.kind) ?? order.count
            return left == right ? $0.offset < $1.offset : left < right
        }.map { $0.element }
        // Grouping can include an existing Auto profile plus its individual
        // members. Do not repeatedly test the same imported connection.
        var awgSeen = Set<String>(), proxySeen = Set<UUID>(), groups: [Group] = []
        for var candidate in [first] + remaining {
            if let original = candidate.awg {
                let configs = try original.validatedConfigurations().filter { awgSeen.insert($0.asWgQuickConfig()).inserted }
                guard !configs.isEmpty else { continue }
                candidate.awg = try AutoTunnelProfile(configurations: configs)
            } else if var proxy = candidate.proxy {
                let profiles = proxy.candidates.filter { proxySeen.insert($0.id).inserted }
                guard !profiles.isEmpty else { continue }
                proxy.profile = profiles[0]; proxy.automaticCandidates = profiles; candidate.proxy = proxy
            }
            groups.append(candidate)
        }
        let plan = CrossProtocolPlan(version: 1, groups: groups); try plan.validate()
        payload.crossProtocol = groups.count > 1 ? plan : nil
        try store(payload, in: primary, id: envelope.id)
    }
    private static func store(_ payload: PrivateTunnelPayload, in proto: NETunnelProviderProtocol, id: String) throws {
        let sealed = try PrivateTunnelStore.current.seal(JSONEncoder().encode(payload), reusing: id)
        var values = proto.providerConfiguration ?? [:]
        values[PrivateTunnelStore.idKey] = sealed.id; values[PrivateTunnelStore.dataKey] = sealed.ciphertext
        proto.providerConfiguration = values
    }
}
