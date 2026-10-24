// SPDX-License-Identifier: MIT
import Foundation
import NetworkExtension

struct AutoTunnelProfile: Codable {
    struct Candidate: Codable { let name: String; let config: String }
    static let referenceKey = "VPN013AutoGroupReference"
    let version: Int
    let candidates: [Candidate]
    init(configurations: [TunnelConfiguration]) throws {
        guard (1...30).contains(configurations.count) else { throw AutoTunnelError.invalidGroup }
        candidates = configurations.map { Candidate(name: $0.name ?? "", config: $0.asWgQuickConfig()) }
        version = 1
        _ = try validatedConfigurations()
    }
    func validatedConfigurations() throws -> [TunnelConfiguration] {
        guard version == 1, (1...30).contains(candidates.count),
              Set(candidates.map { $0.name }).count == candidates.count else { throw AutoTunnelError.invalidGroup }
        return try candidates.map { item in
            guard !item.name.isEmpty, item.name.count <= 128, item.config.utf8.count <= 65536 else { throw AutoTunnelError.invalidGroup }
            let config = try TunnelConfiguration(fromWgQuickConfig: item.config, called: item.name)
            guard config.peers.count == 1, config.peers[0].endpoint != nil,
                  config.peers[0].allowedIPs.contains(where: { $0.stringRepresentation == "0.0.0.0/0" }) else { throw AutoTunnelError.incompatible(item.name) }
            return config
        }
    }
    static func serverCountLabel(_ count: Int) -> String {
        let last = count % 10, lastTwo = count % 100
        let word = (11...14).contains(lastTwo) ? "серверов" : last == 1 ? "сервер" : (2...4).contains(last) ? "сервера" : "серверов"
        return "\(count) \(word)"
    }
    static func load(from proto: NETunnelProviderProtocol) throws -> AutoTunnelProfile? {
        #if os(iOS)
        if proto.privateEnvelope != nil {
            let value = try proto.privatePayload()?.automatic
            if let value = value { _ = try value.validatedConfigurations() }
            return value
        }
        #endif
        #if targetEnvironment(simulator)
        if let raw = proto.providerConfiguration?["VPN013SimulatorAutoJSON"] as? String {
            return try JSONDecoder().decode(Self.self, from: Data(raw.utf8))
        }
        #endif
        guard let ref = proto.providerConfiguration?[referenceKey] as? Data else { return nil }
        guard let raw = Keychain.openReference(called: ref), raw.utf8.count < 1048576 else { throw AutoTunnelError.invalidGroup }
        let value = try JSONDecoder().decode(Self.self, from: Data(raw.utf8))
        _ = try value.validatedConfigurations()
        return value
    }
}
enum AutoTunnelError: LocalizedError {
    case invalidGroup, keychain, active
    case incompatible(String)
    var errorDescription: String? {
        switch self {
        case .invalidGroup: return "Сначала добавьте хотя бы одну конфигурацию AmneziaWG или WireGuard. Для Авто нужны разные имена серверов и доступные конфигурации."
        case .incompatible(let name): return "«\(name)» не подходит для Авто: нужен один сервер с адресом подключения и полным IPv4-туннелем (AllowedIPs = 0.0.0.0/0). Исходная конфигурация не изменена."
        case .keychain: return "Не удалось сохранить защищённую конфигурацию. Проверьте доступное место и повторите импорт. Для VPN-расширения нужна подпись с правом Network Extension."
        case .active: return "Сначала выключите VPN, затем создайте автоматическое подключение."
        }
    }
}
extension NETunnelProviderProtocol {
    var isVPN013Automatic: Bool {
        #if os(iOS)
        if privateEnvelope != nil { return (try? privatePayload()?.automatic) != nil }
        #endif
        #if targetEnvironment(simulator)
        if providerConfiguration?["VPN013SimulatorAutoJSON"] != nil { return true }
        #endif
        return providerConfiguration?[AutoTunnelProfile.referenceKey] is Data
    }
}

struct PrivateTunnelPayload: Codable {
    let version: Int
    let configuration: String
    let automatic: AutoTunnelProfile?
}

extension NETunnelProviderProtocol {
    var privateEnvelope: PrivateTunnelStore.Envelope? {
        guard let id = providerConfiguration?[PrivateTunnelStore.idKey] as? String,
              let data = providerConfiguration?[PrivateTunnelStore.dataKey] as? Data else { return nil }
        return PrivateTunnelStore.Envelope(id: id, ciphertext: data)
    }
    func privatePayload() throws -> PrivateTunnelPayload? {
        guard let envelope = privateEnvelope else { return nil }
        let value = try JSONDecoder().decode(PrivateTunnelPayload.self, from: PrivateTunnelStore.current.open(envelope))
        guard value.version == 1 else { throw PrivateStoreError.invalidEnvelope }
        return value
    }
    func setPrivateAutomatic(_ automatic: AutoTunnelProfile) throws {
        guard let envelope = privateEnvelope, let old = try privatePayload() else { throw PrivateStoreError.invalidEnvelope }
        let payload = PrivateTunnelPayload(version: 1, configuration: old.configuration, automatic: automatic)
        let next = try PrivateTunnelStore.current.seal(JSONEncoder().encode(payload), reusing: envelope.id)
        providerConfiguration = [PrivateTunnelStore.idKey: next.id, PrivateTunnelStore.dataKey: next.ciphertext]
    }
    func receivePrivateStartKey(_ options: [String: NSObject]?) throws {
        guard let envelope = privateEnvelope else { return }
        if let key = options?[PrivateTunnelStore.startKey] as? Data {
            try PrivateTunnelStore.current.receive(key, for: envelope)
        }
        _ = try privatePayload() // Without options, use the extension's own persisted key.
    }
}
