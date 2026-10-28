// SPDX-License-Identifier: MIT
import Foundation
import NetworkExtension

extension NETunnelProviderProtocol {
    static let proxyKindKey = "VPN013ProxyKindV1"
    var isVPN013Proxy: Bool { providerConfiguration?[Self.proxyKindKey] is String }
    func proxyPayload() throws -> ProxyTunnelPayload {
        guard isVPN013Proxy, let bytes = try privatePayload()?.proxy else { throw PrivateStoreError.invalidEnvelope }
        let value = try JSONDecoder().decode(ProxyTunnelPayload.self, from: bytes)
        try value.validate()
        guard value.profile.source.rawValue == providerConfiguration?[Self.proxyKindKey] as? String else { throw PrivateStoreError.invalidEnvelope }
        return value
    }
    static func proxyProtocol(_ value: ProxyTunnelPayload, previous: NETunnelProviderProtocol? = nil) throws -> NETunnelProviderProtocol {
        try value.validate()
        guard let appID = Bundle.main.bundleIdentifier else { throw PrivateStoreError.invalidEnvelope }
        var payload = PrivateTunnelPayload(version: 1, configuration: "", automatic: nil)
        payload.proxy = try JSONEncoder().encode(value)
        let envelope = try PrivateTunnelStore.current.seal(JSONEncoder().encode(payload), reusing: previous?.privateEnvelope?.id)
        let result = NETunnelProviderProtocol()
        result.providerBundleIdentifier = appID + ".network-extension"
        result.serverAddress = value.profile.endpoint
        result.providerConfiguration = [PrivateTunnelStore.idKey: envelope.id, PrivateTunnelStore.dataKey: envelope.ciphertext,
                                        proxyKindKey: value.profile.source.rawValue]
        result.disconnectOnSleep = false
        return result
    }
}
