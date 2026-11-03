import Foundation
import NetworkExtension

// Diagnostic implementation: NEPacketTunnelNetworkSettings.copy() alone
// shares nested route objects. Rebuild the nested route objects independently.
func isolatedCopy(_ original: NEPacketTunnelNetworkSettings) -> NEPacketTunnelNetworkSettings? {
    guard original.proxySettings == nil,
          let result = original.copy() as? NEPacketTunnelNetworkSettings else { return nil }
    if let original4 = original.ipv4Settings {
        guard let value = original4.copy() as? NEIPv4Settings else { return nil }
        func copyRoutes(_ routes: [NEIPv4Route]?) -> [NEIPv4Route]? {
            routes?.map { route in
                let copy = NEIPv4Route(destinationAddress: route.destinationAddress, subnetMask: route.destinationSubnetMask)
                copy.gatewayAddress = route.gatewayAddress
                return copy
            }
        }
        value.includedRoutes = copyRoutes(original4.includedRoutes)
        value.excludedRoutes = copyRoutes(original4.excludedRoutes)
        result.ipv4Settings = value
    }
    if let original6 = original.ipv6Settings {
        guard let value = original6.copy() as? NEIPv6Settings else { return nil }
        func copyRoutes(_ routes: [NEIPv6Route]?) -> [NEIPv6Route]? {
            routes?.map { route in
                let copy = NEIPv6Route(destinationAddress: route.destinationAddress, networkPrefixLength: route.destinationNetworkPrefixLength)
                copy.gatewayAddress = route.gatewayAddress
                return copy
            }
        }
        value.includedRoutes = copyRoutes(original6.includedRoutes)
        value.excludedRoutes = copyRoutes(original6.excludedRoutes)
        result.ipv6Settings = value
    }
    if let originalDNS = original.dnsSettings {
        guard let value = originalDNS.copy() as? NEDNSSettings else { return nil }
        result.dnsSettings = value
    }
    return result
}
