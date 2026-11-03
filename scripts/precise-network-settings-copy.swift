// Synthetic platform-object test. Does not start a VPN or apply settings.
import Foundation
import NetworkExtension

func check(_ value: @autoclosure () -> Bool, _ reason: String) {
    if !value() { fatalError(reason) }
}

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

let original = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "192.0.2.2")
original.mtu = 1280
let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.255"])
let route4 = NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "0.0.0.0")
route4.gatewayAddress = "10.0.0.2"
ipv4.includedRoutes = [route4]
ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: "192.0.2.2", subnetMask: "255.255.255.255")]
original.ipv4Settings = ipv4
let ipv6 = NEIPv6Settings(addresses: ["fd13::2"], networkPrefixLengths: [128])
let route6 = NEIPv6Route(destinationAddress: "::", networkPrefixLength: 0)
route6.gatewayAddress = "fd13::2"
ipv6.includedRoutes = [route6]
ipv6.excludedRoutes = [NEIPv6Route(destinationAddress: "2001:db8::2", networkPrefixLength: 128)]
original.ipv6Settings = ipv6
let dns = NEDNSSettings(servers: ["192.0.2.53", "2001:db8::53"])
dns.searchDomains = ["example.invalid"]
dns.matchDomains = ["", "example.invalid"]
dns.matchDomainsNoSearch = true
original.dnsSettings = dns

guard let snapshot = isolatedCopy(original) else { fatalError("copy failed") }
check(snapshot !== original, "copy was not independent")
check(snapshot.tunnelRemoteAddress == "192.0.2.2" && snapshot.mtu?.intValue == 1280, "remote or MTU changed")
check(snapshot.ipv4Settings?.addresses == ["10.0.0.2"] && snapshot.ipv4Settings?.includedRoutes?.first?.gatewayAddress == "10.0.0.2", "IPv4 configuration changed")
check(snapshot.ipv4Settings?.excludedRoutes?.first?.destinationAddress == "192.0.2.2", "IPv4 exclusion changed")
check(snapshot.ipv6Settings?.addresses == ["fd13::2"] && snapshot.ipv6Settings?.includedRoutes?.first?.gatewayAddress == "fd13::2", "IPv6 configuration changed")
check(snapshot.ipv6Settings?.excludedRoutes?.first?.destinationAddress == "2001:db8::2", "IPv6 exclusion changed")
check(snapshot.dnsSettings?.servers == ["192.0.2.53", "2001:db8::53"], "DNS servers changed")
check(snapshot.dnsSettings?.searchDomains == ["example.invalid"] && snapshot.dnsSettings?.matchDomains == ["", "example.invalid"] && snapshot.dnsSettings?.matchDomainsNoSearch == true, "DNS matching changed")
original.ipv4Settings?.includedRoutes?.first?.gatewayAddress = "10.0.0.3"
original.ipv6Settings?.includedRoutes?.first?.gatewayAddress = "fd13::3"
original.ipv4Settings?.excludedRoutes?.first?.gatewayAddress = "10.0.0.3"
original.ipv6Settings?.excludedRoutes?.first?.gatewayAddress = "fd13::3"
original.dnsSettings?.searchDomains = ["changed.invalid"]
original.dnsSettings?.matchDomains = ["changed.invalid"]
original.mtu = 1400
check(snapshot.mtu?.intValue == 1280, "MTU aliases original")
check(snapshot.ipv4Settings?.includedRoutes?.first?.gatewayAddress == "10.0.0.2", "IPv4 gateway aliases original")
check(snapshot.ipv6Settings?.includedRoutes?.first?.gatewayAddress == "fd13::2", "IPv6 gateway aliases original")
check(snapshot.dnsSettings?.searchDomains == ["example.invalid"], "DNS aliases original")
check(snapshot.dnsSettings?.matchDomains == ["", "example.invalid"], "DNS match domains alias original")
check(snapshot.ipv4Settings?.excludedRoutes?.first?.gatewayAddress == nil && snapshot.ipv6Settings?.excludedRoutes?.first?.gatewayAddress == nil, "excluded route aliases original")
original.proxySettings = NEProxySettings()
check(isolatedCopy(original) == nil, "unsupported proxy settings accepted")
print("NetworkExtension settings snapshot copied and isolated; synthetic values only")
