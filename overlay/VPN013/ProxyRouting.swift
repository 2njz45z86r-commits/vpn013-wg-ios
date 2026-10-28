// SPDX-License-Identifier: MIT
import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

struct ProxyRoutingPolicy: Codable, Equatable {
    enum Mode: String, Codable, CaseIterable {
        case all, bypass, only
        var title: String {
            switch self {
            case .all: return "Весь трафик через VPN"
            case .bypass: return "Выбранное — напрямую"
            case .only: return "Только выбранное — через VPN"
            }
        }
    }
    var mode: Mode = .all
    var domains: [String] = []
    var networks: [String] = []

    static func domain(_ raw: String) throws -> String {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard value.utf8.count <= 253, parts.count >= 2,
              parts.allSatisfy({ part in (1...63).contains(part.utf8.count) && part.first != "-" && part.last != "-" && part.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") } })
        else { throw ProxyProfileError.invalid }
        return value
    }
    static func validNetwork(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]), String(prefix) == parts[1] else { return false }
        var v4 = in_addr(); var v6 = in6_addr()
        return ((0...32).contains(prefix) && inet_pton(AF_INET, String(parts[0]), &v4) == 1) ||
            ((0...128).contains(prefix) && inet_pton(AF_INET6, String(parts[0]), &v6) == 1)
    }
    func validate() throws {
        guard domains.count <= 200, networks.count <= 200,
              try domains.allSatisfy({ try Self.domain($0) == $0 }),
              networks.allSatisfy(Self.validNetwork),
              mode == .all || !domains.isEmpty || !networks.isEmpty else { throw ProxyProfileError.invalid }
    }
}

struct ProxyTunnelPayload: Codable, Equatable {
    var profile: ProxyProfile
    var routing: ProxyRoutingPolicy = ProxyRoutingPolicy()
    func validate() throws { try profile.validate(); try routing.validate() }

    /// Construct our own bounded TUN configuration. Imported top-level JSON never
    /// becomes executable core configuration or a filesystem/log/API instruction.
    func configuration(resolvedHost: String) throws -> Data {
        try validate()
        var v4 = in_addr(); var v6 = in6_addr()
        guard inet_pton(AF_INET, resolvedHost, &v4) == 1 || inet_pton(AF_INET6, resolvedHost, &v6) == 1 else { throw ProxyProfileError.invalid }
        var rules: [[String: Any]] = [["type": "field", "port": "53", "outboundTag": "vpn013-proxy"]]
        let selectedTag = routing.mode == .bypass ? "vpn013-direct" : "vpn013-proxy"
        if routing.mode != .all {
            if !routing.domains.isEmpty { rules.append(["type": "field", "domain": routing.domains.map { "domain:" + $0 }, "outboundTag": selectedTag]) }
            if !routing.networks.isEmpty { rules.append(["type": "field", "ip": routing.networks, "outboundTag": selectedTag]) }
        }
        rules.append(["type": "field", "network": "tcp,udp", "outboundTag": routing.mode == .only ? "vpn013-direct" : "vpn013-proxy"])
        let object: [String: Any] = [
            "log": ["loglevel": "none"], "stats": [:],
            "policy": ["system": ["statsInboundUplink": true, "statsInboundDownlink": true], "levels": ["0": ["bufferSize": 64, "connIdle": 120]]],
            "inbounds": [["tag": "vpn013-tun", "protocol": "tun", "settings": ["name": "utun", "MTU": 1280, "userLevel": 0],
                          "sniffing": ["enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true]]],
            "outbounds": [try profile.outbound(resolvedHost: resolvedHost), ["tag": "vpn013-direct", "protocol": "freedom", "settings": [:]]],
            "routing": ["domainStrategy": "AsIs", "rules": rules]
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}

struct ProxyTraffic: Codable {
    let running: Bool
    let rx: Int64
    let tx: Int64
}
