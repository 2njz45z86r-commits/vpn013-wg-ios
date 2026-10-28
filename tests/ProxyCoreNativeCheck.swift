// Synthetic configuration only. Never starts a VPN or contacts a provider.
import Foundation
@main struct ProxyCoreNativeCheck {
    static func main() throws {
        let uri = "vless://00000000-0000-4000-8000-000000000001@server.example.invalid:443?type=ws&security=tls&sni=server.example.invalid&path=%2Fvpn#Synthetic"
        let profile = try ProxyProfile.fromURI(uri, source: .happ)
        let payload = ProxyTunnelPayload(profile: profile)
        let configuration = String(data: try payload.configuration(resolvedHost: "192.0.2.10"), encoding: .utf8)!
        precondition(configuration.withCString { R013ProxyValidate($0) } == 0, "Generated TUN/VLESS config must parse in the actual pinned core")
        let probe = String(data: try payload.probeConfiguration(resolvedHost: "192.0.2.10"), encoding: .utf8)!
        precondition(probe.withCString { R013ProxyValidate($0) } == 0, "No-listener probe must parse in the pinned core")
        let stale = R013ProxyProbeReset(); _ = R013ProxyProbeReset()
        precondition(probe.withCString { R013ProxyProbe($0, stale) } < 0, "Cancelled generation cannot start a probe")
        precondition(configuration.withCString { R013ProxyProbe($0, R013ProxyProbeReset()) } < 0, "Probe rejects a TUN/listener config before any network action")
        precondition("{}".withCString { R013ProxyStart($0, -1) } == -1, "Reject absent TUN without side effects")
        R013ProxyStop(); R013ProxyStop()
        guard let raw = R013ProxyStatistics() else { preconditionFailure("No stats buffer") }
        defer { free(raw) }
        let stats = try JSONDecoder().decode(ProxyTraffic.self, from: Data(bytes: raw, count: strlen(raw)))
        precondition(!stats.running && stats.rx == 0 && stats.tx == 0)
        print("Actual pinned proxy core: config parsing, stopped statistics and idempotent stop passed; no VPN traffic claimed")
    }
}
