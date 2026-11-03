from pathlib import Path
source=Path('overlay/Sources/WireGuardKit/WireGuardAdapter.swift').read_text(encoding='utf-8')
manager=Path('overlay/Sources/WireGuardApp/Tunnel/TunnelsManager.swift').read_text(encoding='utf-8')
migration=Path('overlay/Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift').read_text(encoding='utf-8')
for expected in ['staticMessage: "startActivation: Entering"','staticMessage: "startDeactivation: Tunnel"']:
    assert expected in manager
for expected in ['staticMessage: "Migrating tunnel configuration"','staticMessage: "Migrating iOS keychain reference"']:
    assert expected in migration
for token in [r"\(name)", r"\(self.name)", r"\(tunnel.name)", r"\(tunnelInOperation.name)", r"\(tunnelManager.localizedDescription"]:
    assert token not in manager and token not in migration
for token in [r"\(error)", r"\(error!)", r"\(lastError!)", r"domain=\(domain)"]:
    assert token not in manager
assert manager.count('as NSError).code)') >= 13
start=source.index('    /// Report resolution outcomes without retaining endpoint addresses or error text.')
end=source.index('    /// Helper method used by network path monitor.',start)
methods=source[start:end]
backend_start=source.index('    // Backend messages can include peer identifiers')
backend_end=source.index('    /// Setup WireGuard log handler.',backend_start)
backend=source[backend_start:backend_end]
assert 'WireGuardAdapter.safeBackendLog(swiftString, level: tunnelLogLevel)' in source
assert r"\(self.state)" not in source and r"\(error.localizedDescription)" not in source
assert source.count(r"\(self.stateLogLabel)") == 2
assert methods.count('private func log') == 3
prefix='''import Foundation
struct Endpoint { let host: String }
struct FakeError: Error { let detail: String }
typealias EndpointResolutionResult = Result<(Endpoint, Endpoint), FakeError>
struct FakeDNS { let servers: [String] }
struct FakeIPv4 { let includedRoutes: [String]?; let excludedRoutes: [String]? }
struct FakeIPv6 { let includedRoutes: [String]?; let excludedRoutes: [String]? }
struct NEPacketTunnelNetworkSettings {
    let tunnelRemoteAddress: String
    let ipv4Settings: FakeIPv4?
    let ipv6Settings: FakeIPv6?
    let mtu: NSNumber?
    let dnsSettings: FakeDNS?
}
enum WireGuardLogLevel { case verbose, error }
enum Level { case verbose, error }
final class Check {
    var messages: [String] = []
    func logHandler(_ level: Level, _ message: String) { messages.append(message) }
'''
suffix='''
    func run() {
        let source = Endpoint(host: "private-endpoint.example.invalid")
        let resolved = Endpoint(host: "198.51.100.29")
        logEndpointResolutionResults([.success((source, source)), .success((source, resolved)), .failure(FakeError(detail: "private-dns-error")), nil])
        logNetworkSettingsSummary(NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "private-remote.example.invalid", ipv4Settings: FakeIPv4(includedRoutes: ["r"], excludedRoutes: []), ipv6Settings: FakeIPv6(includedRoutes: [], excludedRoutes: ["r"]), mtu: 1280, dnsSettings: FakeDNS(servers: ["192.0.2.53"])), context: "start")
        logResolvedEndpoints([source, resolved, nil], context: "start")
        precondition(messages.count == 5)
        for token in ["private-endpoint", "198.51.100.29", "private-dns-error", "private-remote", "192.0.2.53"] {
            precondition(!messages.contains(where: { $0.contains(token) }), "Sensitive value in diagnostic output")
        }
        precondition(messages.contains(where: { $0.contains("translated=true") }))
        precondition(messages.contains(where: { $0.contains("dnsCount=1") }))
        precondition(messages.contains(where: { $0.contains("count=2/3") }))
        let raw = "Peer private-endpoint.example.invalid 198.51.100.29 Sending handshake initiation"
        let safe = Self.safeBackendLog(raw, level: .verbose)
        precondition(safe == "VPN handshake initiation sent" && !safe.contains("private-endpoint") && !safe.contains("198.51.100.29"))
        precondition(Self.safeBackendLog("private-dns-error", level: .error) == "VPN backend error; details withheld")
        precondition(Self.safeBackendLog("private-unknown", level: .verbose) == "VPN backend diagnostic event")
        print("Synthetic endpoint, DNS and backend values excluded from adapter diagnostic messages")
    }
}
Check().run()
'''
Path('build').mkdir(exist_ok=True)
Path('build/private-log-smoke.swift').write_text(prefix+backend+methods+suffix,encoding='utf-8',newline='\n')
