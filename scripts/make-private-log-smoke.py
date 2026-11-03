from pathlib import Path
source=Path('overlay/Sources/WireGuardKit/WireGuardAdapter.swift').read_text(encoding='utf-8')
start=source.index('    /// Report resolution outcomes without retaining endpoint addresses or error text.')
end=source.index('    /// Helper method used by network path monitor.',start)
methods=source[start:end]
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
        print("Synthetic endpoint and DNS values excluded from adapter diagnostic messages")
    }
}
Check().run()
'''
Path('build').mkdir(exist_ok=True)
Path('build/private-log-smoke.swift').write_text(prefix+methods+suffix,encoding='utf-8',newline='\n')
