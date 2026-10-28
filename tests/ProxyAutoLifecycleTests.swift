// Actual extension coordinator with socket-forbidden synthetic drivers.
import Foundation
import Dispatch
import NetworkExtension

enum PacketTunnelProviderError: Error { case savedProtocolConfigurationIsInvalid, dnsResolutionFailure, couldNotStartBackend }
final class NEPacketTunnelProvider {
    var reasserting = false
    var cancelled = false
    func cancelTunnelWithError(_ error: Error?) { cancelled = true }
}
final class ProxySinglePacketAdapter {
    static var latest: ProxySinglePacketAdapter!
    var starts = 0; var stops = 0
    var startDone: ((Error?) -> Void)?
    var stopDone: (() -> Void)?
    var exclusions: [String] = []
    init(provider: NEPacketTunnelProvider) { Self.latest = self }
    static func resolve(_ host: String, port: UInt16) -> String? { host == "one.example.invalid" ? "192.0.2.1" : "192.0.2.2" }
    func start(_ value: ProxyTunnelPayload, resolvedHost: String?, excludedHosts: [String], completion: @escaping (Error?) -> Void) {
        starts += 1; exclusions = excludedHosts; startDone = completion
    }
    func stop(completion: @escaping () -> Void) { stops += 1; stopDone = completion }
    func statistics(completion: @escaping (Data?) -> Void) { completion(Data("{\"running\":true,\"rx\":12,\"tx\":7}".utf8)) }
}
enum EndpointPingResult { case milliseconds(Double) }
final class EndpointPingCoordinator {
    init(maxConcurrent: Int, probeTimeout: TimeInterval, batchTimeout: TimeInterval) {}
    func start(hosts: [String], update: @escaping (String, EndpointPingResult) -> Void, completion: @escaping () -> Void) { completion() }
    func cancel() {}
}
enum EndpointPingRanking {
    static func order(hosts: [String?], measurements: [String: EndpointPingResult]) -> [Int] { Array(hosts.indices) }
}
func R013ProxyProbeReset() -> UInt64 { 1 }
func R013ProxyProbe(_ configuration: UnsafePointer<CChar>?, _ epoch: UInt64) -> Double { fatalError("Lifecycle test must never open a probe") }

@main struct ProxyAutoLifecycleTests {
    static var checks = 0
    static func expect(_ condition: Bool) { checks += 1; precondition(condition, "Proxy automatic lifecycle invariant") }
    static func main() throws {
        let uri = "vless://00000000-0000-4000-8000-000000000001@one.example.invalid:443?security=tls&sni=one.example.invalid#One"
        let first = try ProxyProfile.fromURI(uri, source: .happ)
        var second = first; second.id = UUID(); second.name = "Two"; second.host = "two.example.invalid"
        var payload = ProxyTunnelPayload(profile: first); payload.automaticCandidates = [first, second]; payload.automaticEnabled = false
        DispatchQueue.main.async {
            let provider = NEPacketTunnelProvider(); let coordinator = ProxyPacketAdapter(provider: provider)
            var completed = 0
            coordinator.start(payload) { error in expect(error == nil); completed += 1 }
            func awaitStart() {
                let driver = ProxySinglePacketAdapter.latest!
                guard driver.starts == 1 else { DispatchQueue.main.asyncAfter(deadline: .now() + 0.01, execute: awaitStart); return }
                driver.startDone?(nil)
                expect(completed == 1 && !coordinator.checkingForTesting)
                expect(Set(driver.exclusions) == Set(["192.0.2.1", "192.0.2.2"]))
                coordinator.setAutomaticEnabled(true); expect(coordinator.checkingForTesting && driver.stops == 0)
                coordinator.switchForTesting(1)
                DispatchQueue.main.async {
                    expect(driver.stops == 1 && provider.reasserting)
                    driver.stopDone?()
                    expect(driver.starts == 2)
                    coordinator.setAutomaticEnabled(false)
                    driver.startDone?(nil)
                    expect(coordinator.selectedForTesting == 1 && !coordinator.checkingForTesting && !provider.reasserting)
                    expect(driver.stops == 1 && driver.starts == 2 && !provider.cancelled)
                    coordinator.statistics { data in
                        let value = try! JSONDecoder().decode(ProxyTraffic.self, from: data!)
                        expect(value.selectedName == "Two" && value.selectedEndpoint == "two.example.invalid:443")
                        expect(value.rx == 24 && value.tx == 14 && value.automatic == false)
                        coordinator.stop { expect(!coordinator.checkingForTesting); print("Proxy automatic lifecycle: \(checks) checks passed; synthetic drivers, no VPN traffic"); exit(0) }
                        driver.stopDone?()
                    }
                }
            }
            awaitStart()
        }
        dispatchMain()
    }
}
