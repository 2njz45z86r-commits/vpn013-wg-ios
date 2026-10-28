// SPDX-License-Identifier: MIT
// Real controller/policy with synthetic adapter/provider. Never opens a socket.
import Foundation
import Dispatch
import Network
import NetworkExtension

struct TunnelConfiguration { let name: String? }
enum LogLevel { case info }
func wg_log(_ level: LogLevel, message: String) {}
enum PrimaryState { case unknown }
final class R013PrimaryPermit {
    var rejected = false
    func adoptForPrimary() -> UInt64? { 1 }
    func commit(_ state: PrimaryState) -> Int { rejected = true; return 0 }
}
final class HourlyProbeSupport {
    func start(candidates: [TunnelConfiguration], current: @escaping () -> TunnelConfiguration?,
               apply: @escaping (Int, R013PrimaryPermit, @escaping () -> Void) -> Void) {}
    func stop() {}
}
// Shadow the imported provider with a socket-forbidden synthetic provider.
final class NEPacketTunnelProvider {
    var reasserting = false
    func createTCPConnectionThroughTunnel(to endpoint: NWHostEndpoint, enableTLS: Bool,
            tlsParameters: NWTLSParameters?, delegate: NWTCPConnectionAuthenticationDelegate?) -> NWTCPConnection {
        fatalError("Lifecycle harness must not open a network connection")
    }
}
final class WireGuardAdapter {
    var stops = 0
    var starts = 0
    var stopDone: ((Error?) -> Void)?
    var startDone: ((Error?) -> Void)?
    func stop(primaryTransition: UInt64, completionHandler: @escaping (Error?) -> Void) {
        stops += 1; stopDone = completionHandler
    }
    func start(tunnelConfiguration: TunnelConfiguration, completionHandler: @escaping (Error?) -> Void) {
        starts += 1; startDone = completionHandler
    }
}

@main struct AutoControllerLifecycleTests {
    static var checks = 0
    static func expect(_ value: Bool) { checks += 1; precondition(value, "Lifecycle invariant failed") }
    static func make(_ adapter: WireGuardAdapter, _ provider: NEPacketTunnelProvider) -> AutoTunnelController {
        AutoTunnelController(provider: provider, adapter: adapter,
            candidates: [TunnelConfiguration(name: "Resolved One"), TunnelConfiguration(name: "Resolved Two")], initialIndex: 0,
            configuredCandidates: [TunnelConfiguration(name: "Domain One"), TunnelConfiguration(name: "Domain Two")])
    }
    static func main() {
        DispatchQueue.main.async {
            let adapter = WireGuardAdapter(), provider = NEPacketTunnelProvider()
            let controller = make(adapter, provider)
            expect(controller.activeName == "Domain One" && controller.currentConfiguration?.name == "Domain One")
            controller.scheduleForTesting()
            expect(controller.pendingHealthForTesting)
            controller.applyForTesting(1, permit: R013PrimaryPermit())
            expect(controller.currentConfiguration == nil)
            expect(controller.applyingForTesting && !controller.pendingHealthForTesting && adapter.stops == 1)
            // The hourly winner differs from installedIndex while stop is pending.
            controller.checkForTesting()
            expect(adapter.stops == 1 && adapter.starts == 0)
            var rejectedDone = 0
            let stale = R013PrimaryPermit()
            controller.applyForTesting(0, permit: stale, done: { rejectedDone += 1 })
            expect(stale.rejected && rejectedDone == 1 && adapter.stops == 1)
            adapter.stopDone?(nil)
            DispatchQueue.main.async {
                expect(adapter.starts == 1 && controller.applyingForTesting)
                controller.checkForTesting()
                expect(adapter.stops == 1 && adapter.starts == 1)
                adapter.startDone?(nil)
                DispatchQueue.main.async {
                    expect(controller.installedForTesting == 1 && !controller.applyingForTesting)
                    expect(controller.activeName == "Domain Two" && controller.currentConfiguration?.name == "Domain Two")
                    expect(controller.pendingHealthForTesting && !provider.reasserting)
                    controller.stop()
                    expect(!controller.pendingHealthForTesting)
                    testStopWins()
                }
            }
        }
        dispatchMain()
    }
    static func testStopWins() {
        let adapter = WireGuardAdapter(), provider = NEPacketTunnelProvider()
        let controller = make(adapter, provider)
        var completed = 0
        controller.applyForTesting(1, permit: R013PrimaryPermit(), done: { completed += 1 })
        controller.stop()
        adapter.stopDone?(nil)
        DispatchQueue.main.async {
            expect(adapter.stops == 1 && adapter.starts == 0 && completed == 1)
            expect(!controller.pendingHealthForTesting && !provider.reasserting)
            let rejected = R013PrimaryPermit()
            controller.applyForTesting(0, permit: rejected, done: { completed += 1 })
            expect(rejected.rejected && completed == 2 && adapter.stops == 1)
            print("Auto controller lifecycle checks passed: \(checks); synthetic adapter/provider, no network")
            exit(0)
        }
    }
}
