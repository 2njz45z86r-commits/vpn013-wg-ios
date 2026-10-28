// SPDX-License-Identifier: MIT
import Foundation
import NetworkExtension

/// All state and scheduling live in the extension's main queue. Candidate probes
/// use a separate serial queue: no TUN ownership, no host app timer, no fake ping.
final class ProxyPacketAdapter {
    private weak var provider: NEPacketTunnelProvider?
    private let primary: ProxySinglePacketAdapter
    private let resolver = DispatchQueue(label: "VPN013.auto.resolve")
    private let probes = DispatchQueue(label: "VPN013.auto.probes", qos: .utility)
    private var epoch = UUID()
    private var probeGeneration = UUID()
    private var timer: DispatchWorkItem?
    private var deadline: DispatchWorkItem?
    private var pending: ((Error?) -> Void)?
    private var startupPing: EndpointPingCoordinator?
    private var payload: ProxyTunnelPayload?
    private var resolved: [String?] = []
    private var additional: [[String: String]] = []
    private var selected = 0
    private var connectionRevision = UUID()
    private var trafficOverflow = false
    private var enabled = false
    private var applying = false
    private var failures = 0
    private var latency: Double?
    private var lastSwitch: TimeInterval = 0
    private var nextComparison: TimeInterval = 0
    private var carriedRX: Int64 = 0
    private var carriedTX: Int64 = 0
    init(provider: NEPacketTunnelProvider) { self.provider = provider; primary = ProxySinglePacketAdapter(provider: provider) }

    func start(_ value: ProxyTunnelPayload, completion: @escaping (Error?) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        do { try value.validate() } catch { completion(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid); return }
        let token = UUID(); epoch = token; payload = value; pending = completion; enabled = value.automaticEnabled ?? false
        let timeout = DispatchWorkItem { [weak self] in
            guard let self = self, self.epoch == token, self.pending != nil else { return }
            let done = self.pending; self.pending = nil
            self.stop { }; done?(PacketTunnelProviderError.dnsResolutionFailure)
        }
        deadline = timeout; DispatchQueue.main.asyncAfter(deadline: .now() + 20, execute: timeout)
        resolver.async {
            var secondary: [[String: String]] = []
            let addresses = value.candidates.map { profile -> String? in
                var hosts: [String: String] = [:]
                for endpoint in profile.additionalEndpoints {
                    if let host = ProxySinglePacketAdapter.resolve(endpoint.host, port: endpoint.port) { hosts[endpoint.host] = host }
                }
                secondary.append(hosts)
                guard hosts.count == profile.additionalEndpoints.count else { return nil }
                return ProxySinglePacketAdapter.resolve(profile.host, port: profile.port)
            }
            DispatchQueue.main.async {
                guard self.epoch == token else { return }; self.resolved = addresses; self.additional = secondary
                guard self.enabled else { self.install(value.candidates.firstIndex(where: { $0.id == value.profile.id }) ?? 0, token: token) { self.finish($0) }; return }
                let ping = EndpointPingCoordinator(maxConcurrent: 6, probeTimeout: 1.5, batchTimeout: 8)
                self.startupPing = ping; var measured: [String: EndpointPingResult] = [:]
                ping.start(hosts: value.candidates.map { $0.host }, update: { host, result in measured[host] = result }, completion: {
                    guard self.epoch == token else { return }; self.startupPing = nil
                    let order = EndpointPingRanking.order(hosts: value.candidates.map { Optional($0.host) }, measurements: measured)
                    guard let first = order.first(where: { addresses[$0] != nil }) else { self.finish(PacketTunnelProviderError.dnsResolutionFailure); return }
                    self.install(first, token: token) { self.finish($0) }
                })
            }
        }
    }
    private func finish(_ error: Error?) {
        deadline?.cancel(); deadline = nil; let callback = pending; pending = nil; callback?(error)
    }
    private func install(_ index: Int, token: UUID, completion: @escaping (Error?) -> Void) {
        guard epoch == token, let value = payload, resolved.indices.contains(index), let host = resolved[index] else { completion(PacketTunnelProviderError.dnsResolutionFailure); return }
        applying = true; connectionRevision = UUID()
        primary.start(value.selecting(index), resolvedHost: host, additionalHosts: additional[index], excludedHosts: resolved.compactMap { $0 } + additional.flatMap { $0.values }) { error in
            guard self.epoch == token else { return }; self.applying = false
            if error == nil {
                self.selected = index; self.failures = 0; self.latency = nil
                self.lastSwitch = ProcessInfo.processInfo.systemUptime; self.nextComparison = self.lastSwitch + AutomaticSelection.checkInterval
                self.schedule(after: 8)
            }
            completion(error)
        }
    }
    func setAutomaticEnabled(_ value: Bool) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard enabled != value else { return }
        enabled = value; probeGeneration = UUID(); timer?.cancel(); timer = nil; _ = R013ProxyProbeReset()
        if value { schedule(after: 1) }
    }
    private func schedule(after seconds: TimeInterval) {
        timer?.cancel(); timer = nil; guard enabled, !applying else { return }
        let token = epoch
        let item = DispatchWorkItem { [weak self] in guard let self = self, self.epoch == token else { return }; self.timer = nil; self.check(token) }
        timer = item; DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: item)
    }
    private func check(_ token: UUID) {
        guard enabled, !applying, epoch == token, let value = payload else { return }
        let current = selected; let comparisonDue = ProcessInfo.processInfo.systemUptime >= nextComparison
        let compare = comparisonDue || failures >= 1
        let order = [current] + (compare ? value.candidates.indices.filter { $0 != current } : [])
        let configurations: [(Int, String)] = order.compactMap { index in
            guard let host = resolved[index], let data = try? value.selecting(index).probeConfiguration(resolvedHost: host, additionalHosts: additional[index]), let text = String(data: data, encoding: .utf8) else { return nil }; return (index, text)
        }
        let probeEpoch = R013ProxyProbeReset()
        let generation = UUID(); probeGeneration = generation
        probes.async {
            var samples: [AutomaticLatencySample] = []
            for (index, text) in configurations {
                let ms = text.withCString { R013ProxyProbe($0, probeEpoch) }
                if ms.isFinite && ms >= 0 { samples.append(AutomaticLatencySample(index: index, milliseconds: ms, metric: .tunneledHTTP)) }
            }
            DispatchQueue.main.async {
                guard self.epoch == token, self.probeGeneration == generation, self.enabled, !self.applying else { return }
                let currentSample = samples.first { $0.index == current }
                self.latency = currentSample?.milliseconds; self.failures = currentSample == nil ? self.failures + 1 : 0
                let now = ProcessInfo.processInfo.systemUptime
                if comparisonDue { repeat { self.nextComparison += AutomaticSelection.checkInterval } while self.nextComparison <= now }
                if let replacement = AutomaticSelection.replacement(current: currentSample, candidates: samples, count: value.candidates.count, currentIndex: current, consecutiveFailures: self.failures, secondsSinceSwitch: now - self.lastSwitch) { self.switchTo(replacement, token: token) }
                else { self.schedule(after: 15) }
            }
        }
    }
    private func switchTo(_ index: Int, token: UUID) {
        guard epoch == token, enabled, !applying else { return }
        let previous = selected; applying = true; provider?.reasserting = true
        primary.statistics { data in
            DispatchQueue.main.async {
                guard self.epoch == token else { return }
                if let data = data, let value = try? JSONDecoder().decode(ProxyTraffic.self, from: data), value.rx >= 0, value.tx >= 0 {
                    let rx = self.carriedRX.addingReportingOverflow(value.rx), tx = self.carriedTX.addingReportingOverflow(value.tx)
                    if rx.overflow || tx.overflow { self.trafficOverflow = true }
                    else { self.carriedRX = rx.partialValue; self.carriedTX = tx.partialValue }
                }
                self.primary.stop {
                    guard self.epoch == token else { return }
                    self.install(index, token: token) { error in
                        guard self.epoch == token else { return }
                        if error == nil { self.provider?.reasserting = false; return }
                        self.install(previous, token: token) { recovery in
                            guard self.epoch == token else { return }; self.provider?.reasserting = false
                            if recovery != nil { self.provider?.cancelTunnelWithError(PacketTunnelProviderError.couldNotStartBackend) }
                        }
                    }
                }
            }
        }
    }
    func stop(completion: @escaping () -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        epoch = UUID(); enabled = false; timer?.cancel(); timer = nil; startupPing?.cancel(); startupPing = nil
        _ = R013ProxyProbeReset(); finish(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled))
        primary.stop(completion: completion)
    }
    func statistics(completion: @escaping (Data?) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !applying, !trafficOverflow else { completion(nil); return }
        let token = epoch, revision = connectionRevision, index = selected
        primary.statistics { data in
            DispatchQueue.main.async {
                guard self.epoch == token, self.connectionRevision == revision, self.selected == index, !self.applying, !self.trafficOverflow,
                      let data = data, var value = try? JSONDecoder().decode(ProxyTraffic.self, from: data), value.running, value.rx >= 0, value.tx >= 0,
                      let profile = self.payload?.candidates[index] else { completion(nil); return }
                let rx = value.rx.addingReportingOverflow(self.carriedRX), tx = value.tx.addingReportingOverflow(self.carriedTX)
                guard !rx.overflow, !tx.overflow else { completion(nil); return }
                value.rx = rx.partialValue; value.tx = tx.partialValue
                value.selectedName = profile.name; value.selectedEndpoint = profile.endpoint; value.automatic = self.enabled; value.httpsMilliseconds = self.latency
                completion(try? JSONEncoder().encode(value))
            }
        }
    }
    #if R013_PROXY_AUTO_TESTING
    var selectedForTesting: Int { selected }
    var checkingForTesting: Bool { timer != nil }
    func switchForTesting(_ index: Int) { switchTo(index, token: epoch) }
    #endif
}
