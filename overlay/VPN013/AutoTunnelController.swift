// SPDX-License-Identifier: MIT
import Foundation
import Network
import NetworkExtension

/// All mutable state lives on the main queue; callbacks carry an epoch to ignore stale work.
final class AutoTunnelController {
    private weak var provider: NEPacketTunnelProvider?
    private let adapter: WireGuardAdapter
    private let candidates: [TunnelConfiguration]
    private var policy: AutoFailoverPolicy
    private var timer: DispatchWorkItem?
    private var pathMonitor: NWPathMonitor?
    private var probe: TunnelHTTPSProbe?
    private var epoch = 0
    private var networkAvailable = true
    private var installedIndex: Int
    private var applying = false
    private(set) var phase = "Проверка соединения"
    var activeName: String { candidates[installedIndex].name ?? "Сервер" }
    var currentConfiguration: TunnelConfiguration? { applying ? nil : candidates[installedIndex] }
    var connectionRevision: Int { epoch }
    init(provider: NEPacketTunnelProvider, adapter: WireGuardAdapter, candidates: [TunnelConfiguration], initialIndex: Int) {
        self.provider = provider; self.adapter = adapter; self.candidates = candidates
        policy = AutoFailoverPolicy(count: candidates.count, initialIndex: initialIndex)
        installedIndex = initialIndex
    }
    func start() {
        dispatchPrecondition(condition: .onQueue(.main))
        let monitor = NWPathMonitor(); pathMonitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self, self.policy.running else { return }
            let available = path.status == .satisfied
            if available != self.networkAvailable {
                self.networkAvailable = available
                if self.applying { return } // Backend restart can briefly change the default path.
                self.epoch += 1; self.probe?.cancel(); self.probe = nil
                self.phase = available ? "Проверка после смены сети" : "Ожидание сети"
                self.schedule(after: available ? 10 : 15)
            }
        }
        monitor.start(queue: .main)
        schedule(after: 8)
    }
    func stop() {
        dispatchPrecondition(condition: .onQueue(.main))
        epoch += 1; policy.stop(); timer?.cancel(); timer = nil
        applying=false;provider?.reasserting=false
        probe?.cancel(); probe = nil; pathMonitor?.cancel(); pathMonitor = nil
    }
    private func schedule(after seconds: TimeInterval) {
        timer?.cancel()
        guard policy.running else { return }
        let item = DispatchWorkItem { [weak self] in self?.check() }
        timer = item; DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: item)
    }
    private func check() {
        guard policy.running, let provider = provider else { return }
        guard networkAvailable else { phase = "Ожидание сети"; schedule(after: 15); return }
        if installedIndex != policy.current { applyCandidate(policy.current); return }
        let stamp = epoch
        probe = TunnelHTTPSProbe(provider: provider)
        probe?.run { [weak self] healthy, latency in
            guard let self = self, self.policy.running, self.epoch == stamp else { return }
            self.probe = nil
            switch self.policy.record(healthy: healthy, networkAvailable: self.networkAvailable, latencyMilliseconds: latency) {
            case .stay:
                self.phase = latency.map { "Трафик проверен · \(Int($0)) мс" } ?? "Трафик проверен"
                self.schedule(after: 15)
            case .wait(let seconds):
                self.phase = seconds == 60 ? "Все серверы проверены. Повтор через минуту" : "Повторная проверка"
                self.schedule(after: seconds)
            case .switchTo(let index):
                self.applyCandidate(index)
            case .stopped: break
            }
        }
    }
    private func applyCandidate(_ index:Int) {
        phase = "Переключение на " + (candidates[index].name ?? "сервер")
        applying=true
        epoch += 1;let change=epoch
        wg_log(.info,message:"Auto failover: candidate index=\(index)")
        provider?.reasserting=true
        // Recreate the backend inside the SAME Packet Tunnel. An incremental UAPI
        // update could retain optional AWG junk/header parameters from the old node.
        // The system VPN is not stopped and the original profiles are not edited.
        adapter.stop { [weak self] _ in
            DispatchQueue.main.async {
                guard let self=self,self.policy.running,self.epoch==change else { return }
                self.adapter.start(tunnelConfiguration:self.candidates[index]) { [weak self] error in
                    DispatchQueue.main.async {
                        guard let self=self,self.policy.running,self.epoch==change else { return }
                        self.applying=false
                        self.provider?.reasserting=false
                        if error == nil {
                            self.installedIndex=index;self.phase="Проверка нового сервера";self.schedule(after:8)
                        } else {
                            self.phase="Не удалось подключиться. Повторная попытка"
                            switch self.policy.record(healthy:false,networkAvailable:true) {
                            case .switchTo(let next):self.applyCandidate(next)
                            case .wait(let seconds):self.schedule(after:seconds)
                            default:self.schedule(after:60)
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Explicit through-tunnel API; a normal provider URLSession could bypass the VPN.
/// Two independent HTTPS origins, system TLS validation, no credentials or identifiers sent.
private final class TunnelHTTPSProbe {
    private weak var provider: NEPacketTunnelProvider?
    private var connection: NWTCPConnection?
    private var observation: NSKeyValueObservation?
    private var deadline: DispatchWorkItem?
    private var completion: ((Bool, Double?) -> Void)?
    private var endpointIndex = 0
    private var requestSent = false
    private var response = Data()
    private var requestStartedAt: TimeInterval?
    private var slowLatency: Double?
    private let endpoints = [("www.apple.com", "/library/test/success.html"), ("one.one.one.one", "/cdn-cgi/trace")]
    init(provider: NEPacketTunnelProvider) { self.provider = provider }
    func run(completion: @escaping (Bool, Double?) -> Void) { self.completion = completion; attempt() }
    func cancel() { completion = nil; cleanup() }
    private func cleanup() { deadline?.cancel(); deadline = nil; observation = nil; connection?.cancel(); connection = nil }
    private func finish(_ healthy: Bool, latency: Double? = nil) { let done = completion; completion = nil; cleanup(); done?(healthy, latency) }
    private func failed(_ item: NWTCPConnection) {
        guard completion != nil, connection === item else { return }
        cleanup(); endpointIndex += 1
        if endpointIndex < endpoints.count { attempt() }
        else if let latency = slowLatency { finish(true, latency: latency) }
        else { finish(false) }
    }
    private func attempt() {
        guard let provider = provider, completion != nil else { finish(false); return }
        requestSent = false; response = Data(); requestStartedAt = nil
        let target = endpoints[endpointIndex]
        let item = provider.createTCPConnectionThroughTunnel(to: NWHostEndpoint(hostname: target.0, port: "443"), enableTLS: true, tlsParameters: nil, delegate: nil)
        connection = item
        let timeout = DispatchWorkItem { [weak self, weak item] in if let item = item { self?.failed(item) } }
        deadline = timeout; DispatchQueue.main.asyncAfter(deadline: .now() + 4, execute: timeout)
        observation = item.observe(\.state, options: [.initial, .new]) { [weak self] item, _ in
            DispatchQueue.main.async {
                guard let self = self, self.connection === item, self.completion != nil else { return }
                if item.state == .connected && !self.requestSent {
                    self.requestSent = true
                    self.requestStartedAt = ProcessInfo.processInfo.systemUptime
                    let request = "GET \(target.1) HTTP/1.1\r\nHost: \(target.0)\r\nConnection: close\r\nCache-Control: no-cache\r\n\r\n"
                    item.write(Data(request.utf8)) { [weak self] error in
                        DispatchQueue.main.async { if error != nil { self?.failed(item) } else { self?.read(item) } }
                    }
                } else if item.state == .disconnected || item.state == .cancelled { self.failed(item) }
            }
        }
    }
    private func read(_ item: NWTCPConnection) {
        guard completion != nil, connection === item else { return }
        item.readMinimumLength(1, maximumLength: 1024) { [weak self] data, error in
            DispatchQueue.main.async {
                guard let self = self, self.connection === item, self.completion != nil else { return }
                guard error == nil, let data = data, !data.isEmpty else { self.failed(item); return }
                self.response.append(data)
                let text = String(decoding: self.response, as: UTF8.self)
                if text.contains("\r\n\r\n") {
                    let line = text.components(separatedBy: "\r\n").first ?? ""
                    if line.hasPrefix("HTTP/1.1 200 ") || line.hasPrefix("HTTP/1.0 200 ") {
                        guard let started = self.requestStartedAt else { self.failed(item); return }
                        let latency = (ProcessInfo.processInfo.systemUptime - started) * 1000
                        if latency > AutoFailoverPolicy.maximumLatencyMilliseconds {
                            // Confirm a slow origin against the other independent target before rotating.
                            self.slowLatency = min(self.slowLatency ?? latency, latency)
                            self.failed(item)
                        } else { self.finish(true, latency: latency) }
                    } else { self.failed(item) }
                } else if self.response.count >= 8192 { self.failed(item) } else { self.read(item) }
            }
        }
    }
}
