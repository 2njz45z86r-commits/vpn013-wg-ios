// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import Network
import os

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var crossProtocol: CrossProtocolCoordinator?
    private var crossPlan: CrossProtocolPlan?
    private var crossResolver: CrossProtocolResolution?
    private var crossPath: NWPathMonitor?
    private var crossDeadline: DispatchWorkItem?
    private var crossEngine: VPN013ConnectionKind?
    private var crossStopping = false
    private var crossStopCompletions: [(Error?) -> Void] = []
    private var proxyAdapter: ProxyPacketAdapter?
    private var localStatistics: VPN013LocalStatisticsServer?
    private var localAutomaticControl: VPN013LocalStatisticsServer?
    private var automaticSession: VPN013AutomaticSessionState?
    // Read and changed only on the main queue. A stopped startup cannot open a listener later.
    private var localStatisticsEpoch = UUID()
    private var automatic: AutoTunnelController?
    private var automaticStartCompletion: ((Error?) -> Void)?
    private var automaticEpoch = 0
    private var automaticStartupPing: EndpointPingCoordinator?
    private lazy var hourlySupport = HourlyProbeSupport(provider: self)

    private lazy var adapter: WireGuardAdapter = {
        let value = WireGuardAdapter(with: self) { logLevel, message in
            wg_log(logLevel.osLogLevel, message: message)
        }
        let support = hourlySupport
        value.primaryChangeObserved = { [weak support] in support?.willChange() }
        value.primaryChangeCompleted = { [weak support] in support?.didChange() }
        return value
    }()


    private func logAppGroupInfo() {
        #if os(iOS)
        wg_log(.info, staticMessage: "Storage: authenticated encryption and private process container; no shared App Group")
        #else
        let appGroupId = FileManager.appGroupId ?? "nil"
        let logPath = FileManager.logFileURL?.path ?? "nil"
        let errorPath = FileManager.networkExtensionLastErrorFileURL?.path ?? "nil"
        wg_log(.info, message: "App group id: \(appGroupId)")
        wg_log(.info, message: "Log file path: \(logPath)")
        wg_log(.info, message: "Last error file path: \(errorPath)")
        #endif
    }

    private func logTunnelConfigurationSummary(_ tunnelConfiguration: TunnelConfiguration) {
        let interface = tunnelConfiguration.interface
        let mtuString = interface.mtu.map { String($0) } ?? "auto"
        let peerSummaries = tunnelConfiguration.peers.enumerated().map { index, peer in
            let keepalive = peer.persistentKeepAlive.map { String($0) } ?? "0"
            return "peer[\(index)]: allowedIPs=\(peer.allowedIPs.count) excludeIPs=\(peer.excludeIPs.count) keepalive=\(keepalive)"
        }
        let peersSummary = peerSummaries.isEmpty ? "none" : peerSummaries.joined(separator: "; ")
        wg_log(.info, message: "Config summary: addressCount=\(interface.addresses.count) dnsCount=\(interface.dns.count) mtu=\(mtuString) peers=\(peersSummary)")
    }

    private func logRuntimeConfigSummary(_ settings: String) {
        var peerCount = 0
        var handshakeValues = [String]()
        var rxValues = [String]()
        var txValues = [String]()
        let handshakePrefix = "last_handshake_time_sec="
        let rxPrefix = "rx_bytes="
        let txPrefix = "tx_bytes="
        for line in settings.split(separator: "\n") {
            if line.hasPrefix("public_key=") {
                peerCount += 1
            } else if line.hasPrefix(handshakePrefix) {
                handshakeValues.append(String(line.dropFirst(handshakePrefix.count)))
            } else if line.hasPrefix(rxPrefix) {
                rxValues.append(String(line.dropFirst(rxPrefix.count)))
            } else if line.hasPrefix(txPrefix) {
                txValues.append(String(line.dropFirst(txPrefix.count)))
            }
        }
        wg_log(.debug, message: "Runtime config summary: peers=\(peerCount) last_handshake_time_sec=\(handshakeValues) rx_bytes=\(rxValues) tx_bytes=\(txValues)")
    }


    private func makeAutomaticSession(_ proto: NETunnelProviderProtocol, initial: Bool) throws -> VPN013AutomaticSessionState {
        guard let envelope = proto.privateEnvelope else { throw PrivateStoreError.invalidEnvelope }
        let store = PrivateTunnelStore.current
        return try VPN013AutomaticSessionState(directory: store.directory,
            secret: store.key(for: envelope.id), id: envelope.id,
            ciphertext: envelope.ciphertext, initialEnabled: initial)
    }

    private func startLocalChannels(_ proto: NETunnelProviderProtocol, epoch: UUID) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard localStatisticsEpoch == epoch, let envelope = proto.privateEnvelope,
              let secret = try? PrivateTunnelStore.current.key(for: envelope.id),
              let credentials = try? VPN013LocalStatisticsCredentials(secret: secret,
                id: envelope.id, ciphertext: envelope.ciphertext) else { return }
        let server = VPN013LocalStatisticsServer(credentials: credentials) { [weak self] operation, reply in
            DispatchQueue.main.async {
                guard let self = self, self.localStatisticsEpoch == epoch else { reply(nil); return }
                self.handleAppMessage(Data([operation]), completionHandler: reply)
            }
        }
        server.onRejected = { wg_log(.error, staticMessage: "Local statistics authentication rejected") }
        localStatistics = server; server.start()
        guard automaticSession != nil,
              let control = try? VPN013LocalStatisticsCredentials.automaticControl(secret: secret,
                id: envelope.id, ciphertext: envelope.ciphertext) else { return }
        let commands = VPN013LocalStatisticsServer(controlCredentials: control) { [weak self] operation, stamp, digest, reply in
            DispatchQueue.main.async {
                guard let self = self, self.localStatisticsEpoch == epoch,
                      self.proxyAdapter != nil || self.automatic != nil || self.crossProtocol != nil,
                      let state = self.automaticSession else { reply(nil); return }
                do {
                    let enabled = try state.accept(operation: operation, stamp: stamp, digest: digest)
                    if let cross = self.crossProtocol { cross.setEnabled(enabled) }
                    else { self.proxyAdapter?.setAutomaticEnabled(enabled); self.automatic?.setEnabled(enabled) }
                    wg_log(.info, staticMessage: "Authenticated automatic mode applied")
                    reply(Data([1]))
                } catch { wg_log(.error, staticMessage: "Automatic mode command rejected"); reply(nil) }
            }
        }
        commands.onRejected = { wg_log(.error, staticMessage: "Local automatic control authentication rejected") }
        localAutomaticControl = commands; commands.start()
    }

    private func stopLocalChannels(completion: @escaping () -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        let servers = [localStatistics, localAutomaticControl].compactMap { $0 }
        localStatistics = nil; localAutomaticControl = nil
        let group = DispatchGroup()
        for server in servers { group.enter(); server.stop { group.leave() } }
        group.notify(queue: .main, execute: completion)
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let statisticsEpoch = UUID()
        let rememberStatisticsStartup = { self.localStatisticsEpoch = statisticsEpoch }
        if Thread.isMainThread { rememberStatisticsStartup() }
        else { DispatchQueue.main.sync(execute: rememberStatisticsStartup) }
        let activationAttemptId = options?["activationAttemptId"] as? String
        let errorNotifier = ErrorNotifier(activationAttemptId: activationAttemptId)

        Logger.configureGlobal(tagged: "NET", withFilePath: FileManager.logFileURL?.path)

        #if os(iOS)
        do {
            try (self.protocolConfiguration as? NETunnelProviderProtocol)?.receivePrivateStartKey(options)
        } catch { completionHandler(error); return }
        #endif

        #if os(iOS)
        if let proto = self.protocolConfiguration as? NETunnelProviderProtocol,
           let plan = try? proto.privatePayload()?.crossProtocol {
            do {
                try plan.validate()
                let state = try makeAutomaticSession(proto, initial: true)
                DispatchQueue.main.async {
                    guard self.localStatisticsEpoch == statisticsEpoch else { completionHandler(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)); return }
                    self.automaticSession = state
                    self.startCrossProtocol(plan, enabled: state.enabled, epoch: statisticsEpoch) { error in
                        guard error == nil else { self.automaticSession = nil; completionHandler(error); return }
                        guard self.localStatisticsEpoch == statisticsEpoch else { completionHandler(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)); return }
                        self.startLocalChannels(proto, epoch: statisticsEpoch); completionHandler(nil)
                    }
                }
            } catch { completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid) }
            return
        }
        if let proto = self.protocolConfiguration as? NETunnelProviderProtocol, proto.isVPN013Proxy {
            do {
                var value = try proto.proxyPayload()
                let state = try makeAutomaticSession(proto, initial: value.automaticEnabled ?? false)
                value.automaticEnabled = state.enabled
                DispatchQueue.main.async {
                    guard self.localStatisticsEpoch == statisticsEpoch else {
                        completionHandler(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)); return
                    }
                    let adapter = ProxyPacketAdapter(provider: self)
                    self.automaticSession = state
                    self.proxyAdapter = adapter
                    adapter.start(value) { error in
                        guard error == nil else { self.automaticSession = nil; completionHandler(error); return }
                        guard self.localStatisticsEpoch == statisticsEpoch else {
                            completionHandler(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)); return
                        }
                        self.startLocalChannels(proto, epoch: statisticsEpoch)
                        completionHandler(nil)
                    }
                }
            } catch { completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid) }
            return
        }
        #endif

        let optionKeys = options?.keys.sorted().joined(separator: ", ") ?? "none"
        wg_log(.info, message: "Start options keys: \(optionKeys)")
        logAppGroupInfo()

        wg_log(.info, message: "Starting tunnel from the " + (activationAttemptId == nil ? "OS directly, rather than the app" : "app"))

        guard let tunnelProviderProtocol = self.protocolConfiguration as? NETunnelProviderProtocol,
              let tunnelConfiguration = tunnelProviderProtocol.asTunnelConfiguration() else {
            errorNotifier.notify(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }

        // Own the listener only after the tunnel starts successfully. Failed
        // starts must not leave an authenticated socket or profile key alive.
        let finishStart: (Error?) -> Void = { error in
            guard error == nil else { completionHandler(error); return }
            DispatchQueue.main.async {
                guard self.localStatisticsEpoch == statisticsEpoch else {
                    completionHandler(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)); return
                }
                self.startLocalChannels(tunnelProviderProtocol, epoch: statisticsEpoch)
                completionHandler(nil)
            }
        }

        do {
            if let profile = try AutoTunnelProfile.load(from:tunnelProviderProtocol) {
                let candidates = try profile.validatedConfigurations()
                let initial = (try? tunnelProviderProtocol.privatePayload()?.automaticEnabled) ?? true
                let state = try tunnelProviderProtocol.privateEnvelope.map { _ in
                    try makeAutomaticSession(tunnelProviderProtocol, initial: initial)
                }
                DispatchQueue.main.async {
                    guard self.localStatisticsEpoch == statisticsEpoch else {
                        completionHandler(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)); return
                    }
                    self.automaticSession = state
                    self.startAutomatic(candidates:candidates, enabled: state?.enabled ?? initial, completion:finishStart)
                }
                return
            }
        } catch { finishStart(error); return }

        logTunnelConfigurationSummary(tunnelConfiguration)

        // Start the tunnel
        adapter.start(tunnelConfiguration: tunnelConfiguration) { adapterError in
            guard let adapterError = adapterError else {
                let interfaceName = self.adapter.interfaceName ?? "unknown"

                wg_log(.info, message: "Tunnel interface is \(interfaceName)")

                finishStart(nil)
                return
            }

            switch adapterError {
            case .cannotLocateTunnelFileDescriptor:
                wg_log(.error, staticMessage: "Starting tunnel failed: could not determine file descriptor")
                errorNotifier.notify(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                finishStart(PacketTunnelProviderError.couldNotDetermineFileDescriptor)

            case .dnsResolution(let dnsErrors):
                wg_log(.error, message: "DNS resolution failed; endpointCount=\(dnsErrors.count)")
                errorNotifier.notify(PacketTunnelProviderError.dnsResolutionFailure)
                finishStart(PacketTunnelProviderError.dnsResolutionFailure)

            case .setNetworkSettings:
                wg_log(.error, staticMessage: "Starting tunnel failed: could not apply network settings")
                errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
                finishStart(PacketTunnelProviderError.couldNotSetNetworkSettings)

            case .startWireGuardBackend(let errorCode):
                wg_log(.error, message: "Starting tunnel failed with wgTurnOn returning \(errorCode)")
                errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                finishStart(PacketTunnelProviderError.couldNotStartBackend)

            case .invalidState:
                // Must never happen
                fatalError()
            }
        }
    }

    override func
    stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if crossProtocol != nil || crossResolver != nil {
            DispatchQueue.main.async {
                self.localStatisticsEpoch = UUID(); self.crossResolver?.cancel(); self.crossResolver = nil
                self.crossDeadline?.cancel(); self.crossDeadline = nil; self.crossPath?.cancel(); self.crossPath = nil
                let cross = self.crossProtocol; self.crossProtocol = nil; self.automaticSession = nil
                self.stopLocalChannels {
                    if let cross = cross { cross.stop(completion: completionHandler) }
                    else { self.stopCrossEngine { _ in completionHandler() } }
                }
            }
            return
        }
        if (protocolConfiguration as? NETunnelProviderProtocol)?.isVPN013Proxy == true {
            DispatchQueue.main.async {
                self.localStatisticsEpoch = UUID()
                let proxy = self.proxyAdapter
                self.proxyAdapter = nil
                self.automaticSession = nil
                self.stopLocalChannels {
                    if let proxy = proxy { proxy.stop(completion: completionHandler) } else { completionHandler() }
                }
            }
            return
        }
        wg_log(.info, message: "Stopping tunnel, reason=\(reason.rawValue) (\(reason))")

        let cleanup = {
            self.localStatisticsEpoch = UUID()
            self.automaticSession = nil
            self.automaticEpoch += 1;self.automatic?.stop();self.automatic = nil
            self.automaticStartupPing?.cancel();self.automaticStartupPing = nil
            let pending=self.automaticStartCompletion;self.automaticStartCompletion=nil
            pending?(NSError(domain:NSURLErrorDomain,code:NSURLErrorCancelled))
        }
        if Thread.isMainThread { cleanup() } else { DispatchQueue.main.sync(execute:cleanup) }
        let stopAdapter = {
        self.adapter.stop { error in
            ErrorNotifier.removeLastErrorFile()

            if error != nil {
                wg_log(.error, staticMessage: "Failed to stop WireGuard adapter")
            }
            completionHandler()

            #if os(macOS)
            // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
            // Remove it when they finally fix this upstream and the fix has been rolled out to
            // sufficient quantities of users.
            exit(0)
            #endif
        }
        }
        DispatchQueue.main.async { self.stopLocalChannels(completion: stopAdapter) }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        if crossProtocol != nil {
            if messageData == Data([11]) {
                DispatchQueue.main.async { self.readCrossRuntime(completion: completionHandler) }; return
            }
            let running: Bool
            if let phase = crossProtocol?.phase, case .running = phase { running = true } else { running = false }
            let initialIsProxy = (protocolConfiguration as? NETunnelProviderProtocol)?.isVPN013Proxy == true
            if !running || initialIsProxy != (crossEngine != .amneziawg) { completionHandler(nil); return }
        }
        if (protocolConfiguration as? NETunnelProviderProtocol)?.isVPN013Proxy == true {
            guard messageData == Data([8]) || messageData == Data([0x53, 0x50, 1]) else { completionHandler(nil); return }
            DispatchQueue.main.async {
                guard let proxy = self.proxyAdapter else { completionHandler(nil); return }
                proxy.statistics(completion: completionHandler)
            }
            return
        }

        if messageData == Data([5]) {
            // Deliberately independent of the engine/main queues and profile storage.
            completionHandler(try? JSONEncoder().encode(VPN013ProviderIdentity.current))
            return
        }
        if messageData == Data([6]) {
            adapter.readRuntimeConfiguration { result in
                let state: VPN013ProviderStatistics.State
                let sample: VPN013RuntimeStatisticsReply?
                switch result {
                case .available(let text):
                    let parsed = VPN013RuntimeStatisticsReply(runtime: text)
                    state = parsed.hasMeasurements ? .available : .noMeasurements
                    sample = parsed.hasMeasurements ? parsed : nil
                case .stopped: state = .stopped; sample = nil
                case .temporarilyOffline: state = .offline; sample = nil
                case .unavailable: state = .unavailable; sample = nil
                }
                let reply = VPN013ProviderStatistics(provider: .current, state: state, sample: sample)
                completionHandler(try? JSONEncoder().encode(reply))
            }
            return
        }

        if messageData == Data([4]) {
            // Read the running backend directly. In particular, do not reopen
            // protocolConfiguration/private storage or wait on the main queue.
            // Only bounded parsed counters and handshake time cross this IPC.
            adapter.getRuntimeConfiguration { runtime in
                let value = VPN013RuntimeStatisticsReply(runtime: runtime)
                completionHandler(try? JSONEncoder().encode(value))
            }
            return
        }

        if messageData == Data([2]) {
            DispatchQueue.main.async {
                let text = self.automatic.map { $0.activeName + "\n" + $0.phase }
                completionHandler(text?.data(using:.utf8))
            };return
        }

        if messageData == Data([3]) {
            DispatchQueue.main.async {
                let revision = self.automatic?.connectionRevision ?? 0
                let lifecycle = self.automaticEpoch
                let configuration = self.automatic != nil ? self.automatic?.currentConfiguration
                    : (self.protocolConfiguration as? NETunnelProviderProtocol)?.asTunnelConfiguration()
                guard let configuration = configuration else { completionHandler(nil); return }
                self.adapter.getRuntimeConfiguration { runtime in
                    DispatchQueue.main.async {
                        guard lifecycle == self.automaticEpoch,
                              revision == (self.automatic?.connectionRevision ?? 0),
                              self.automatic == nil || self.automatic?.currentConfiguration != nil else {
                            completionHandler(nil); return
                        }
                        var value = VPN013ConnectionSnapshot(name: configuration.name ?? "Сервер",
                            endpoints: configuration.peers.compactMap { $0.endpoint?.stringRepresentation },
                            hosts: configuration.peers.compactMap { $0.endpoint.map { String(describing: $0.host) } },
                            phase: self.automatic?.phase, revision: revision,
                            statistics: .parse(runtime))
                        if self.automatic != nil { value.hourlyComparison = self.hourlySupport?.summary ?? "Сравнение VPN недоступно" }
                        value.automaticEnabled = self.automatic?.automaticEnabled
                        completionHandler(try? JSONEncoder().encode(value))
                    }
                }
            }; return
        }

        wg_log(.debug, message: "handleAppMessage: received \(messageData.count) bytes")
        if messageData.count == 1 && messageData[0] == 0 {
            wg_log(.debug, message: "handleAppMessage: runtime configuration requested")
            adapter.getRuntimeConfiguration { [weak self] settings in
                var data: Data?
                if let settings = settings {
                    self?.logRuntimeConfigSummary(settings)
                    data = settings.data(using: .utf8)!
                } else {
                    wg_log(.debug, message: "handleAppMessage: runtime configuration unavailable")
                }
                completionHandler(data)
            }
        } else {
            wg_log(.debug, message: "handleAppMessage: unsupported message payload")
            completionHandler(nil)
        }
    }
}

extension PacketTunnelProvider {
    private func stopCrossEngine(completion: @escaping (Error?) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        crossStopCompletions.append(completion)
        guard !crossStopping else { return }; crossStopping = true
        automaticEpoch += 1; automaticStartupPing?.cancel(); automaticStartupPing = nil
        let pending = automaticStartCompletion; automaticStartCompletion = nil
        pending?(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled))
        automatic?.stop(); automatic = nil
        let finish: (Error?) -> Void = { error in
            DispatchQueue.main.async {
                self.crossEngine = nil; self.crossStopping = false; self.reasserting = false
                let callbacks = self.crossStopCompletions; self.crossStopCompletions.removeAll()
                callbacks.forEach { $0(error) }
            }
        }
        if let proxy = proxyAdapter {
            proxyAdapter = nil; proxy.stop { finish(nil) }
        } else if crossEngine == .amneziawg {
            adapter.stop { error in
                if case .invalidState? = error { finish(nil) }
                else { finish(error) }
            }
        } else { finish(nil) }
    }
    private func startCrossProtocol(_ plan: CrossProtocolPlan, enabled: Bool, epoch: UUID, completion: @escaping (Error?) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        crossPlan = plan
        let resolver = CrossProtocolResolution(); crossResolver = resolver
        do {
            try resolver.start(plan) { addresses in
                guard self.localStatisticsEpoch == epoch else { return }; self.crossResolver = nil
                let coordinator = CrossProtocolCoordinator(count: plan.groups.count, enabled: enabled,
                    start: { [weak self] index, automatic, done in
                        guard let self = self, self.localStatisticsEpoch == epoch, plan.groups.indices.contains(index) else { done(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)); return }
                        let group = plan.groups[index]; self.crossEngine = group.kind
                        self.reasserting = self.crossProtocol?.phase != .starting(0)
                        if let awg = group.awg {
                            do {
                                let original = try awg.validatedConfigurations()
                                let resolved = original.map { configuration -> TunnelConfiguration in
                                    var peers = configuration.peers
                                    for i in peers.indices {
                                        guard let endpoint = peers[i].endpoint, let host = addresses[String(describing: endpoint.host)],
                                              let port = endpoint.stringRepresentation.split(separator: ":").last else { continue }
                                        peers[i].endpoint = Endpoint(from: (host.contains(":") ? "[\(host)]" : host) + ":" + String(port))
                                    }
                                    return TunnelConfiguration(name: configuration.name, interface: configuration.interface, peers: peers)
                                }
                                self.startAutomatic(candidates: resolved, enabled: automatic, displayCandidates: original) { error in
                                    guard self.localStatisticsEpoch == epoch else { return }
                                    self.automatic?.onExhausted = { [weak self] in self?.crossProtocol?.failed() ?? false }
                                    self.automatic?.onVerifiedTraffic = { [weak self] in self?.crossProtocol?.verifiedTraffic() }
                                    self.reasserting = false; done(error)
                                }
                            } catch { done(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid) }
                        } else if var payload = group.proxy {
                            payload.automaticEnabled = automatic
                            let proxy = ProxyPacketAdapter(provider: self); self.proxyAdapter = proxy
                            proxy.onExhausted = { [weak self] in self?.crossProtocol?.failed() ?? false }
                            proxy.onVerifiedTraffic = { [weak self] in self?.crossProtocol?.verifiedTraffic() }
                            proxy.start(payload, preResolved: addresses) { error in
                                guard self.localStatisticsEpoch == epoch else { return }; self.reasserting = false; done(error)
                            }
                        } else { done(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid) }
                    }, stop: { [weak self] done in
                        guard let self = self else { done(nil); return }; self.stopCrossEngine(completion: done)
                    }, pause: { [weak self] enabled in
                        self?.automatic?.setEnabled(enabled); self?.proxyAdapter?.setAutomaticEnabled(enabled)
                    }, ended: { [weak self] error in self?.cancelTunnelWithError(error) })
                self.crossProtocol = coordinator
                coordinator.changed = { [weak coordinator] in
                    guard let coordinator = coordinator, plan.groups.indices.contains(coordinator.selection.current) else { return }
                    let phase: String
                    switch coordinator.phase {
                    case .idle: phase = "idle"
                    case .starting: phase = "starting"
                    case .running: phase = "running"
                    case .switching: phase = "switching"
                    case .stopped: phase = "stopped"
                    }
                    wg_log(.info, message: "Cross-protocol: phase=\(phase);section=\(plan.groups[coordinator.selection.current].kind.rawValue)")
                }
                let monitor = NWPathMonitor(); self.crossPath = monitor
                monitor.pathUpdateHandler = { [weak coordinator] path in coordinator?.networkAvailable = path.status == .satisfied }
                monitor.start(queue: .main)
                let deadline = DispatchWorkItem { [weak coordinator] in coordinator?.stop(completion: {}) }
                self.crossDeadline = deadline
                DispatchQueue.main.asyncAfter(deadline: .now() + 45, execute: deadline)
                coordinator.start { error in
                    self.crossDeadline?.cancel(); self.crossDeadline = nil
                    if error != nil, self.crossProtocol === coordinator {
                        self.crossPath?.cancel(); self.crossPath = nil; self.crossProtocol = nil
                    }
                    completion(error)
                }
            }
        } catch { crossResolver?.cancel(); crossResolver = nil; completion(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid) }
    }
    private func readCrossRuntime(completion: @escaping (Data?) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard let coordinator = crossProtocol, let plan = crossPlan,
              plan.groups.indices.contains(coordinator.selection.current) else { completion(nil); return }
        let group = plan.groups[coordinator.selection.current]
        let token = localStatisticsEpoch
        let encode: (String, String?, String, UInt64?, UInt64?, Date?) -> Void = { name, endpoint, phase, rx, tx, handshake in
            guard self.localStatisticsEpoch == token, self.crossProtocol === coordinator else { completion(nil); return }
            completion(try? JSONEncoder().encode(CrossProtocolRuntime(schema: 1, kind: group.kind, name: name,
                endpoint: endpoint, phase: phase, received: rx, sent: tx, handshake: handshake,
                automaticEnabled: coordinator.selection.enabled, trafficVerified: coordinator.trafficConfirmed)))
        }
        guard case .running = coordinator.phase else {
            encode(group.name, nil, "Переключение конфигурации", nil, nil, nil); return
        }
        let selection = coordinator.selection.current
        if let proxy = proxyAdapter {
            proxy.statistics { data in
                DispatchQueue.main.async {
                    guard coordinator.phase == .running(selection), let data = data,
                          let value = try? JSONDecoder().decode(ProxyTraffic.self, from: data), value.running,
                          value.rx >= 0, value.tx >= 0 else { completion(nil); return }
                    encode(value.selectedName ?? group.name, value.selectedEndpoint,
                        coordinator.trafficConfirmed ? "VPN-трафик подтверждён" : "Проверка VPN-трафика",
                        UInt64(value.rx), UInt64(value.tx), nil)
                }
            }
        } else if let configuration = automatic?.currentConfiguration {
            let revision = automatic?.connectionRevision
            adapter.getRuntimeConfiguration { runtime in
                DispatchQueue.main.async {
                    guard coordinator.phase == .running(selection), self.automatic?.connectionRevision == revision else { completion(nil); return }
                    let stats = VPN013ConnectionSnapshot.Statistics.parse(runtime)
                    encode(configuration.name ?? group.name, configuration.peers.first?.endpoint?.stringRepresentation,
                        self.automatic?.phase ?? "Проверка VPN-трафика", stats.received, stats.sent, stats.handshake)
                }
            }
        } else { completion(nil) }
    }
    private func startAutomatic(candidates:[TunnelConfiguration],enabled:Bool = true,displayCandidates:[TunnelConfiguration]? = nil,completion:@escaping (Error?) -> Void) {
        automaticEpoch += 1;let stamp=automaticEpoch
        automaticStartupPing?.cancel();automaticStartupPing=nil
        automaticStartCompletion=completion
        // Resolve reserves while the physical network is still available. Reusing
        // these addresses avoids a dead tunnel's DNS blocking the reserve itself.
        // The stored profiles retain their domain names; refresh on every start.
        var started=false
        var bootstrapCandidates=candidates
        var configuredCandidates=candidates
        var resolvedCandidates:[TunnelConfiguration]?
        var measurements:[String:EndpointPingResult]=[:]
        var measured=false
        let hosts=candidates.map { $0.peers.first?.endpoint.map { String(describing:$0.host) } }
        func begin() {
            guard !started,self.automaticEpoch==stamp else { return };started=true
            self.automaticStartupPing?.cancel();self.automaticStartupPing=nil
            let order=enabled ? EndpointPingRanking.order(hosts:hosts,measurements:measurements) : Array(candidates.indices)
            let resolved=resolvedCandidates ?? candidates
            bootstrapCandidates=order.map { resolved[$0] }
            configuredCandidates=order.map { (displayCandidates ?? candidates)[$0] }
            // Missing ICMP does not mean a candidate is down: keep all fallbacks.
            // Log counts only, never domains, keys or configuration contents.
            let count=measurements.values.filter { if case .milliseconds = $0 { return true }; return false }.count
            wg_log(.info,message:"Auto startup: measured=\(count);candidates=\(candidates.count)")
            attemptResolved(0)
        }
        func attemptResolved(_ index:Int, attempt:Int = 1) {
            guard self.automaticEpoch==stamp else { return }
            self.adapter.start(tunnelConfiguration:bootstrapCandidates[index]) { error in
                DispatchQueue.main.async {
                    guard self.automaticEpoch==stamp else { return }
                    if error != nil && attempt < 2 {
                        DispatchQueue.main.asyncAfter(deadline:.now()+5) {
                            guard self.automaticEpoch==stamp else { return }
                            attemptResolved(index,attempt:attempt+1)
                        }
                        return
                    }
                    if error != nil && index+1<bootstrapCandidates.count { attemptResolved(index+1);return }
                    let done=self.automaticStartCompletion;self.automaticStartCompletion=nil
                    if let error=error { done?(error);return }
                    let controller=AutoTunnelController(provider:self,adapter:self.adapter,candidates:bootstrapCandidates,initialIndex:index,hourly:self.hourlySupport,configuredCandidates:configuredCandidates)
                    self.automatic=controller;controller.start();controller.setEnabled(enabled);done?(nil)
                }
            }
        }
        let ping=EndpointPingCoordinator(maxConcurrent:6,probeTimeout:1.5,batchTimeout:8)
        automaticStartupPing=ping
        ping.start(hosts:hosts.compactMap { $0 },update:{ host,result in
            guard !started,self.automaticEpoch==stamp else { return }
            measurements[host]=result
        },completion:{
            guard !started,self.automaticEpoch==stamp else { return }
            measured=true
            if resolvedCandidates != nil { begin() }
        })
        DispatchQueue.global(qos:.userInitiated).async {
            let results=DNSResolver.resolveSync(endpoints:candidates.map { $0.peers.first?.endpoint })
            let ready=candidates.enumerated().map { index,config -> TunnelConfiguration in
                var peers=config.peers
                if case .success(let endpoint)?=results[index] { peers[0].endpoint=endpoint }
                return TunnelConfiguration(name:config.name,interface:config.interface,peers:peers)
            }
            DispatchQueue.main.async {
                guard !started,self.automaticEpoch==stamp else { return }
                resolvedCandidates=ready
                if measured { begin() }
            }
        }
        // Bound the physical-network pass before applying tunnel routes.
        DispatchQueue.main.asyncAfter(deadline:.now()+8) { begin() }
    }
}

extension WireGuardLogLevel {
    var osLogLevel: OSLogType {
        switch self {
        case .verbose:
            return .debug
        case .error:
            return .error
        }
    }
}
