// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import os

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var proxyAdapter: ProxyPacketAdapter?
    private var localStatistics: VPN013LocalStatisticsServer?
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
        if let proto = self.protocolConfiguration as? NETunnelProviderProtocol, proto.isVPN013Proxy {
            do {
                let value = try proto.proxyPayload()
                DispatchQueue.main.async {
                    guard self.localStatisticsEpoch == statisticsEpoch else {
                        completionHandler(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)); return
                    }
                    let adapter = ProxyPacketAdapter(provider: self)
                    self.proxyAdapter = adapter
                    adapter.start(value, completion: completionHandler)
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
                // Independent read-only authenticated transport. It cannot alter the
                // engine, routes, profiles or keys and never binds a LAN/WAN address.
                if let envelope = tunnelProviderProtocol.privateEnvelope,
                   let secret = try? PrivateTunnelStore.current.key(for: envelope.id),
                   let credentials = try? VPN013LocalStatisticsCredentials(secret: secret,
                        id: envelope.id, ciphertext: envelope.ciphertext) {
                    let server = VPN013LocalStatisticsServer(credentials: credentials) { [weak self] operation, reply in
                        guard let self = self else { reply(nil); return }
                        self.handleAppMessage(Data([operation]), completionHandler: reply)
                    }
                    self.localStatistics = server; server.start()
                }
                completionHandler(nil)
            }
        }

        do {
            if let profile = try AutoTunnelProfile.load(from:tunnelProviderProtocol) {
                let candidates = try profile.validatedConfigurations()
                let enabled = (try? tunnelProviderProtocol.privatePayload()?.automaticEnabled) ?? true
                DispatchQueue.main.async { self.startAutomatic(candidates:candidates, enabled: enabled, completion:finishStart) }
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
        if (protocolConfiguration as? NETunnelProviderProtocol)?.isVPN013Proxy == true {
            DispatchQueue.main.async {
                self.localStatisticsEpoch = UUID()
                let proxy = self.proxyAdapter
                self.proxyAdapter = nil
                if let proxy = proxy { proxy.stop(completion: completionHandler) } else { completionHandler() }
            }
            return
        }
        wg_log(.info, message: "Stopping tunnel, reason=\(reason.rawValue) (\(reason))")

        let cleanup = {
            self.localStatisticsEpoch = UUID()
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
        if let server = localStatistics {
            localStatistics = nil
            server.stop(completion: stopAdapter)
        } else { stopAdapter() }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler = completionHandler else { return }
        if messageData.count == 2, messageData[0] == 7, messageData[1] <= 1 {
            DispatchQueue.main.async {
                let enabled = messageData[1] == 1
                if let proxy = self.proxyAdapter { proxy.setAutomaticEnabled(enabled); completionHandler(Data([1])) }
                else if let automatic = self.automatic { automatic.setEnabled(enabled); completionHandler(Data([1])) }
                else { completionHandler(nil) }
            }; return
        }
        if (protocolConfiguration as? NETunnelProviderProtocol)?.isVPN013Proxy == true {
            guard messageData == Data([0x53, 0x50, 1]), let proxy = proxyAdapter else { completionHandler(nil); return }
            proxy.statistics(completion: completionHandler)
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
    private func startAutomatic(candidates:[TunnelConfiguration],enabled:Bool = true,completion:@escaping (Error?) -> Void) {
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
            configuredCandidates=order.map { candidates[$0] }
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
