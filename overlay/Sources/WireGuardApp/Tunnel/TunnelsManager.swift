// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import os.log

#if os(iOS)
    import UIKit
    import CryptoKit
#endif

#if os(iOS)
    @objc enum TunnelHandshakeState: Int {
        case idle
        case waiting
        case confirmed
        case failed
    }

    enum TunnelHandshakeError: Error {
        case timedOut(TimeInterval)

        var timeoutInterval: TimeInterval {
            switch self {
            case .timedOut(let interval):
                return interval
            }
        }
    }
#endif

protocol TunnelsManagerListDelegate: AnyObject {
    func tunnelAdded(at index: Int)
    func tunnelModified(at index: Int)
    func tunnelMoved(from oldIndex: Int, to newIndex: Int)
    func tunnelRemoved(at index: Int, tunnel: TunnelContainer)
}

protocol TunnelsManagerActivationDelegate: AnyObject {
    func tunnelActivationAttemptFailed(
        tunnel: TunnelContainer, error: TunnelsManagerActivationAttemptError)  // startTunnel wasn't called or failed
    func tunnelActivationAttemptSucceeded(tunnel: TunnelContainer)  // startTunnel succeeded
    func tunnelActivationFailed(tunnel: TunnelContainer, error: TunnelsManagerActivationError)  // status didn't change to connected
    func tunnelActivationSucceeded(tunnel: TunnelContainer)  // status changed to connected
}

class TunnelsManager {
    private var tunnels: [TunnelContainer]
    weak var tunnelsListDelegate: TunnelsManagerListDelegate?
    weak var activationDelegate: TunnelsManagerActivationDelegate?
    private var statusObservationToken: NotificationToken?
    private var waiteeObservationToken: NSKeyValueObservation?
    private var configurationsObservationToken: NotificationToken?
    private var managedUpdateInProgress = false
    #if os(iOS)
    private var automaticPreparationInProgress = false
    #endif

    func beginManagedUpdate() {
        managedUpdateInProgress = true
        configurationsObservationToken = nil
    }

    func endManagedUpdate() {
        managedUpdateInProgress = false
        startObservingTunnelConfigurations()
        #if !targetEnvironment(simulator)
        reload()
        #endif
    }

    init(tunnelProviders: [NETunnelProviderManager]) {
        tunnels = tunnelProviders.map { TunnelContainer(tunnel: $0) }.sorted {
            TunnelsManager.tunnelIsBefore($0, $1)
        }
        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-start-current") {
            tunnels.first?.status = .active
        }
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-power-connecting") {
            tunnels.first?.status = .activating
        }
        #endif
        startObservingTunnelStatuses()
        startObservingTunnelConfigurations()
    }

    static func create(
        completionHandler: @escaping (Result<TunnelsManager, TunnelsManagerError>) -> Void
    ) {
        #if targetEnvironment(simulator)
            completionHandler(
                .success(TunnelsManager(tunnelProviders: ProcessInfo.processInfo.arguments.contains("--vpn013-test-import") ? [] : MockTunnels.createMockTunnels())))
        #else
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error = error {
                    wg_log(.error, message: "Failed to load tunnel provider managers: \(error)")
                    completionHandler(
                        .failure(
                            TunnelsManagerError.systemErrorOnListingTunnels(systemError: error)))
                    return
                }

                var tunnelManagers = managers ?? []
                var refs: Set<Data> = []
                var tunnelNames: Set<String> = []
                for (index, tunnelManager) in tunnelManagers.enumerated().reversed() {
                    #if os(iOS)
                    // Proxy profiles have a separate typed UI/manager. Preserve them,
                    // including a temporarily unreadable profile; never call orphan cleanup.
                    if (tunnelManager.protocolConfiguration as? NETunnelProviderProtocol)?.isVPN013Proxy == true {
                        tunnelManagers.remove(at: index); continue
                    }
                    #endif
                    if let tunnelName = tunnelManager.localizedDescription {
                        tunnelNames.insert(tunnelName)
                    }
                    guard
                        let proto = tunnelManager.protocolConfiguration as? NETunnelProviderProtocol
                    else { continue }
                    if proto.migrateConfigurationIfNeeded(
                        called: tunnelManager.localizedDescription ?? "unknown")
                    {
                        tunnelManager.saveToPreferences { _ in }
                    }
                    #if os(iOS)
                    if proto.privateEnvelope != nil && proto.verifyConfigurationReference() { continue }
                    #endif
                    #if os(iOS)
                        let passwordRef =
                            proto.verifyConfigurationReference() ? proto.passwordReference : nil
                    #elseif os(macOS)
                        let passwordRef: Data?
                        if proto.providerConfiguration?["UID"] as? uid_t == getuid() {
                            passwordRef =
                                proto.verifyConfigurationReference() ? proto.passwordReference : nil
                        } else {
                            passwordRef = proto.passwordReference  // To handle multiple users in macOS, we skip verifying
                        }
                    #else
                        #error("Unimplemented")
                    #endif
                    if let ref = passwordRef {
                        refs.insert(ref)
                        if let groupRef = proto.providerConfiguration?[AutoTunnelProfile.referenceKey] as? Data { refs.insert(groupRef) }
                    } else {
                        wg_log(
                            .info,
                            message:
                                "Removing orphaned tunnel with non-verifying keychain entry: \(tunnelManager.localizedDescription ?? "<unknown>")"
                        )
                        tunnelManager.removeFromPreferences { _ in }
                        tunnelManagers.remove(at: index)
                    }
                }
                #if os(macOS)
                Keychain.deleteReferences(except: refs)
                #endif
                #if os(iOS)
                    RecentTunnelsTracker.cleanupTunnels(except: tunnelNames)
                #endif
                completionHandler(.success(TunnelsManager(tunnelProviders: tunnelManagers)))
            }
        #endif
    }

    func reload() {
        #if targetEnvironment(simulator)
        return // Simulator profiles exist only in memory, not in system VPN preferences.
        #endif
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            guard let self = self else { return }

            let loadedTunnelProviders = (managers ?? []).filter {
                #if os(iOS)
                return ($0.protocolConfiguration as? NETunnelProviderProtocol)?.isVPN013Proxy != true
                #else
                return true
                #endif
            }

            for (index, currentTunnel) in self.tunnels.enumerated().reversed() {
                if !loadedTunnelProviders.contains(where: { $0.isEquivalentTo(currentTunnel) }) {
                    // Tunnel was deleted outside the app
                    self.tunnels.remove(at: index)
                    self.tunnelsListDelegate?.tunnelRemoved(at: index, tunnel: currentTunnel)
                }
            }
            for loadedTunnelProvider in loadedTunnelProviders {
                if let matchingTunnel = self.tunnels.first(where: {
                    loadedTunnelProvider.isEquivalentTo($0)
                }) {
                    matchingTunnel.tunnelProvider = loadedTunnelProvider
                    matchingTunnel.refreshStatus()
                } else {
                    // Tunnel was added outside the app
                    if let proto = loadedTunnelProvider.protocolConfiguration
                        as? NETunnelProviderProtocol
                    {
                        if proto.migrateConfigurationIfNeeded(
                            called: loadedTunnelProvider.localizedDescription ?? "unknown")
                        {
                            loadedTunnelProvider.saveToPreferences { _ in }
                        }
                    }
                    let tunnel = TunnelContainer(tunnel: loadedTunnelProvider)
                    self.tunnels.append(tunnel)
                    self.tunnels.sort { TunnelsManager.tunnelIsBefore($0, $1) }
                    self.tunnelsListDelegate?.tunnelAdded(at: self.tunnels.firstIndex(of: tunnel)!)
                }
            }
        }
    }

    func add(
        tunnelConfiguration: TunnelConfiguration, onDemandOption: ActivateOnDemandOption = .off,
        automaticProfile: AutoTunnelProfile? = nil,
        sourcePrepared: Bool = false,
        completionHandler: @escaping (Result<TunnelContainer, TunnelsManagerError>) -> Void
    ) {
        #if os(iOS) && !targetEnvironment(simulator)
        if !sourcePrepared {
            CrossProtocolPlan.prepareMutation { result in
                switch result {
                case .failure(let error): completionHandler(.failure(.systemErrorOnAddTunnel(systemError: error)))
                case .success(let permit):
                    self.add(tunnelConfiguration: tunnelConfiguration, onDemandOption: onDemandOption, automaticProfile: automaticProfile, sourcePrepared: true) { result in permit.release(); completionHandler(result) }
                }
            }
            return
        }
        #endif
        let tunnelName = tunnelConfiguration.name ?? ""
        if tunnelName.isEmpty {
            completionHandler(.failure(TunnelsManagerError.tunnelNameEmpty))
            return
        }

        if tunnels.contains(where: { $0.name == tunnelName }) {
            completionHandler(.failure(TunnelsManagerError.tunnelAlreadyExistsWithThatName))
            return
        }

        let tunnelProviderManager = NETunnelProviderManager()
        tunnelProviderManager.setTunnelConfiguration(tunnelConfiguration)
        guard tunnelProviderManager.protocolConfiguration != nil else {
            completionHandler(.failure(.systemErrorOnAddTunnel(systemError: PrivateTunnelStore.lastError ?? PrivateStoreError.invalidEnvelope)))
            return
        }
        tunnelProviderManager.isEnabled = true

        if let profile = automaticProfile,
           let proto = tunnelProviderManager.protocolConfiguration as? NETunnelProviderProtocol {
            do {
                let raw = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
                #if os(iOS)
                try proto.setPrivateAutomatic(profile)
                #else
                guard let ref = Keychain.makeReference(containing: raw, called: "VPN013 automatic group") else { throw AutoTunnelError.keychain }
                proto.providerConfiguration = (proto.providerConfiguration ?? [:]).merging([AutoTunnelProfile.referenceKey:ref]) { _,new in new }
                #endif
            } catch {
                proto.destroyConfigurationReference()
                completionHandler(.failure(TunnelsManagerError.systemErrorOnAddTunnel(systemError:error)));return
            }
        }

        onDemandOption.apply(on: tunnelProviderManager)

        let activeTunnel = tunnels.first { $0.status == .active || $0.status == .activating }

        #if targetEnvironment(simulator)
        let simulated = TunnelContainer(tunnel: tunnelProviderManager)
        tunnels.append(simulated); tunnels.sort { TunnelsManager.tunnelIsBefore($0, $1) }
        tunnelsListDelegate?.tunnelAdded(at:tunnels.firstIndex(of:simulated)!)
        completionHandler(.success(simulated)); return
        #endif

        tunnelProviderManager.saveToPreferences { [weak self] error in
            if let error = error {
                wg_log(.error, message: "Add: Saving configuration failed: \(error)")
                (tunnelProviderManager.protocolConfiguration as? NETunnelProviderProtocol)?
                    .destroyConfigurationReference()
                completionHandler(
                    .failure(TunnelsManagerError.systemErrorOnAddTunnel(systemError: error)))
                return
            }

            guard let self = self else { return }

            #if os(iOS)
                // HACK: In iOS, adding a tunnel causes deactivation of any currently active tunnel.
                // This is an ugly hack to reactivate the tunnel that has been deactivated like that.
                if let activeTunnel = activeTunnel {
                    if activeTunnel.status == .inactive || activeTunnel.status == .deactivating {
                        self.startActivation(of: activeTunnel)
                    }
                    if activeTunnel.status == .active || activeTunnel.status == .activating {
                        activeTunnel.status = .restarting
                    }
                }
            #endif

            let tunnel = TunnelContainer(tunnel: tunnelProviderManager)
            self.tunnels.append(tunnel)
            self.tunnels.sort { TunnelsManager.tunnelIsBefore($0, $1) }
            self.tunnelsListDelegate?.tunnelAdded(at: self.tunnels.firstIndex(of: tunnel)!)
            completionHandler(.success(tunnel))
        }
    }

    func addMultiple(
        tunnelConfigurations: [TunnelConfiguration],
        completionHandler: @escaping (UInt, TunnelsManagerError?) -> Void
    ) {
        // Temporarily pause observation of changes to VPN configurations to prevent the feedback
        // loop that causes `reload()` to be called on each newly added tunnel, which significantly
        // impacts performance.
        configurationsObservationToken = nil

        self.addMultiple(
            tunnelConfigurations: ArraySlice(tunnelConfigurations), numberSuccessful: 0,
            lastError: nil
        ) { [weak self] numSucceeded, error in
            completionHandler(numSucceeded, error)

            // Restart observation of changes to VPN configrations.
            self?.startObservingTunnelConfigurations()

            // Force reload all configurations to make sure that all tunnels are up to date.
            self?.reload()
        }
    }

    private func addMultiple(
        tunnelConfigurations: ArraySlice<TunnelConfiguration>, numberSuccessful: UInt,
        lastError: TunnelsManagerError?,
        completionHandler: @escaping (UInt, TunnelsManagerError?) -> Void
    ) {
        guard let head = tunnelConfigurations.first else {
            completionHandler(numberSuccessful, lastError)
            return
        }
        let tail = tunnelConfigurations.dropFirst()
        add(tunnelConfiguration: head) { [weak self, tail] result in
            DispatchQueue.main.async {
                var numberSuccessfulCount = numberSuccessful
                var latestError = lastError
                switch result {
                case .failure(let error):
                    latestError = error
                case .success:
                    numberSuccessfulCount = numberSuccessful + 1
                }
                self?.addMultiple(
                    tunnelConfigurations: tail, numberSuccessful: numberSuccessfulCount,
                    lastError: latestError, completionHandler: completionHandler)
            }
        }
    }

    func modify(
        tunnel: TunnelContainer, tunnelConfiguration: TunnelConfiguration,
        onDemandOption: ActivateOnDemandOption,
        shouldEnsureOnDemandEnabled: Bool = false,
        automaticProfile: AutoTunnelProfile? = nil,
        sourcePrepared: Bool = false,
        completionHandler: @escaping (TunnelsManagerError?) -> Void
    ) {
        #if os(iOS) && !targetEnvironment(simulator)
        if !sourcePrepared {
            CrossProtocolPlan.prepareMutation { result in
                switch result {
                case .failure(let error): completionHandler(.systemErrorOnModifyTunnel(systemError: error))
                case .success(let permit):
                    self.modify(tunnel: tunnel, tunnelConfiguration: tunnelConfiguration, onDemandOption: onDemandOption, shouldEnsureOnDemandEnabled: shouldEnsureOnDemandEnabled, automaticProfile: automaticProfile, sourcePrepared: true) { error in permit.release(); completionHandler(error) }
                }
            }
            return
        }
        #endif
        let tunnelName = tunnelConfiguration.name ?? ""
        if tunnelName.isEmpty {
            completionHandler(TunnelsManagerError.tunnelNameEmpty)
            return
        }

        let tunnelProviderManager = tunnel.tunnelProvider
        let previousProtocol = tunnelProviderManager.protocolConfiguration?.copy() as? NEVPNProtocol

        let isIntroducingOnDemandRules =
            (tunnelProviderManager.onDemandRules ?? []).isEmpty && onDemandOption != .off
        if isIntroducingOnDemandRules && tunnel.status != .inactive
            && tunnel.status != .deactivating
        {
            tunnel.onDeactivated = { [weak self] in
                self?.modify(
                    tunnel: tunnel, tunnelConfiguration: tunnelConfiguration,
                    onDemandOption: onDemandOption, shouldEnsureOnDemandEnabled: true, automaticProfile: automaticProfile,
                    completionHandler: completionHandler)
            }
            self.startDeactivation(of: tunnel)
            return
        } else {
            tunnel.onDeactivated = nil
        }

        let oldName = tunnelProviderManager.localizedDescription ?? ""
        let isNameChanged = tunnelName != oldName
        if isNameChanged {
            guard !tunnels.contains(where: { $0.name == tunnelName }) else {
                completionHandler(TunnelsManagerError.tunnelAlreadyExistsWithThatName)
                return
            }
            tunnel.name = tunnelName
        }

        var isTunnelConfigurationChanged = false
        if tunnelProviderManager.tunnelConfiguration != tunnelConfiguration {
            guard tunnelProviderManager.setTunnelConfiguration(tunnelConfiguration) else {
                tunnel.name = oldName
                completionHandler(.systemErrorOnModifyTunnel(systemError: PrivateTunnelStore.lastError ?? PrivateStoreError.invalidEnvelope)); return
            }
            isTunnelConfigurationChanged = true
        }
        tunnelProviderManager.isEnabled = true

        if let profile = automaticProfile, let proto = tunnelProviderManager.protocolConfiguration as? NETunnelProviderProtocol {
            do { try proto.setPrivateAutomatic(profile); isTunnelConfigurationChanged = true }
            catch {
                tunnelProviderManager.protocolConfiguration = previousProtocol
                tunnel.name = oldName
                completionHandler(.systemErrorOnModifyTunnel(systemError: error)); return
            }
        }

        let isActivatingOnDemand =
            !tunnelProviderManager.isOnDemandEnabled && shouldEnsureOnDemandEnabled
        onDemandOption.apply(on: tunnelProviderManager)
        if shouldEnsureOnDemandEnabled {
            tunnelProviderManager.isOnDemandEnabled = true
        }

        let saveCompletion: (Error?) -> Void = { [weak self] error in
            if let error = error {
                tunnelProviderManager.protocolConfiguration = previousProtocol
                tunnel.name = oldName
                wg_log(.error, message: "Modify: Saving configuration failed: \(error)")
                completionHandler(TunnelsManagerError.systemErrorOnModifyTunnel(systemError: error))
                return
            }
            guard let self = self else { return }
            if isNameChanged {
                let oldIndex = self.tunnels.firstIndex(of: tunnel)!
                self.tunnels.sort { TunnelsManager.tunnelIsBefore($0, $1) }
                let newIndex = self.tunnels.firstIndex(of: tunnel)!
                self.tunnelsListDelegate?.tunnelMoved(from: oldIndex, to: newIndex)
                #if os(iOS)
                    RecentTunnelsTracker.handleTunnelRenamed(oldName: oldName, newName: tunnelName)
                #endif
            }
            self.tunnelsListDelegate?.tunnelModified(at: self.tunnels.firstIndex(of: tunnel)!)

            if isTunnelConfigurationChanged {
                if tunnel.status == .active || tunnel.status == .activating
                    || tunnel.status == .reasserting
                {
                    // Turn off the tunnel, and then turn it back on, so the changes are made effective
                    tunnel.status = .restarting
                    (tunnel.tunnelProvider.connection as? NETunnelProviderSession)?.stopTunnel()
                }
            }

            if isActivatingOnDemand {
                // Reload tunnel after saving.
                // Without this, the tunnel stopes getting updates on the tunnel status from iOS.
                tunnelProviderManager.loadFromPreferences { error in
                    tunnel.isActivateOnDemandEnabled = tunnelProviderManager.isOnDemandEnabled
                    if let error = error {
                        wg_log(
                            .error,
                            message:
                                "Modify: Re-loading after saving configuration failed: \(error)")
                        completionHandler(
                            TunnelsManagerError.systemErrorOnModifyTunnel(systemError: error))
                    } else {
                        completionHandler(nil)
                    }
                }
            } else {
                completionHandler(nil)
            }
        }
        #if targetEnvironment(simulator)
        saveCompletion(nil)
        #else
        tunnelProviderManager.saveToPreferences(completionHandler: saveCompletion)
        #endif
    }

    func remove(
        tunnel: TunnelContainer, sourcePrepared: Bool = false, completionHandler: @escaping (TunnelsManagerError?) -> Void
    ) {
        #if os(iOS) && !targetEnvironment(simulator)
        if !sourcePrepared {
            CrossProtocolPlan.prepareMutation { result in
                switch result {
                case .failure(let error): completionHandler(.systemErrorOnRemoveTunnel(systemError: error))
                case .success(let permit): self.remove(tunnel: tunnel, sourcePrepared: true) { error in permit.release(); completionHandler(error) }
                }
            }
            return
        }
        #endif
        let tunnelProviderManager = tunnel.tunnelProvider
        let removeCompletion: (Error?) -> Void = { [weak self] error in
            if let error = error {
                wg_log(.error, message: "Remove: Saving configuration failed: \(error)")
                completionHandler(TunnelsManagerError.systemErrorOnRemoveTunnel(systemError: error))
                return
            }
            #if os(macOS)
            if tunnel.isTunnelAvailableToUser {
                (tunnelProviderManager.protocolConfiguration as? NETunnelProviderProtocol)?.destroyConfigurationReference()
            }
            #elseif os(iOS)
            (tunnelProviderManager.protocolConfiguration as? NETunnelProviderProtocol)?.destroyConfigurationReference()
            #endif
            if let self = self, let index = self.tunnels.firstIndex(of: tunnel) {
                self.tunnels.remove(at: index)
                self.tunnelsListDelegate?.tunnelRemoved(at: index, tunnel: tunnel)
            }
            completionHandler(nil)

            #if os(iOS)
                RecentTunnelsTracker.handleTunnelRemoved(tunnelName: tunnel.name)
            #endif
        }
        #if targetEnvironment(simulator)
        removeCompletion(nil)
        #else
        tunnelProviderManager.removeFromPreferences(completionHandler: removeCompletion)
        #endif
    }

    func removeMultiple(
        tunnels: [TunnelContainer], completionHandler: @escaping (TunnelsManagerError?) -> Void
    ) {
        // Temporarily pause observation of changes to VPN configurations to prevent the feedback
        // loop that causes `reload()` to be called for each removed tunnel, which significantly
        // impacts performance.
        configurationsObservationToken = nil

        removeMultiple(tunnels: ArraySlice(tunnels)) { [weak self] error in
            completionHandler(error)

            // Restart observation of changes to VPN configrations.
            self?.startObservingTunnelConfigurations()

            // Force reload all configurations to make sure that all tunnels are up to date.
            self?.reload()
        }
    }

    private func removeMultiple(
        tunnels: ArraySlice<TunnelContainer>,
        completionHandler: @escaping (TunnelsManagerError?) -> Void
    ) {
        guard let head = tunnels.first else {
            completionHandler(nil)
            return
        }
        let tail = tunnels.dropFirst()
        remove(tunnel: head) { [weak self, tail] error in
            DispatchQueue.main.async {
                if let error = error {
                    completionHandler(error)
                } else {
                    self?.removeMultiple(tunnels: tail, completionHandler: completionHandler)
                }
            }
        }
    }

    func setOnDemandEnabled(
        _ isOnDemandEnabled: Bool, on tunnel: TunnelContainer,
        completionHandler: @escaping (TunnelsManagerError?) -> Void
    ) {
        let tunnelProviderManager = tunnel.tunnelProvider
        let isCurrentlyEnabled =
            (tunnelProviderManager.isOnDemandEnabled && tunnelProviderManager.isEnabled)
        guard isCurrentlyEnabled != isOnDemandEnabled else {
            completionHandler(nil)
            return
        }
        let isActivatingOnDemand = !tunnelProviderManager.isOnDemandEnabled && isOnDemandEnabled
        tunnelProviderManager.isOnDemandEnabled = isOnDemandEnabled
        tunnelProviderManager.isEnabled = true
        tunnelProviderManager.saveToPreferences { error in
            if let error = error {
                wg_log(.error, message: "Modify On-Demand: Saving configuration failed: \(error)")
                completionHandler(TunnelsManagerError.systemErrorOnModifyTunnel(systemError: error))
                return
            }
            if isActivatingOnDemand {
                // If we're enabling on-demand, we want to make sure the tunnel is enabled.
                // If not enabled, the OS will not turn the tunnel on/off based on our rules.
                tunnelProviderManager.loadFromPreferences { error in
                    // isActivateOnDemandEnabled will get changed in reload(), but no harm in setting it here too
                    tunnel.isActivateOnDemandEnabled = tunnelProviderManager.isOnDemandEnabled
                    if let error = error {
                        wg_log(
                            .error,
                            message:
                                "Modify On-Demand: Re-loading after saving configuration failed: \(error)"
                        )
                        completionHandler(
                            TunnelsManagerError.systemErrorOnModifyTunnel(systemError: error))
                        return
                    }
                    completionHandler(nil)
                }
            } else {
                completionHandler(nil)
            }
        }
    }

    func numberOfTunnels() -> Int {
        return tunnels.count
    }

    func tunnel(at index: Int) -> TunnelContainer {
        return tunnels[index]
    }

    func mapTunnels<T>(transform: (TunnelContainer) throws -> T) rethrows -> [T] {
        return try tunnels.map(transform)
    }

    func index(of tunnel: TunnelContainer) -> Int? {
        return tunnels.firstIndex(of: tunnel)
    }

    func tunnel(named tunnelName: String) -> TunnelContainer? {
        return tunnels.first { $0.name == tunnelName }
    }

    func waitingTunnel() -> TunnelContainer? {
        return tunnels.first { $0.status == .waiting }
    }

    func tunnelInOperation() -> TunnelContainer? {
        if let waitingTunnelObject = waitingTunnel() {
            return waitingTunnelObject
        }
        return tunnels.first { $0.status != .inactive }
    }

    func startActivation(of tunnel: TunnelContainer, automaticPrepared: Bool = false) {
        #if os(iOS)
        guard !CrossProtocolPlan.changingSources else {
            activationDelegate?.tunnelActivationAttemptFailed(tunnel: tunnel, error: .tunnelIsNotInactive); return
        }
        #endif
        guard !managedUpdateInProgress else { return }
        guard tunnels.contains(tunnel) else { return }  // Ensure it's not deleted
        guard tunnel.status == .inactive else {
            activationDelegate?.tunnelActivationAttemptFailed(
                tunnel: tunnel, error: .tunnelIsNotInactive)
            return
        }

        #if os(iOS)
        if !automaticPrepared {
            prepareBuiltinAutomatic(tunnel) { [weak self, weak tunnel] error in
                guard let self = self, let tunnel = tunnel, self.tunnels.contains(tunnel) else { return }
                if let error = error {
                    self.activationDelegate?.tunnelActivationAttemptFailed(tunnel: tunnel, error: .failedWhileSaving(systemError: error))
                } else { self.startActivation(of: tunnel, automaticPrepared: true) }
            }
            return
        }
        #endif

        if let alreadyWaitingTunnel = tunnels.first(where: { $0.status == .waiting }) {
            alreadyWaitingTunnel.status = .inactive
        }

        if let tunnelInOperation = tunnels.first(where: { $0.status != .inactive }) {
            wg_log(
                .info,
                message:
                    "Tunnel '\(tunnel.name)' waiting for deactivation of '\(tunnelInOperation.name)'"
            )
            tunnel.status = .waiting
            activateWaitingTunnelOnDeactivation(of: tunnelInOperation)
            if tunnelInOperation.status != .deactivating {
                if tunnelInOperation.isActivateOnDemandEnabled {
                    setOnDemandEnabled(false, on: tunnelInOperation) { [weak self] error in
                        guard error == nil else {
                            wg_log(
                                .error,
                                message:
                                    "Unable to activate tunnel '\(tunnel.name)' because on-demand could not be disabled on active tunnel '\(tunnel.name)'"
                            )
                            return
                        }
                        self?.startDeactivation(of: tunnelInOperation)
                    }
                } else {
                    startDeactivation(of: tunnelInOperation)
                }
            }
            return
        }

        #if targetEnvironment(simulator)
            tunnel.status = .active
        #else
            tunnel.startActivation(activationDelegate: activationDelegate)
        #endif

        #if os(iOS)
            RecentTunnelsTracker.handleTunnelActivated(tunnelName: tunnel.name)
        #endif
    }

    #if os(iOS)
    var automaticModeBusy: Bool {
        builtinPreparing || tunnels.contains { ![.inactive, .active].contains($0.status) }
    }
    private var builtinPreparing: Bool {
        get { automaticPreparationInProgress }
        set {
            automaticPreparationInProgress = newValue
            NotificationCenter.default.post(name: AutomaticModeRow.availabilityChanged, object: nil)
        }
    }
    private func prepareBuiltinAutomatic(_ tunnel: TunnelContainer, completion: @escaping (Error?) -> Void) {
        guard !builtinPreparing else { completion(ProxyOperationError.busy); return }
        guard let proto = tunnel.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
              let old = proto.copy() as? NETunnelProviderProtocol else { completion(AutoTunnelError.keychain); return }
        do {
            let stored = try proto.privatePayload()
            let serviceIdentity = try stored?.serviceRoutingIdentity()
            let group: AutoTunnelProfile?
            if stored?.automatic != nil && stored?.builtinAutomatic == nil {
                group = try AutoTunnelProfile.load(from: proto)!
            } else {
                let sources = [tunnel] + tunnels.filter { $0 !== tunnel }
                var names = Set<String>()
                let configurations = sources.compactMap { item -> TunnelConfiguration? in
                    let value = try? (item.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.privatePayload()
                    guard value?.automatic == nil, let config = item.tunnelConfiguration,
                          (try? value?.serviceRoutingIdentity()) == serviceIdentity,
                          let name = config.name, !names.contains(name),
                          (try? AutoTunnelProfile(configurations: [config])) != nil else { return nil }
                    names.insert(name); return config
                }
                if VPN013AutomaticMode.enabled() {
                    guard configurations.first?.name == tunnel.name else { throw AutoTunnelError.incompatible(tunnel.name) }
                    group = try AutoTunnelProfile(configurations: configurations)
                } else { group = try? AutoTunnelProfile(configurations: configurations) }
            }
            try proto.setBuiltinAutomatic(group, enabled: VPN013AutomaticMode.enabled(), initial: true)
            builtinPreparing = true
            let done: (Error?) -> Void = { error in
                DispatchQueue.main.async {
                    self.builtinPreparing = false
                    if error != nil { tunnel.tunnelProvider.protocolConfiguration = old }
                    completion(error)
                }
            }
            #if targetEnvironment(simulator)
            done(nil)
            #else
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                DispatchQueue.main.async {
                    guard error == nil else { done(ProxyOperationError.system); return }
                    do {
                        try CrossProtocolPlan.attach(to: proto, managers: managers ?? [])
                        tunnel.tunnelProvider.saveToPreferences(completionHandler: done)
                    } catch { done(error) }
                }
            }
            #endif
        } catch { tunnel.tunnelProvider.protocolConfiguration = old; completion(error) }
    }

    func applyAutomaticPreference(completion: @escaping (Error?) -> Void) {
        guard !builtinPreparing else { completion(ProxyOperationError.busy); return }
        guard let tunnel = tunnelInOperation(), tunnel.status == .active,
              tunnel.hasAutomaticRuntime else { completion(nil); return }
        builtinPreparing = true
        tunnel.applyAutomaticMode(VPN013AutomaticMode.enabled()) { error in
            self.builtinPreparing = false; completion(error)
        }
    }
    #endif

    func startDeactivation(of tunnel: TunnelContainer) {
        tunnel.isAttemptingActivation = false
        guard tunnel.status != .inactive && tunnel.status != .deactivating else { return }
        #if targetEnvironment(simulator)
            tunnel.status = .inactive
        #else
            tunnel.startDeactivation()
        #endif
    }

    func refreshStatuses() {
        tunnels.forEach { $0.refreshStatus() }
    }

    private func activateWaitingTunnelOnDeactivation(of tunnel: TunnelContainer) {
        waiteeObservationToken = tunnel.observe(\.status) { [weak self] tunnel, _ in
            guard let self = self else { return }
            if tunnel.status == .inactive {
                if let waitingTunnel = self.tunnels.first(where: { $0.status == .waiting }) {
                    waitingTunnel.startActivation(activationDelegate: self.activationDelegate)
                }
                self.waiteeObservationToken = nil
            }
        }
    }

    private func startObservingTunnelStatuses() {
        statusObservationToken = NotificationCenter.default.observe(
            name: .NEVPNStatusDidChange, object: nil, queue: OperationQueue.main
        ) { [weak self] statusChangeNotification in
            guard let self = self,
                let session = statusChangeNotification.object as? NETunnelProviderSession,
                let tunnelProvider = session.manager as? NETunnelProviderManager,
                let tunnel = self.tunnels.first(where: { $0.tunnelProvider == tunnelProvider })
            else { return }

            wg_log(
                .debug,
                message:
                    "Tunnel '\(tunnel.name)' connection status changed to '\(tunnel.tunnelProvider.connection.status)'"
            )

            if session.status == .connected {
                #if os(iOS)
                    // The system confirms that the Packet Tunnel has started, not
                    // that a peer has exchanged traffic. A quiet manual tunnel
                    // must not be stopped by a foreground handshake deadline.
                    // Runtime handshake/traffic remain available in its detail;
                    // Auto performs its own through-tunnel traffic checks.
                    tunnel.cancelHandshakeMonitoring()
                #endif
                if tunnel.isAttemptingActivation {
                    tunnel.isAttemptingActivation = false
                    self.activationDelegate?.tunnelActivationSucceeded(tunnel: tunnel)
                }
            } else if session.status == .disconnected {
                #if os(iOS)
                    tunnel.cancelHandshakeMonitoring()
                #endif
                if tunnel.isAttemptingActivation {
                    tunnel.isAttemptingActivation = false
                    if let (title, message) = lastErrorTextFromNetworkExtension(for: tunnel) {
                        self.activationDelegate?.tunnelActivationFailed(
                            tunnel: tunnel,
                            error: .activationFailedWithExtensionError(
                                title: title, message: message,
                                wasOnDemandEnabled: tunnelProvider.isOnDemandEnabled))
                    } else {
                        self.activationDelegate?.tunnelActivationFailed(
                            tunnel: tunnel,
                            error: .activationFailed(
                                wasOnDemandEnabled: tunnelProvider.isOnDemandEnabled))
                    }
                }
            }

            if session.status == .disconnected {
                tunnel.onDeactivated?()
                tunnel.onDeactivated = nil
            }

            if tunnel.status == .restarting && session.status == .disconnected {
                tunnel.startActivation(activationDelegate: self.activationDelegate)
                return
            }

            tunnel.refreshStatus()
        }
    }

    func startObservingTunnelConfigurations() {
        configurationsObservationToken = NotificationCenter.default.observe(
            name: .NEVPNConfigurationChange, object: nil, queue: OperationQueue.main
        ) { [weak self] _ in
            DispatchQueue.main.async { [weak self] in
                // We schedule reload() in a subsequent runloop to ensure that the completion handler of loadAllFromPreferences
                // (reload() calls loadAllFromPreferences) is called after the completion handler of the saveToPreferences or
                // removeFromPreferences call, if any, that caused this notification to fire. This notification can also fire
                // as a result of a tunnel getting added or removed outside of the app.
                self?.reload()
            }
        }
    }

    static func tunnelIsBefore(_ lhs: TunnelContainer, _ rhs: TunnelContainer) -> Bool {
        VPN013ProfileOrdering.isBefore(name: lhs.name, automatic: lhs.isVPN013Automatic,
                                      name: rhs.name, automatic: rhs.isVPN013Automatic)
    }

    static func tunnelNameIsLessThan(_ lhs: String, _ rhs: String) -> Bool {
        return lhs.compare(
            rhs, options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive, .numeric])
            == .orderedAscending
    }
}

private func lastErrorTextFromNetworkExtension(for tunnel: TunnelContainer) -> (
    title: String, message: String
)? {
    guard let lastErrorFileURL = FileManager.networkExtensionLastErrorFileURL else { return nil }
    guard let lastErrorData = try? Data(contentsOf: lastErrorFileURL) else { return nil }
    guard
        let lastErrorStrings = String(data: lastErrorData, encoding: .utf8)?.splitToArray(
            separator: "\n")
    else { return nil }
    guard lastErrorStrings.count == 2 && tunnel.activationAttemptId == lastErrorStrings[0] else {
        return nil
    }

    if let extensionError = PacketTunnelProviderError(rawValue: lastErrorStrings[1]) {
        return extensionError.alertText
    }

    return (tr("alertTunnelActivationFailureTitle"), tr("alertTunnelActivationFailureMessage"))
}

class TunnelContainer: NSObject {
    #if os(iOS)
        private enum HandshakeConstants {
            static let pollInterval: TimeInterval = 1.0
            static let acceptanceSkew: TimeInterval = 1.0
            static let defaultTimeout: TimeInterval = 12.0
        }
    #endif
    @objc dynamic var name: String
    @objc dynamic var status: TunnelStatus {
        didSet { if status != oldValue && status != .active { statisticsMessages.invalidate() } }
    }
    #if os(iOS)
        @objc dynamic var handshakeState: TunnelHandshakeState = .idle
    #endif

    @objc dynamic var isActivateOnDemandEnabled: Bool
    @objc dynamic var hasOnDemandRules: Bool

    var isAttemptingActivation = false {
        didSet {
            if isAttemptingActivation {
                self.activationTimer?.invalidate()
                let activationTimer = Timer(timeInterval: 5 /* seconds */, repeats: true) {
                    [weak self] _ in
                    guard let self = self else { return }
                    wg_log(
                        .debug,
                        message:
                            "Status update notification timeout for tunnel '\(self.name)'. Tunnel status is now '\(self.tunnelProvider.connection.status)'."
                    )
                    switch self.tunnelProvider.connection.status {
                    case .connected, .disconnected, .invalid:
                        self.activationTimer?.invalidate()
                        self.activationTimer = nil
                    default:
                        break
                    }
                    self.refreshStatus()
                }
                self.activationTimer = activationTimer
                RunLoop.main.add(activationTimer, forMode: .common)
            }
        }
    }
    var activationAttemptId: String?
    var activationTimer: Timer?
    var deactivationTimer: Timer?
    var onDeactivated: (() -> Void)?
    #if os(iOS)
        private var handshakePollTimer: Timer?
        private var handshakeTimeoutTimer: Timer?
        private var handshakeTimeoutDeadline: Date?
        private var handshakeCutoffDate: Date?
        private var pendingTimeoutInterval: TimeInterval?
        private var handshakeCompletion: ((Result<Date, TunnelHandshakeError>) -> Void)?
        private var handshakePollInFlight = false
        private var appDidEnterBackgroundObserver: NSObjectProtocol?
        private var appWillEnterForegroundObserver: NSObjectProtocol?
    #endif

    fileprivate var tunnelProvider: NETunnelProviderManager {
        didSet {
            isActivateOnDemandEnabled = tunnelProvider.isOnDemandEnabled && tunnelProvider.isEnabled
            hasOnDemandRules = !(tunnelProvider.onDemandRules ?? []).isEmpty
        }
    }

    var tunnelConfiguration: TunnelConfiguration? {
        return tunnelProvider.tunnelConfiguration
    }

    var persistentProfileIdentifier: String? {
        (tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope?.id
    }

    var automaticProfileForUpdates: AutoTunnelProfile? {
        guard let proto = tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol else { return nil }
        #if os(iOS)
        if proto.privateEnvelope != nil { return try? proto.privatePayload()?.automatic }
        #endif
        return try? AutoTunnelProfile.load(from: proto)
    }

    var isVPN013Automatic: Bool {
        (tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.isVPN013Automatic == true
    }
    var usesAutomaticSelection: Bool {
        if status == .active,
           let envelope = (tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope,
           effectiveAutomaticRevision == envelope.ciphertext, let enabled = effectiveAutomaticEnabled { return enabled }
        return (tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.usesVPN013Automatic == true
    }
    var hasAutomaticRuntime: Bool {
        guard let proto = tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol else { return false }
        #if os(iOS)
        if let payload = try? proto.privatePayload(), payload.builtinAutomatic != nil || payload.crossProtocol != nil { return true }
        #endif
        return proto.isVPN013Automatic
    }
    var requiresAutomaticIdentity: Bool {
        guard let proto = tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol else { return false }
        #if os(iOS)
        if let payload = try? proto.privatePayload(), payload.builtinAutomatic != nil || payload.crossProtocol != nil {
            guard let envelope = proto.privateEnvelope else { return true }
            return VPN013AutomaticIdentityHistory.required(id: envelope.id, ciphertext: envelope.ciphertext,
                initial: payload.automatic != nil || payload.builtinAutomaticIdentityRequired != false)
        }
        #endif
        return proto.isVPN013Automatic
    }

    var automaticServerCount: Int {
        guard let proto = tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol else { return 0 }
        return (try? AutoTunnelProfile.load(from: proto))?.candidates.count ?? 0
    }

    func getAutomaticStatus(completion: @escaping (String?) -> Void) {
        guard usesAutomaticSelection, status == .active,
              let session = tunnelProvider.connection as? NETunnelProviderSession else { completion(nil);return }
        do { try session.sendProviderMessage(Data([2])) { data in
            DispatchQueue.main.async { completion(data.flatMap { String(data:$0,encoding:.utf8) }) }
        } } catch { completion(nil) }
    }

    private(set) var connectionSnapshotIssue: VPN013SnapshotIssue?
    private var effectiveAutomaticRevision: Data?
    private var effectiveAutomaticEnabled: Bool?
    private var automaticControl: VPN013LocalStatisticsRead?
    private let statisticsMessages = VPN013StatisticsMessageClient()
    private var lastStatisticsDiagnostic = ""
    private var lastStatisticsDiagnosticAt: TimeInterval = 0

    func applyAutomaticMode(_ enabled: Bool, completion: @escaping (Error?) -> Void) {
        guard status == .active, automaticControl == nil,
              let envelope = (tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope,
              let secret = try? PrivateTunnelStore.current.key(for: envelope.id),
              let credentials = try? VPN013LocalStatisticsCredentials.automaticControl(secret: secret,
                id: envelope.id, ciphertext: envelope.ciphertext),
              let read = try? VPN013LocalStatisticsRead(credentials: credentials, operation: enabled ? 10 : 9) else {
            completion(ProxyOperationError.system); return
        }
        if enabled { VPN013AutomaticIdentityHistory.rememberEnabled(id: envelope.id, ciphertext: envelope.ciphertext) }
        automaticControl = read
        read.start { result in
            self.automaticControl = nil
            guard self.status == .active,
                  (self.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope?.ciphertext == envelope.ciphertext,
                  (try? result.get()) == Data([1]) else { completion(ProxyOperationError.system); return }
            self.effectiveAutomaticRevision = envelope.ciphertext; self.effectiveAutomaticEnabled = enabled
            completion(nil)
        }
    }

    private func statisticsSender(_ session: NETunnelProviderSession) -> VPN013StatisticsMessageClient.Sender {
        { message, response in try session.sendProviderMessage(message, responseHandler: response) }
    }

    /// Refresh only the reference to an exact active encrypted profile. No save/start/stop.
    private func refreshStatisticsSession(completion: @escaping (VPN013StatisticsMessageClient.Sender?) -> Void) {
        guard let proto = tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
              let expected = proto.privateEnvelope, let provider = proto.providerBundleIdentifier,
              status == .active else { completion(nil); return }
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self = self, error == nil, self.status == .active,
                      let current = self.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
                      current.providerBundleIdentifier == provider,
                      current.privateEnvelope?.id == expected.id,
                      current.privateEnvelope?.ciphertext == expected.ciphertext else { completion(nil); return }
                let exact = (managers ?? []).filter { manager in
                    guard let value = manager.protocolConfiguration as? NETunnelProviderProtocol,
                          value.providerBundleIdentifier == provider,
                          value.privateEnvelope?.id == expected.id,
                          value.privateEnvelope?.ciphertext == expected.ciphertext else { return false }
                    return manager.connection.status == .connected || manager.connection.status == .reasserting
                }
                guard exact.count == 1, let session = exact[0].connection as? NETunnelProviderSession else {
                    completion(nil); return
                }
                completion(self.statisticsSender(session))
            }
        }
    }

    private func recordStatisticsDiagnostic() {
        let now = ProcessInfo.processInfo.systemUptime
        let value = statisticsMessages.diagnostic
        guard value != lastStatisticsDiagnostic || now - lastStatisticsDiagnosticAt >= 60 else { return }
        lastStatisticsDiagnostic = value; lastStatisticsDiagnosticAt = now
        // Only fixed stages and validated version/build numbers. No IDs, keys or endpoints.
        wg_log(.info, message: "Statistics RPC: " + value)
    }

    func getConnectionSnapshot(completion: @escaping (VPN013ConnectionSnapshot?) -> Void) {
        connectionSnapshotIssue = nil
        guard status == .active else { connectionSnapshotIssue = .notRunning; completion(nil); return }
        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-current-card-timeout") { return }
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-current-card-missing") { connectionSnapshotIssue = .emptyResponse; completion(nil); return }
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-current-card") {
            let config = automaticProfileForUpdates.flatMap { try? $0.validatedConfigurations().last } ?? tunnelConfiguration
            guard let config = config else { completion(nil); return }
            completion(VPN013ConnectionSnapshot(name: config.name ?? name,
                endpoints: config.peers.compactMap { $0.endpoint?.stringRepresentation },
                hosts: config.peers.compactMap { $0.endpoint.map { String(describing: $0.host) } },
                phase: "Симулятор · данные примера", revision: 0,
                statistics: .init(received: 2048, sent: 1024,
                    handshake: ProcessInfo.processInfo.arguments.contains("--vpn013-test-current-handshake") ? Date() : nil)))
            return
        }
        #endif
        let automatic = hasAutomaticRuntime
        let manualConfiguration = automatic ? nil : tunnelConfiguration
        let manualName = name
        let capturedEnvelope = (tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope
        let capturedProvider = (tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
        guard let session = tunnelProvider.connection as? NETunnelProviderSession else { connectionSnapshotIssue = .noSession; completion(nil); return }
        statisticsMessages.read(automatic: automatic, send: statisticsSender(session),
            refresh: { [weak self] done in
                guard let self = self else { done(nil); return }
                self.refreshStatisticsSession(completion: done)
            }, local: { operation, done in
                guard let envelope = capturedEnvelope,
                      let secret = try? PrivateTunnelStore.current.key(for: envelope.id),
                      let credentials = try? VPN013LocalStatisticsCredentials(secret: secret,
                        id: envelope.id, ciphertext: envelope.ciphertext),
                      let read = try? VPN013LocalStatisticsRead(credentials: credentials, operation: operation) else {
                    done(.failure(VPN013LocalStatisticsCredentials.Failure.unavailable)); return {}
                }
                read.start(completion: done)
                return { read.cancel() }
            }) { result in
                    self.recordStatisticsDiagnostic()
                    guard self.status == .active else { self.connectionSnapshotIssue = .notRunning; completion(nil); return }
                    guard self.hasAutomaticRuntime == automatic,
                          let current = self.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
                          capturedProvider != nil, current.providerBundleIdentifier == capturedProvider,
                          current.privateEnvelope?.id == capturedEnvelope?.id,
                          current.privateEnvelope?.ciphertext == capturedEnvelope?.ciphertext else {
                        self.connectionSnapshotIssue = .invalidResponse; completion(nil); return
                    }
                    let output: VPN013StatisticsMessageClient.Output
                    switch result {
                    case .failure(let issue): self.connectionSnapshotIssue = issue; completion(nil); return
                    case .success(let value): output = value
                    }
                    let data = output.data
                    if !automatic {
                        let parsed: VPN013RuntimeStatisticsReply?
                        switch output.format {
                        case .manual: parsed = (try? JSONDecoder().decode(VPN013ProviderStatistics.self, from: data))?.sample
                        case .legacyManual: parsed = try? JSONDecoder().decode(VPN013RuntimeStatisticsReply.self, from: data)
                        case .automatic: parsed = nil
                        }
                        guard let reply = parsed, reply.schema == 1 else {
                            self.connectionSnapshotIssue = .invalidResponse; completion(nil); return
                        }
                        guard reply.hasMeasurements, let statistics = reply.statistics else {
                            self.connectionSnapshotIssue = .runtimeUnavailable; completion(nil); return
                        }
                        guard let config = manualConfiguration else {
                            self.connectionSnapshotIssue = .invalidResponse; completion(nil); return
                        }
                        guard !self.hasAutomaticRuntime,
                              self.tunnelConfiguration?.asWgQuickConfig() == config.asWgQuickConfig(),
                              let expected = VPN013RuntimeStatisticsReply.identity(config.peers.map { $0.publicKey.hexKey }),
                              reply.peerIdentity == expected else {
                            self.connectionSnapshotIssue = .invalidResponse; completion(nil); return
                        }
                        let value = VPN013ConnectionSnapshot(name: manualName,
                            endpoints: config.peers.compactMap { $0.endpoint?.stringRepresentation },
                            hosts: config.peers.compactMap { $0.endpoint.map { String(describing: $0.host) } },
                            phase: nil, revision: 0, statistics: statistics)
                        guard value.isValid else { self.connectionSnapshotIssue = .invalidResponse; completion(nil); return }
                        self.connectionSnapshotIssue = nil; completion(value); return
                    }
                    guard let value = try? JSONDecoder().decode(VPN013ConnectionSnapshot.self, from: data), value.isValid
                    else { self.connectionSnapshotIssue = .invalidResponse; completion(nil); return }
                    if let enabled = value.automaticEnabled, let envelope = capturedEnvelope {
                        self.effectiveAutomaticRevision = envelope.ciphertext; self.effectiveAutomaticEnabled = enabled
                        if enabled { VPN013AutomaticIdentityHistory.rememberEnabled(id: envelope.id, ciphertext: envelope.ciphertext) }
                    }
                    self.connectionSnapshotIssue = nil
                    completion(value)
        }
    }

    var onDemandOption: ActivateOnDemandOption {
        return ActivateOnDemandOption(from: tunnelProvider)
    }

    #if os(macOS)
        var isTunnelAvailableToUser: Bool {
            return (tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerConfiguration?["UID"] as? uid_t == getuid()
        }
    #endif

    init(tunnel: NETunnelProviderManager) {
        name = tunnel.localizedDescription ?? "Unnamed"
        let status = TunnelStatus(from: tunnel.connection.status)
        self.status = status
        isActivateOnDemandEnabled = tunnel.isOnDemandEnabled && tunnel.isEnabled
        hasOnDemandRules = !(tunnel.onDemandRules ?? []).isEmpty
        tunnelProvider = tunnel
        super.init()
    }

    func getRuntimeTunnelConfiguration(
        completionHandler: @escaping ((TunnelConfiguration?) -> Void)
    ) {
        guard status != .inactive,
            let session = tunnelProvider.connection as? NETunnelProviderSession
        else {
            completionHandler(tunnelConfiguration)
            return
        }
        guard
            nil
                != (try? session.sendProviderMessage(
                    Data([UInt8(0)]),
                    responseHandler: {
                        guard self.status != .inactive, let data = $0,
                            let base = self.tunnelConfiguration,
                            let settings = String(data: data, encoding: .utf8)
                        else {
                            completionHandler(self.tunnelConfiguration)
                            return
                        }
                        do {
                            let runtime = try TunnelConfiguration(
                                fromUapiConfig: settings, basedOn: base)
                            completionHandler(runtime)
                        } catch {
                            var keys = Set<String>()
                            for line in settings.split(separator: "\n") {
                                if let equalsIndex = line.firstIndex(of: "=") {
                                    keys.insert(String(line[..<equalsIndex]))
                                }
                            }
                            let keyList = keys.sorted().joined(separator: ", ")
                            wg_log(
                                .error,
                                message: "Runtime config parse failed: \(error). Keys: [\(keyList)]"
                            )
                            completionHandler(self.tunnelConfiguration)
                        }
                    }))
        else {
            completionHandler(tunnelConfiguration)
            return
        }
    }

    func refreshStatus() {
        #if targetEnvironment(simulator) && DEBUG
        // These explicit UI fixtures have a model connection only. Simulator
        // foreground refresh must not replace that state with the inactive
        // NETunnelProviderSession stub. Button/row actions still update status.
        let arguments = ProcessInfo.processInfo.arguments
        if arguments.contains("--vpn013-test-start-current") || arguments.contains("--vpn013-test-power-connecting") {
            return
        }
        #endif
        if (status == .restarting)
            || (status == .waiting && tunnelProvider.connection.status == .disconnected)
        {
            return
        }
        let systemStatus = tunnelProvider.connection.status
        #if os(iOS)
            if systemStatus == .connected {
                status =
                    (handshakeState == .waiting) ? .activating : TunnelStatus(from: systemStatus)
            } else {
                if handshakeState != .idle {
                    cancelHandshakeMonitoring()
                }
                status = TunnelStatus(from: systemStatus)
            }
        #else
            status = TunnelStatus(from: systemStatus)
        #endif
    }

    fileprivate func startActivation(
        recursionCount: UInt = 0, lastError: Error? = nil,
        activationDelegate: TunnelsManagerActivationDelegate?
    ) {
        if recursionCount >= 8 {
            wg_log(
                .error,
                message: "startActivation: Failed after 8 attempts. Giving up with \(lastError!)")
            activationDelegate?.tunnelActivationAttemptFailed(
                tunnel: self, error: .failedBecauseOfTooManyErrors(lastSystemError: lastError!))
            return
        }

        wg_log(.debug, message: "startActivation: Entering (tunnel: \(name))")

        status = .activating  // Ensure that no other tunnel can attempt activation until this tunnel is done trying

        #if os(iOS)
            cancelHandshakeMonitoring()
        #endif

        guard tunnelProvider.isEnabled else {
            // In case the tunnel had gotten disabled, re-enable and save it,
            // then call this function again.
            wg_log(
                .debug, staticMessage: "startActivation: Tunnel is disabled. Re-enabling and saving"
            )
            tunnelProvider.isEnabled = true
            tunnelProvider.saveToPreferences { [weak self] error in
                guard let self = self else { return }
                if error != nil {
                    wg_log(.error, message: "Error saving tunnel after re-enabling: \(error!)")
                    activationDelegate?.tunnelActivationAttemptFailed(
                        tunnel: self, error: .failedWhileSaving(systemError: error!))
                    return
                }
                wg_log(
                    .debug,
                    staticMessage:
                        "startActivation: Tunnel saved after re-enabling, invoking startActivation")
                self.startActivation(
                    recursionCount: recursionCount + 1,
                    lastError: NEVPNError(NEVPNError.configurationUnknown),
                    activationDelegate: activationDelegate)
            }
            return
        }

        // Start the tunnel
        var activationStage = "prepare"
        do {
            wg_log(.debug, staticMessage: "startActivation: Starting tunnel")
            isAttemptingActivation = true
            let activationAttemptId = UUID().uuidString
            self.activationAttemptId = activationAttemptId
            var options: [String: NSObject] = ["activationAttemptId": activationAttemptId as NSString]
            #if os(iOS)
            if let proto = tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
               let envelope = proto.privateEnvelope {
                activationStage = "private-store-key"
                options[PrivateTunnelStore.startKey] = try PrivateTunnelStore.current.key(for: envelope.id) as NSData
            }
            #endif
            activationStage = "system-start"
            guard let session = tunnelProvider.connection as? NETunnelProviderSession else {
                throw NSError(domain: "VPN013.Activation", code: 1, userInfo: [NSLocalizedDescriptionKey: "Системный профиль VPN недоступен. Закройте и снова откройте VPN013, затем повторите подключение."])
            }
            try session.startTunnel(options: options)
            wg_log(.debug, staticMessage: "startActivation: Success")
            activationDelegate?.tunnelActivationAttemptSucceeded(tunnel: self)
        } catch let error {
            isAttemptingActivation = false
            let diagnostic = error as NSError
            let domain = String(diagnostic.domain.filter { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "_") }.prefix(96))
            wg_log(.error, message: "Activation failure: stage=\(activationStage) domain=\(domain) code=\(diagnostic.code)")
            guard let systemError = error as? NEVPNError else {
                wg_log(.error, message: "Failed to activate tunnel: Error: \(error)")
                status = .inactive
                activationDelegate?.tunnelActivationAttemptFailed(
                    tunnel: self, error: .failedWhileStarting(systemError: error))
                return
            }
            guard
                systemError.code == NEVPNError.configurationInvalid
                    || systemError.code == NEVPNError.configurationStale
            else {
                wg_log(.error, message: "Failed to activate tunnel: VPN Error: \(error)")
                status = .inactive
                activationDelegate?.tunnelActivationAttemptFailed(
                    tunnel: self, error: .failedWhileStarting(systemError: systemError))
                return
            }
            wg_log(
                .debug,
                staticMessage: "startActivation: Will reload tunnel and then try to start it.")
            tunnelProvider.loadFromPreferences { [weak self] error in
                guard let self = self else { return }
                if error != nil {
                    wg_log(.error, message: "startActivation: Error reloading tunnel: \(error!)")
                    self.status = .inactive
                    activationDelegate?.tunnelActivationAttemptFailed(
                        tunnel: self, error: .failedWhileLoading(systemError: systemError))
                    return
                }
                wg_log(
                    .debug,
                    staticMessage: "startActivation: Tunnel reloaded, invoking startActivation")
                self.startActivation(
                    recursionCount: recursionCount + 1, lastError: systemError,
                    activationDelegate: activationDelegate)
            }
        }
    }

    fileprivate func startDeactivation() {
        wg_log(.debug, message: "startDeactivation: Tunnel: \(name)")
        #if os(iOS)
            cancelHandshakeMonitoring()
        #endif
        (tunnelProvider.connection as? NETunnelProviderSession)?.stopTunnel()
    }

    deinit {
        #if os(iOS)
            cancelHandshakeMonitoring()
        #endif
    }
}

extension NETunnelProviderManager {
    private static var cachedConfigKey: UInt8 = 0

    var tunnelConfiguration: TunnelConfiguration? {
        if let cached = objc_getAssociatedObject(self, &NETunnelProviderManager.cachedConfigKey)
            as? TunnelConfiguration
        {
            return cached
        }
        let config = (protocolConfiguration as? NETunnelProviderProtocol)?.asTunnelConfiguration(
            called: localizedDescription)
        if config != nil {
            objc_setAssociatedObject(
                self, &NETunnelProviderManager.cachedConfigKey, config,
                objc_AssociationPolicy.OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        }
        return config
    }

    @discardableResult
    func setTunnelConfiguration(_ tunnelConfiguration: TunnelConfiguration) -> Bool {
        guard let next = NETunnelProviderProtocol(
            tunnelConfiguration: tunnelConfiguration, previouslyFrom: protocolConfiguration) else { return false }
        protocolConfiguration = next
        localizedDescription = tunnelConfiguration.name
        objc_setAssociatedObject(
            self, &NETunnelProviderManager.cachedConfigKey, tunnelConfiguration,
            objc_AssociationPolicy.OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        return true
    }

    func isEquivalentTo(_ tunnel: TunnelContainer) -> Bool {
        return localizedDescription == tunnel.name
            && tunnelConfiguration == tunnel.tunnelConfiguration
    }
}

#if os(iOS)
    extension TunnelContainer {
        func beginAwaitingFreshHandshakeIfNeeded(
            connectedAt: Date = Date(),
            completion: @escaping (Result<Date, TunnelHandshakeError>) -> Void
        ) {
            // The extension owns traffic checks across all thirteen candidates.
            if usesAutomaticSelection { handshakeState = .confirmed; completion(.success(connectedAt));return }
            #if targetEnvironment(simulator)
                completion(.success(connectedAt))
                return
            #endif

            switch handshakeState {
            case .confirmed:
                completion(.success(connectedAt))
                return
            case .waiting:
                handshakeCompletion = completion
                return
            default:
                break
            }

            handshakeCompletion = completion
            handshakeState = .waiting
            handshakeCutoffDate = connectedAt.addingTimeInterval(-HandshakeConstants.acceptanceSkew)
            wg_log(
                .debug,
                message:
                    "Handshake wait started: connectedAt=\(connectedAt) cutoff=\(handshakeCutoffDate ?? connectedAt) timeout=\(handshakeTimeoutInterval())"
            )
            scheduleHandshakeTimeout()
            registerForAppLifecycleNotifications()
            pollHandshakeFreshness()
        }

        func cancelHandshakeMonitoring(resetState: Bool = true) {
            cleanupHandshakeTimers()
            unregisterAppLifecycleNotifications()
            handshakeCompletion = nil
            handshakeCutoffDate = nil
            pendingTimeoutInterval = nil
            handshakePollInFlight = false
            if resetState {
                handshakeState = .idle
            }
        }

        private func handshakeTimeoutInterval() -> TimeInterval {
            return HandshakeConstants.defaultTimeout
        }

        private func pollHandshakeFreshness() {
            guard handshakeState == .waiting else { return }
            guard !handshakePollInFlight else { return }
            handshakePollInFlight = true

            getRuntimeTunnelConfiguration { [weak self] runtimeConfiguration in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    self.handshakePollInFlight = false
                    guard self.handshakeState == .waiting else { return }
                    guard let runtimeConfiguration = runtimeConfiguration,
                        let cutoffDate = self.handshakeCutoffDate
                    else {
                        wg_log(.debug, message: "Handshake poll: runtime config unavailable")
                        self.scheduleNextHandshakePoll()
                        return
                    }

                    let peerSummaries = runtimeConfiguration.peers.map { peer in
                        let hs = peer.lastHandshakeTime.map { String(describing: $0) } ?? "nil"
                        let rx = peer.rxBytes.map { String($0) } ?? "nil"
                        let tx = peer.txBytes.map { String($0) } ?? "nil"
                        return "hs=\(hs) rx=\(rx) tx=\(tx)"
                    }
                    let isFresh = HandshakeFreshnessEvaluator.containsFreshHandshake(
                        peers: runtimeConfiguration.peers, cutoffDate: cutoffDate)
                    wg_log(
                        .debug,
                        message:
                            "Handshake poll: cutoff=\(cutoffDate) peers=[\(peerSummaries.joined(separator: "; "))] fresh=\(isFresh)"
                    )

                    if isFresh {
                        self.finishHandshakeWaiting(result: .success(Date()))
                    } else {
                        self.scheduleNextHandshakePoll()
                    }
                }
            }
        }

        private func scheduleNextHandshakePoll() {
            guard handshakeState == .waiting else { return }
            handshakePollTimer?.invalidate()
            handshakePollTimer = Timer(
                timeInterval: HandshakeConstants.pollInterval, repeats: false
            ) { [weak self] _ in
                self?.pollHandshakeFreshness()
            }
            if let timer = handshakePollTimer {
                RunLoop.main.add(timer, forMode: .common)
            }
        }

        private func scheduleHandshakeTimeout(after interval: TimeInterval? = nil) {
            let timeout = interval ?? handshakeTimeoutInterval()
            handshakeTimeoutTimer?.invalidate()
            pendingTimeoutInterval = nil
            handshakeTimeoutDeadline = Date().addingTimeInterval(timeout)
            handshakeTimeoutTimer = Timer(timeInterval: timeout, repeats: false) { [weak self] _ in
                guard let self = self else { return }
                self.finishHandshakeWaiting(result: .failure(.timedOut(timeout)))
            }
            if let timer = handshakeTimeoutTimer {
                RunLoop.main.add(timer, forMode: .common)
            }
        }

        private func finishHandshakeWaiting(result: Result<Date, TunnelHandshakeError>) {
            cleanupHandshakeTimers()
            unregisterAppLifecycleNotifications()
            handshakeCutoffDate = nil
            switch result {
            case .success:
                handshakeState = .confirmed
                status = .active
                wg_log(.debug, message: "Handshake wait succeeded")
            case .failure(let error):
                handshakeState = .failed
                wg_log(.debug, message: "Handshake wait failed: \(error)")
            }
            let completion = handshakeCompletion
            handshakeCompletion = nil
            completion?(result)
        }

        private func cleanupHandshakeTimers() {
            handshakePollTimer?.invalidate()
            handshakeTimeoutTimer?.invalidate()
            handshakePollTimer = nil
            handshakeTimeoutTimer = nil
            handshakeTimeoutDeadline = nil
            pendingTimeoutInterval = nil
            handshakePollInFlight = false
        }

        private func registerForAppLifecycleNotifications() {
            guard appDidEnterBackgroundObserver == nil, appWillEnterForegroundObserver == nil else {
                return
            }
            let center = NotificationCenter.default
            appDidEnterBackgroundObserver = center.addObserver(
                forName: UIApplication.didEnterBackgroundNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                self?.applicationDidEnterBackground()
            }
            appWillEnterForegroundObserver = center.addObserver(
                forName: UIApplication.willEnterForegroundNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                self?.applicationWillEnterForeground()
            }
        }

        private func unregisterAppLifecycleNotifications() {
            let center = NotificationCenter.default
            if let observer = appDidEnterBackgroundObserver {
                center.removeObserver(observer)
            }
            if let observer = appWillEnterForegroundObserver {
                center.removeObserver(observer)
            }
            appDidEnterBackgroundObserver = nil
            appWillEnterForegroundObserver = nil
        }

        private func applicationDidEnterBackground() {
            guard handshakeState == .waiting else { return }
            if let deadline = handshakeTimeoutDeadline {
                pendingTimeoutInterval = max(0, deadline.timeIntervalSinceNow)
            }
            handshakePollTimer?.invalidate()
            handshakePollTimer = nil
            handshakeTimeoutTimer?.invalidate()
            handshakeTimeoutTimer = nil
        }

        private func applicationWillEnterForeground() {
            guard handshakeState == .waiting else { return }
            if let remaining = pendingTimeoutInterval {
                pendingTimeoutInterval = nil
                if remaining <= 0 {
                    finishHandshakeWaiting(result: .failure(.timedOut(handshakeTimeoutInterval())))
                    return
                }
                scheduleHandshakeTimeout(after: remaining)
            } else if let deadline = handshakeTimeoutDeadline {
                let remaining = max(0, deadline.timeIntervalSinceNow)
                if remaining <= 0 {
                    finishHandshakeWaiting(result: .failure(.timedOut(handshakeTimeoutInterval())))
                    return
                }
                scheduleHandshakeTimeout(after: remaining)
            } else {
                scheduleHandshakeTimeout()
            }
            pollHandshakeFreshness()
        }
    }
#endif

#if os(iOS)
struct WireGuardRoutingTarget {
    let tunnel: TunnelContainer
    let id: String
    let ciphertext: Data
    let sourceIdentity: Data
    let selection: ServiceRoutingSelection
}

extension TunnelsManager {
    func serviceRoutingTargets() throws -> [WireGuardRoutingTarget] {
        try tunnels.compactMap { tunnel in
            guard let proto = tunnel.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
                  let envelope = proto.privateEnvelope, let payload = try proto.privatePayload(), payload.proxy == nil else { return nil }
            let selection = try payload.serviceRouting.map { try JSONDecoder().decode(ServiceRoutingSelection.self, from: $0) } ?? ServiceRoutingSelection()
            _ = try ServiceRoutingCatalog.shared.get().resolve(selection)
            return WireGuardRoutingTarget(tunnel: tunnel, id: envelope.id, ciphertext: envelope.ciphertext, sourceIdentity: try serviceSourceIdentity(payload), selection: selection)
        }
    }

    func updateServiceRouting(_ targets: [WireGuardRoutingTarget], selection: ServiceRoutingSelection,
                              completion: @escaping (Error?) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !builtinPreparing, !CrossProtocolPlan.changingSources else { completion(ProxyOperationError.busy); return }
        do {
            let prepared = try prepareServiceRouting(targets, selection: selection)
            #if targetEnvironment(simulator)
            persistServiceRouting(prepared, completion: completion)
            #else
            _ = prepared // Preflight every target before invalidating recovery snapshots.
            CrossProtocolPlan.prepareMutation { result in
                switch result {
                case .failure(let error): completion(error)
                case .success(let permit):
                    do {
                        // Invalidation can alter encrypted recovery snapshots.
                        // Recheck ownership and the original configuration before resealing.
                        let current = try self.serviceRoutingTargets()
                        let refreshed = try targets.map { target -> WireGuardRoutingTarget in
                            guard let value = current.first(where: { $0.tunnel === target.tunnel && $0.id == target.id }),
                                  value.sourceIdentity == target.sourceIdentity else { throw ProxyOperationError.unreadable }
                            return value
                        }
                        let next = try self.prepareServiceRouting(refreshed, selection: selection)
                        self.persistServiceRouting(next) { error in permit.release(); completion(error) }
                    } catch { permit.release(); completion(error) }
                }
            }
            #endif
        } catch { completion(error) }
    }

    private func serviceSourceIdentity(_ payload: PrivateTunnelPayload) throws -> Data {
        var source = payload; source.crossProtocol = nil
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return Data(SHA256.hash(data: try encoder.encode(source)))
    }

    #if targetEnvironment(simulator) && DEBUG
    static func serviceRoutingFixture() -> String {
        let manager = TunnelsManager(tunnelProviders: MockTunnels.createMockTunnels())
        defer { for tunnel in manager.tunnels { (tunnel.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol)?.destroyConfigurationReference() } }
        do { return try manager.exerciseServiceRoutingFixture() } catch { preconditionFailure("WG service routing fixture failed") }
    }
    private func exerciseServiceRoutingFixture() throws -> String {
        let before = try serviceRoutingTargets(); precondition(before.count == 3)
        let originals = before.map { $0.tunnel.tunnelConfiguration!.asWgQuickConfig() }
        let catalog = try ServiceRoutingCatalog.shared.get()
        guard let facebook = catalog.groups.flatMap({ $0.services }).first(where: { $0.name == "Facebook" }) else { preconditionFailure("Missing pinned service") }
        var selection = ServiceRoutingSelection(); selection.setOnly(true); selection.toggle(facebook.id)
        func run(_ targets: [WireGuardRoutingTarget], _ value: ServiceRoutingSelection, failure: Bool = false) {
            var completed = false
            updateServiceRouting(targets, selection: value) { error in completed = true; precondition((error != nil) == failure) }
            precondition(completed)
        }
        let forged = WireGuardRoutingTarget(tunnel: before[2].tunnel, id: "unowned", ciphertext: before[2].ciphertext, sourceIdentity: before[2].sourceIdentity, selection: before[2].selection)
        run([before[0], forged], selection, failure: true)
        let afterForged = try serviceRoutingTargets()
        precondition(afterForged.map { $0.ciphertext } == before.map { $0.ciphertext })
        before[1].tunnel.status = .active
        run(Array(before.prefix(2)), selection, failure: true)
        precondition(before[1].tunnel.status == .active)
        before[1].tunnel.status = .inactive
        before[1].tunnel.tunnelProvider.isOnDemandEnabled = true
        run(Array(before.prefix(2)), selection, failure: true)
        before[1].tunnel.tunnelProvider.isOnDemandEnabled = false
        let afterGuards = try serviceRoutingTargets()
        precondition(afterGuards.map { $0.ciphertext } == before.map { $0.ciphertext })
        run(Array(before.prefix(2)), selection)
        let after = try serviceRoutingTargets()
        precondition(after[0].selection == selection && after[1].selection == selection && after[2].ciphertext == before[2].ciphertext)
        precondition(after.map { $0.tunnel.tunnelConfiguration!.asWgQuickConfig() } == originals)
        precondition(after.map { $0.id } == before.map { $0.id })
        guard let encodedProtocol = after[0].tunnel.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
              let encoded = try encodedProtocol.privatePayload() else { throw ProxyOperationError.unreadable }
        let identity = try encoded.serviceRoutingIdentity(); precondition(identity != nil)
        var remembered = selection; remembered.bypass = [facebook.id]
        var same = encoded; same.serviceRouting = try JSONEncoder().encode(remembered)
        let sameIdentity = try same.serviceRoutingIdentity(); precondition(sameIdentity == identity)
        var invalid = encoded; invalid.serviceRouting = Data("{\"mode\":\"only\",\"only\":[],\"bypass\":[]}".utf8)
        do { _ = try invalid.serviceRoutingIdentity(); preconditionFailure("Empty active policy accepted") } catch { }
        precondition(after.allSatisfy { $0.tunnel.tunnelProvider.isEnabled && !$0.tunnel.tunnelProvider.isOnDemandEnabled && $0.tunnel.status == .inactive })
        selection.setOnly(false); run(Array(after.prefix(2)), selection)
        let off = try serviceRoutingTargets()
        guard let offProtocol = off[0].tunnel.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
              let offPayload = try offProtocol.privatePayload() else { throw ProxyOperationError.unreadable }
        let offIdentity = try offPayload.serviceRoutingIdentity(); precondition(offIdentity == nil)
        precondition(off[0].selection.mode == .unchanged && off[0].selection.only == [facebook.id])
        precondition(off[2].ciphertext == before[2].ciphertext && off.map { $0.tunnel.tunnelConfiguration!.asWgQuickConfig() } == originals)
        return "WG bulk: ownership, active/on-demand guards, 2/3 scope, original configs, retained OFF choices passed"
    }
    #endif

    private func prepareServiceRouting(_ targets: [WireGuardRoutingTarget], selection: ServiceRoutingSelection) throws -> [(WireGuardRoutingTarget, NETunnelProviderProtocol)] {
        guard !targets.isEmpty, targets.count <= 512, Set(targets.map { $0.id }).count == targets.count else { throw ProxyOperationError.unreadable }
        let resolved = try ServiceRoutingCatalog.shared.get().resolveWireGuard(selection)
        let routing = try resolved.map { try WireGuardIPv4ServiceRouting(mode: $0.mode == .only ? .only : .bypass, networks: $0.networks) }
        let data = try JSONEncoder().encode(selection)
        guard data.count <= 32_768 else { throw ServiceCatalogError.invalid }
        return try targets.map { target in
            guard tunnels.contains(where: { $0 === target.tunnel }), target.tunnel.status == .inactive,
                  let proto = target.tunnel.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
                  proto.privateEnvelope?.id == target.id, proto.privateEnvelope?.ciphertext == target.ciphertext,
                  let next = proto.copy() as? NETunnelProviderProtocol, var payload = try proto.privatePayload(), payload.proxy == nil else { throw ProxyOperationError.stopFirst }
            guard !target.tunnel.tunnelProvider.isOnDemandEnabled else { throw ServiceCatalogError.automaticStart }
            let configurations = try payload.automatic?.validatedConfigurations() ?? [TunnelConfiguration(fromWgQuickConfig: payload.configuration, called: target.tunnel.name)]
            for configuration in configurations { try routing?.validate(configuration: configuration) }
            payload.serviceRouting = data; payload.builtinAutomatic = nil; payload.crossProtocol = nil
            let sealed = try PrivateTunnelStore.current.seal(JSONEncoder().encode(payload), reusing: target.id)
            var values = proto.providerConfiguration ?? [:]
            values[PrivateTunnelStore.idKey] = sealed.id; values[PrivateTunnelStore.dataKey] = sealed.ciphertext
            next.providerConfiguration = values
            return (target, next)
        }
    }

    private func persistServiceRouting(_ prepared: [(WireGuardRoutingTarget, NETunnelProviderProtocol)], completion: @escaping (Error?) -> Void) {
        builtinPreparing = true
        var attempted: [(TunnelContainer, NETunnelProviderProtocol)] = []
        var offset = 0
        func persist(_ tunnel: TunnelContainer, _ done: @escaping (Error?) -> Void) {
            #if targetEnvironment(simulator)
            done(nil)
            #else
            tunnel.tunnelProvider.saveToPreferences { error in DispatchQueue.main.async { done(error) } }
            #endif
        }
        func finish(_ error: Error?) { builtinPreparing = false; completion(error) }
        func rollback(_ original: Error) {
            var failed = false
            func next() {
                guard let (tunnel, old) = attempted.popLast() else { finish(failed ? ProxyOperationError.routingPartial : original); return }
                guard tunnel.status == .inactive, !tunnel.tunnelProvider.isOnDemandEnabled else { failed = true; next(); return }
                tunnel.tunnelProvider.protocolConfiguration = old
                persist(tunnel) { error in failed = failed || error != nil; next() }
            }
            next()
        }
        func next() {
            guard offset < prepared.count else { finish(nil); return }
            let (target, proto) = prepared[offset]; offset += 1
            guard tunnels.contains(where: { $0 === target.tunnel }), target.tunnel.status == .inactive, !target.tunnel.tunnelProvider.isOnDemandEnabled,
                  let old = target.tunnel.tunnelProvider.protocolConfiguration as? NETunnelProviderProtocol,
                  old.privateEnvelope?.id == target.id, old.privateEnvelope?.ciphertext == target.ciphertext else { rollback(ProxyOperationError.stopFirst); return }
            attempted.append((target.tunnel, old))
            target.tunnel.tunnelProvider.protocolConfiguration = proto
            persist(target.tunnel) { error in if let error = error { rollback(error) } else { next() } }
        }
        next()
    }
}
#endif
