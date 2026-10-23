// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import NetworkExtension

enum PacketTunnelProviderError: String, Error {
    case savedProtocolConfigurationIsInvalid
    case dnsResolutionFailure
    case couldNotStartBackend
    case couldNotDetermineFileDescriptor
    case couldNotSetNetworkSettings
}

extension NETunnelProviderProtocol {
    convenience init?(tunnelConfiguration: TunnelConfiguration, previouslyFrom old: NEVPNProtocol? = nil) {
        self.init()

        guard let name = tunnelConfiguration.name else { return nil }
        guard let appId = Bundle.main.bundleIdentifier else { return nil }
        providerBundleIdentifier = "\(appId).network-extension"
        #if os(iOS)
        PrivateTunnelStore.lastError = nil
        do {
            let previous = old as? NETunnelProviderProtocol
            let automatic = try previous?.privatePayload()?.automatic
            let payload = PrivateTunnelPayload(version: 1, configuration: tunnelConfiguration.asWgQuickConfig(), automatic: automatic)
            let sealed = try PrivateTunnelStore.current.seal(JSONEncoder().encode(payload), reusing: previous?.privateEnvelope?.id)
            providerConfiguration = [PrivateTunnelStore.idKey: sealed.id, PrivateTunnelStore.dataKey: sealed.ciphertext]
        } catch { PrivateTunnelStore.lastError = error; return nil }
        #else
        passwordReference = Keychain.makeReference(containing: tunnelConfiguration.asWgQuickConfig(), called: name, previouslyReferencedBy: old?.passwordReference)
        #if targetEnvironment(simulator)
        providerConfiguration = ["WgQuickConfig":tunnelConfiguration.asWgQuickConfig()]
        #else
        if passwordReference == nil {
            return nil
        }
        #endif
        #if os(macOS)
        providerConfiguration = ["UID": getuid()]
        #endif
        #endif

        let endpoints = tunnelConfiguration.peers.compactMap { $0.endpoint }
        if endpoints.count == 1 {
            serverAddress = endpoints[0].stringRepresentation
        } else if endpoints.isEmpty {
            serverAddress = "Unspecified"
        } else {
            serverAddress = "Multiple endpoints"
        }
    }

    func asTunnelConfiguration(called name: String? = nil) -> TunnelConfiguration? {
        #if os(iOS)
        if privateEnvelope != nil {
            guard let payload = try? privatePayload() else { return nil }
            return try? TunnelConfiguration(fromWgQuickConfig: payload.configuration, called: name)
        }
        #endif
        if let passwordReference = passwordReference,
            let config = Keychain.openReference(called: passwordReference) {
            return try? TunnelConfiguration(fromWgQuickConfig: config, called: name)
        }
        if let oldConfig = providerConfiguration?["WgQuickConfig"] as? String {
            return try? TunnelConfiguration(fromWgQuickConfig: oldConfig, called: name)
        }
        return nil
    }

    func destroyConfigurationReference() {
        #if os(iOS)
        if let envelope = privateEnvelope { PrivateTunnelStore.current.remove(envelope.id); return }
        #endif
        if let ref = providerConfiguration?[AutoTunnelProfile.referenceKey] as? Data { Keychain.deleteReference(called:ref) }
        guard let ref = passwordReference else { return }
        Keychain.deleteReference(called: ref)
    }

    func verifyConfigurationReference() -> Bool {
        #if os(iOS)
        if privateEnvelope != nil { return (try? privatePayload()) != nil }
        #endif
        guard let ref = passwordReference else { return false }
        return Keychain.verifyReference(called: ref)
    }

    @discardableResult
    func migrateConfigurationIfNeeded(called name: String) -> Bool {
        #if os(iOS)
        if privateEnvelope != nil { return false }
        #endif
        /* This is how we did things before we switched to putting items
         * in the keychain. But it's still useful to keep the migration
         * around so that .mobileconfig files are easier.
         */
        if let oldConfig = providerConfiguration?["WgQuickConfig"] as? String {
            #if os(iOS)
            do {
                let value = PrivateTunnelPayload(version: 1, configuration: oldConfig, automatic: nil)
                let envelope = try PrivateTunnelStore.current.seal(JSONEncoder().encode(value))
                providerConfiguration = [PrivateTunnelStore.idKey: envelope.id, PrivateTunnelStore.dataKey: envelope.ciphertext]
                passwordReference = nil
                return true
            } catch { PrivateTunnelStore.lastError = error; return false }
            #else
            #if os(macOS)
            providerConfiguration = ["UID": getuid()]
            #elseif os(iOS)
            providerConfiguration = nil
            #else
            #error("Unimplemented")
            #endif
            guard passwordReference == nil else { return true }
            wg_log(.info, message: "Migrating tunnel configuration '\(name)'")
            passwordReference = Keychain.makeReference(containing: oldConfig, called: name)
            return true
            #endif
        }
        #if os(macOS)
        if passwordReference != nil && providerConfiguration?["UID"] == nil && verifyConfigurationReference() {
            providerConfiguration = ["UID": getuid()]
            return true
        }
        #elseif os(iOS)
        /* Update the stored reference from the old iOS 14 one to the canonical iOS 15 one.
         * The iOS 14 ones are 96 bits, while the iOS 15 ones are 160 bits. We do this so
         * that we can have fast set exclusion in deleteReferences safely. */
        if passwordReference != nil && passwordReference!.count == 12 {
            var result: CFTypeRef?
            let ret = SecItemCopyMatching([kSecValuePersistentRef: passwordReference!,
                                           kSecReturnPersistentRef: true] as CFDictionary,
                                           &result)
            if ret != errSecSuccess || result == nil {
                return false
            }
            guard let newReference = result as? Data else { return false }
            if !newReference.elementsEqual(passwordReference!) {
                wg_log(.info, message: "Migrating iOS 14-style keychain reference to iOS 15-style keychain reference for '\(name)'")
                passwordReference = newReference
                return true
            }
        }
        #endif
        return false
    }
}
