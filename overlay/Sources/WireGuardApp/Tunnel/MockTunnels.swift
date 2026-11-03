// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import NetworkExtension

// Creates mock tunnels for the iOS Simulator.

#if targetEnvironment(simulator)
class MockTunnels {
    static let tunnelNames = ["Беларусь", "Германия", "Германия 2", "Грузия", "Испания", "Нидерланды", "Польша", "Польша 2", "США", "Турция", "Финляндия", "Финляндия 2", "Швеция"]
    static let address = "192.168.%d.%d/32"
    static let dnsServers = ["8.8.8.8", "8.8.4.4"]
    static var endpoint: String {
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-ping-loopback") { return "127.0.0.1:4444" }
        #endif
        return "192.0.2.1:4444"
    }
    static let allowedIPs = "0.0.0.0/0"

    #if DEBUG
    // Synthetic keys and expected bytes exist only in the simulator process.
    private static var expectedArchiveConfigs: [String: String] = [:]

    static func sharedArchiveFixture() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("vpn013-import-fixture-" + UUID().uuidString + ".zip")
        expectedArchiveConfigs = [:]
        let files = try createMockTunnels().enumerated().flatMap { index, manager -> [(fileName: String, contents: Data)] in
            guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  let config = tunnelProtocol.asTunnelConfiguration(called: manager.localizedDescription) else { return [] }
            var raw = config.asWgQuickConfig()
            let classic = "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 16\nS2 = 16\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"
            let generation2 = "S3 = 16\nS4 = 16\nI1 = <b 0x00>\nI2 = <r 4>\nI3 = <b 0x01>\nI4 = <r 8>\nI5 = <b 0x02>\n"
            let legacy15 = "I2 = <b 0xA><c><t><wt 1>\nJ1 = <b 0xBB><r 4>\nJ3 = <b 0xCC>\nITime = 30\n"
            let trailerFlag = index % 8 == 3 ? "true" : "false"
            let generation31 = "HeaderProtectionKey = \(PrivateKey().base64Key)\nContentPaddingAddition = 0\nRekeyAfterTime = 120\nRekeyTimeout = 5\nRejectAfterTime = 180\nKeepaliveTimeout = 10\nMaxHandshakeAttempts = 20\nRandomTrailers = \(trailerFlag)\nDisableCookies = false\n"
            let extras: String
            switch index % 5 {
            case 0: extras = index == 0 || index == 5 ? "I1 = <t>\n" : "" // Two choices plus a plain WireGuard example.
            case 1: extras = classic // Classic AmneziaWG.
            case 2: extras = classic + generation2 // AmneziaWG 2.x.
            case 3: extras = classic + generation2 + generation31 // AmneziaWG 3.1 fields.
            default: extras = classic + legacy15 // AmneziaWG 1.5 legacy tags and J/ITime.
            }
            raw = raw.replacingOccurrences(of: "[Peer]", with: extras + "\n[Peer]")
            let parsed = try TunnelConfiguration(fromWgQuickConfig: raw, called: config.name!)
            let canonical = parsed.asWgQuickConfig()
            // Compare every requested option to its parsed/exported value, rather
            // than comparing two parsings which could both drop the same field.
            precondition(extras.split(separator: "\n").allSatisfy { canonical.contains(String($0) + "\n") })
            if index % 5 == 4 {
                precondition(parsed.interface.legacyAWG15 && parsed.interface.legacyJunk1 == "<b 0xBB><r 4>" && parsed.interface.legacyIntervalSeconds == 30)
                precondition(!TunnelImporter.needsVersionChoice(parsed))
                let reparsed = try TunnelConfiguration(fromWgQuickConfig: canonical)
                precondition(reparsed.interface == parsed.interface)
                let edit = TunnelViewModel(tunnelConfiguration: parsed)
                edit.interfaceData[.name] = "Synthetic edited profile"
                switch edit.save() {
                case .saved(let edited):
                    precondition(edited.interface.legacyAWG15 && edited.interface.legacyJunk1 == parsed.interface.legacyJunk1 && edited.interface.legacyIntervalSeconds == 30)
                case .error: preconditionFailure("Editing a legacy profile lost valid settings")
                }
            }
            if index == 0 {
                let ambiguous = raw
                let oddHex = raw.replacingOccurrences(of: "I1 = <t>", with: "I1 = <b 0xF>")
                let oddHexConfig = try TunnelConfiguration(fromWgQuickConfig: oddHex, called: "Synthetic legacy hex")
                precondition(oddHexConfig.interface.legacyAWG15 && oddHexConfig.interface.specialJunk1 == "<b 0xF>")
                precondition(!TunnelImporter.needsVersionChoice(oddHexConfig))
                let oddHexRoundTrip = try TunnelConfiguration(fromWgQuickConfig: oddHexConfig.asWgQuickConfig())
                precondition(oddHexRoundTrip.interface == oddHexConfig.interface)
                let modern = try TunnelConfiguration(fromWgQuickConfig: ambiguous, called: "Synthetic choice")
                let explicitlyLegacy = try TunnelConfiguration(fromWgQuickConfig: "# VPN013-AmneziaWG = 1.5\n" + ambiguous)
                precondition(!modern.interface.legacyAWG15 && explicitlyLegacy.interface.legacyAWG15)
                precondition(TunnelImporter.needsVersionChoice(modern) && !TunnelImporter.needsVersionChoice(explicitlyLegacy))
                let reparsedLegacy = try TunnelConfiguration(fromWgQuickConfig: explicitlyLegacy.asWgQuickConfig())
                precondition(reparsedLegacy.interface.legacyAWG15)
                let choice = TunnelViewModel(tunnelConfiguration: modern)
                choice.interfaceData[.legacyAWGVersion] = "1.5"
                switch choice.save() {
                case .saved(let selected):
                    precondition(selected.interface.legacyAWG15 && selected.asWgQuickConfig().contains("# VPN013-AmneziaWG = 1.5"))
                case .error: preconditionFailure("Explicit legacy version choice was rejected")
                }
            }
            expectedArchiveConfigs[config.name!] = canonical
            return ["Android", "iPhone"].map { platform in
                let contents = index == 1 && platform == "iPhone" ? Data([0xff, 0xfe]) + raw.data(using: .utf16LittleEndian)! : Data(raw.utf8)
                return (fileName: platform + "/" + config.name! + ".conf", contents: contents)
            }
        }
        try ZipArchive.archive(inputs: files, to: url)
        return url
    }

    static func verifyImportedArchive(_ configurations: [TunnelConfiguration?]) {
        let parsed = configurations.compactMap { $0 }
        precondition(expectedArchiveConfigs.count == 13 && parsed.count == 13)
        for config in parsed {
            guard let name = config.name, let expected = expectedArchiveConfigs[name] else { preconditionFailure("Unknown synthetic archive item") }
            precondition(config.asWgQuickConfig() == expected, "Synthetic archive options changed during import")
        }
        precondition(Set(parsed.compactMap { $0.name }).count == expectedArchiveConfigs.count)
    }
    #endif

    static func createMockTunnels() -> [NETunnelProviderManager] {
        var names = tunnelNames
        #if DEBUG
        let arguments = ProcessInfo.processInfo.arguments
        if let index = arguments.firstIndex(of: "--vpn013-test-count"), arguments.indices.contains(index + 1),
           let count = Int(arguments[index + 1]), (0...40).contains(count) {
            names = (0..<count).map { "Личный сервер \($0 + 1)" }
        }
        if arguments.contains("--vpn013-test-ordering") { names = ["!Первый", "0 Server", "Дом"] }
        #endif
        let managers = names.map { tunnelName -> NETunnelProviderManager in

            var interface = InterfaceConfiguration(privateKey: PrivateKey())
            interface.addresses = [IPAddressRange(from: String(format: address, Int.random(in: 1 ... 10), Int.random(in: 1 ... 254)))!]
            interface.dns = dnsServers.map { DNSServer(from: $0)! }

            var peer = PeerConfiguration(publicKey: PrivateKey().publicKey)
            peer.endpoint = Endpoint(from: endpoint)
            peer.allowedIPs = [IPAddressRange(from: allowedIPs)!]

            let tunnelConfiguration = TunnelConfiguration(name: tunnelName, interface: interface, peers: [peer])

            let tunnelProviderManager = NETunnelProviderManager()
            tunnelProviderManager.protocolConfiguration = NETunnelProviderProtocol(tunnelConfiguration: tunnelConfiguration)
            tunnelProviderManager.localizedDescription = tunnelConfiguration.name
            tunnelProviderManager.isEnabled = true

            return tunnelProviderManager
        }
        #if DEBUG && targetEnvironment(simulator)
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-ownership-corrupt") {
            ClientOwnershipFixture.seedCorruptRegistryOnce(managers)
        }
        #endif
        return managers
    }
}
#endif
