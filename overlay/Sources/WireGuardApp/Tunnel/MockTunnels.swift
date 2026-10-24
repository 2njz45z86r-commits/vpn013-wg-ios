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
    static func sharedArchiveFixture() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("vpn013-import-fixture-" + UUID().uuidString + ".zip")
        let files = createMockTunnels().flatMap { manager -> [(fileName: String, contents: Data)] in
            let config = (manager.protocolConfiguration as! NETunnelProviderProtocol).asTunnelConfiguration(called: manager.localizedDescription)!
            var raw = config.asWgQuickConfig()
            let extras = "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nS3 = 0\nS4 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nI1 = <b 0x00>\nHeaderProtectionKey = \(PrivateKey().base64Key)\nContentPaddingAddition = 0\nRekeyAfterTime = 120\nRekeyTimeout = 5\nRejectAfterTime = 180\nKeepaliveTimeout = 10\nMaxHandshakeAttempts = 20\nRandomTrailers = false\nDisableCookies = false\n"
            raw = raw.replacingOccurrences(of: "[Peer]", with: extras + "\n[Peer]")
            return ["Android", "iPhone"].map { (fileName: $0 + "/" + config.name! + ".conf", contents: Data(raw.utf8)) }
        }
        try ZipArchive.archive(inputs: files, to: url)
        return url
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
        return names.map { tunnelName -> NETunnelProviderManager in

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
    }
}
#endif
