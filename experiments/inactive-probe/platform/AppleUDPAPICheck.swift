// SPDX-License-Identifier: MIT
// SDK type-check spike only; this is not linked into a shipped VPN extension.
import Foundation
import NetworkExtension

enum R013UDPAPICheck {
    // Apple documents nil from: as primary physical-interface binding.
    // A nil bridge return must fail closed; never substitute a default socket.
    static func physical(provider: NEPacketTunnelProvider, host: String,
                         port: UInt16) -> NWUDPSession? {
        guard port > 0 else { return nil }
        let endpoint = NWHostEndpoint(hostname: host, port: String(port))
        return provider.createUDPSession(to: endpoint, from: nil) as NWUDPSession?
    }

    // A future equal-method baseline can explicitly use the active virtual
    // interface. This is a different API from the physical candidate transport.
    static func activeTunnel(provider: NEPacketTunnelProvider, host: String,
                             port: UInt16) -> NWUDPSession? {
        guard port > 0 else { return nil }
        let endpoint = NWHostEndpoint(hostname: host, port: String(port))
        return provider.createUDPSessionThroughTunnel(to: endpoint, from: nil) as NWUDPSession?
    }

    static func read(session: NWUDPSession,
                     handler: @escaping ([Data]?, Error?) -> Void) {
        session.setReadHandler(handler, maxDatagrams: 1)
    }

    // Real adapters must serialize writes and wait for this completion.
    static func write(session: NWUDPSession, packet: Data,
                      completion: @escaping (Error?) -> Void) {
        session.writeDatagram(packet, completionHandler: completion)
    }

    static func close(session: NWUDPSession) {
        session.cancel()
    }
}
