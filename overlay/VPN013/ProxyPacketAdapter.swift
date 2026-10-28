// SPDX-License-Identifier: MIT
import Foundation
import NetworkExtension
import Darwin

/// Main-queue lifecycle, serialized core ownership. A cancelled resolution cannot
/// apply settings or start a core after stop. Never owns the system TUN fd.
final class ProxySinglePacketAdapter {
    private weak var provider: NEPacketTunnelProvider?
    private let engine = DispatchQueue(label: "VPN013.proxy.engine")
    private let resolver = DispatchQueue(label: "VPN013.proxy.resolve")
    private var epoch = UUID()
    private var deadline: DispatchWorkItem?
    private var pending: ((Error?) -> Void)?
    init(provider: NEPacketTunnelProvider) { self.provider = provider }

    func start(_ payload: ProxyTunnelPayload, resolvedHost: String? = nil, excludedHosts: [String] = [], completion: @escaping (Error?) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        let token = UUID(); epoch = token; pending = completion
        let timeout = DispatchWorkItem { [weak self] in
            guard let self = self, self.epoch == token, self.pending != nil else { return }
            self.epoch = UUID(); self.finish(PacketTunnelProviderError.dnsResolutionFailure)
            self.engine.async { R013ProxyStop() }
        }
        deadline = timeout; DispatchQueue.main.asyncAfter(deadline: .now() + 15, execute: timeout)
        resolver.async { [weak self] in
            let host = resolvedHost ?? Self.resolve(payload.profile.host, port: payload.profile.port)
            DispatchQueue.main.async {
                guard let self = self, self.epoch == token else { return }
                guard let host = host, let provider = self.provider else { self.finish(PacketTunnelProviderError.dnsResolutionFailure); return }
                let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: host)
                let ipv4 = NEIPv4Settings(addresses: ["172.29.13.2"], subnetMasks: ["255.255.255.255"])
                ipv4.includedRoutes = [NEIPv4Route.default()]
                let physicalHosts = Set(excludedHosts + [host])
                ipv4.excludedRoutes = physicalHosts.filter { !$0.contains(":") }.map { NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255") }
                settings.ipv4Settings = ipv4
                let ipv6 = NEIPv6Settings(addresses: ["fd13:13:13::2"], networkPrefixLengths: [128])
                ipv6.includedRoutes = [NEIPv6Route.default()]
                ipv6.excludedRoutes = physicalHosts.filter { $0.contains(":") }.map { NEIPv6Route(destinationAddress: $0, networkPrefixLength: 128) }
                settings.ipv6Settings = ipv6
                let dns = NEDNSSettings(servers: ["1.1.1.1", "2606:4700:4700::1111"]); dns.matchDomains = [""]
                settings.dnsSettings = dns; settings.mtu = 1280
                provider.setTunnelNetworkSettings(settings) { error in
                    DispatchQueue.main.async {
                        guard self.epoch == token else { return }
                        guard error == nil else { self.finish(PacketTunnelProviderError.couldNotSetNetworkSettings); return }
                        guard let fd = Self.tunnelDescriptor(), let data = try? payload.configuration(resolvedHost: host),
                              let configuration = String(data: data, encoding: .utf8) else {
                            self.finish(PacketTunnelProviderError.couldNotDetermineFileDescriptor); return
                        }
                        self.engine.async {
                            let valid = DispatchQueue.main.sync { self.epoch == token }
                            guard valid else { return }
                            let result = configuration.withCString { R013ProxyStart($0, fd) }
                            DispatchQueue.main.async {
                                guard self.epoch == token else { return }
                                self.finish(result == 0 ? nil : PacketTunnelProviderError.couldNotStartBackend)
                            }
                        }
                    }
                }
            }
        }
    }
    private func finish(_ error: Error?) {
        deadline?.cancel(); deadline = nil
        let callback = pending; pending = nil; callback?(error)
    }
    func stop(completion: @escaping () -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        epoch = UUID(); finish(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled))
        engine.async { R013ProxyStop(); DispatchQueue.main.async(execute: completion) }
    }
    func statistics(completion: @escaping (Data?) -> Void) {
        engine.async {
            guard let raw = R013ProxyStatistics() else { completion(nil); return }
            let bytes = Data(bytes: raw, count: strlen(raw)); free(raw)
            completion(bytes.count < 1024 ? bytes : nil)
        }
    }
    static func resolve(_ host: String, port: UInt16) -> String? {
        var hints = addrinfo(); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else { return nil }
        defer { freeaddrinfo(first) }
        var current: UnsafeMutablePointer<addrinfo>? = first
        while let item = current {
            var name = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if (item.pointee.ai_family == AF_INET || item.pointee.ai_family == AF_INET6),
               getnameinfo(item.pointee.ai_addr, item.pointee.ai_addrlen, &name, socklen_t(name.count), nil, 0, NI_NUMERICHOST) == 0 { return String(cString: name) }
            current = item.pointee.ai_next
        }
        return nil
    }
    private static func tunnelDescriptor() -> Int32? {
        // Same documented utun-control identification used by the incumbent adapter.
        for fd: Int32 in 0...1024 {
            var name = [CChar](repeating: 0, count: Int(IFNAMSIZ)); var length = socklen_t(name.count)
            if getsockopt(fd, 2, 2, &name, &length) == 0 && String(cString: name).hasPrefix("utun") { return fd }
        }
        return nil
    }
}
