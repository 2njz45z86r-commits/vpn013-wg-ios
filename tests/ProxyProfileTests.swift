// SPDX-License-Identifier: MIT
// Synthetic keys only; no network requests, system VPN or real subscriptions.
import Foundation

@main struct ProxyProfileTests {
    static func main() throws {
        var checks = 0
        func check(_ condition: @autoclosure () -> Bool, _ label: String) {
            precondition(condition(), label); checks += 1
        }
        func rejects(_ label: String, _ body: () throws -> Void) {
            do { try body(); preconditionFailure("Accepted invalid input: " + label) }
            catch { checks += 1 }
        }
        let key = Data((0..<32).map { UInt8($0) }).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let uri = "vless://00000000-0000-4000-8000-000000000001@de3.example.invalid:443?type=tcp&security=reality&sni=www.example.invalid&pbk=\(key)&sid=01234567&fp=chrome&flow=xtls-rprx-vision#Germany"
        for kind in [VPN013ConnectionKind.happ, .incy, .blacktemple] {
            let profiles = try ProxyImport.profiles(Data(uri.utf8), source: kind)
            check(profiles.count == 1 && profiles[0].source == kind, "separate source selection")
            check(profiles[0].host == "de3.example.invalid", "domain retained")
            check(profiles[0].name == "Germany", "display name")
            let outbound = try profiles[0].outbound(resolvedHost: "192.0.2.10")
            let stream = outbound["streamSettings"] as! [String: Any]
            let reality = stream["realitySettings"] as! [String: Any]
            check(reality["serverName"] as? String == "www.example.invalid", "original SNI retained with resolved endpoint")
            check(outbound["protocol"] as? String == "vless", "actual common transport")
            let encoded = try JSONEncoder().encode(profiles[0])
            let restored = try JSONDecoder().decode(ProxyProfile.self, from: encoded)
            check(restored == profiles[0], "lossless typed private persistence input")
        }
        let original = try ProxyImport.profiles(Data(uri.utf8), source: .blacktemple)
        let subscription = Data((uri + "\n" + uri.replacingOccurrences(of: "#Germany", with: "#Finland")).utf8).base64EncodedData()
        let decoded = try ProxyImport.profiles(subscription, source: .blacktemple)
        check(decoded.count == 2 && decoded[1].name == "Finland", "standard BlackTemple subscription")
        let config: [String: Any] = ["meta": ["serverName": "JSON server"], "outbounds": [try original[0].outbound()],
            "inbounds": [["listen": "0.0.0.0", "port": 12345, "protocol": "socks"]], "log": ["access": "/tmp/untrusted.log"], "api": ["tag": "external-api"]]
        let json = try JSONSerialization.data(withJSONObject: [config])
        let jsonProfiles = try ProxyImport.profiles(json, source: .incy)
        check(jsonProfiles.count == 1 && jsonProfiles[0].name == "JSON server", "Xray JSON subscription")
        let rebuilt = try JSONSerialization.data(withJSONObject: jsonProfiles[0].outbound())
        let rebuiltText = String(decoding: rebuilt, as: UTF8.self)
        check(!rebuiltText.contains("0.0.0.0") && !rebuiltText.contains("untrusted.log") && !rebuiltText.contains("external-api"), "incoming executable configuration discarded")
        rejects("AWG source") { _ = try ProxyImport.profiles(Data(uri.utf8), source: .amneziawg) }
        rejects("duplicate query") { _ = try ProxyProfile.fromURI(uri.replacingOccurrences(of: "#Germany", with: "&security=tls#Germany"), source: .happ) }
        rejects("insecure TLS") { _ = try ProxyProfile.fromURI(uri.replacingOccurrences(of: "#Germany", with: "&allowInsecure=1#Germany"), source: .happ) }
        rejects("invalid key") { _ = try ProxyProfile.fromURI(uri.replacingOccurrences(of: key, with: "short"), source: .happ) }
        rejects("odd short ID") { _ = try ProxyProfile.fromURI(uri.replacingOccurrences(of: "sid=01234567", with: "sid=123"), source: .happ) }
        rejects("unsupported transport") { _ = try ProxyProfile.fromURI(uri.replacingOccurrences(of: "type=tcp", with: "type=kcp"), source: .happ) }
        rejects("invalid port") { _ = try ProxyProfile.fromURI(uri.replacingOccurrences(of: ":443?", with: ":65536?"), source: .happ) }
        rejects("control in name") { _ = try ProxyProfile.fromURI(uri.replacingOccurrences(of: "#Germany", with: "#bad%0Aname"), source: .happ) }
        rejects("opaque proprietary key") { _ = try ProxyImport.profiles(Data("not-a-standard-profile!".utf8), source: .blacktemple) }
        rejects("oversized input") { _ = try ProxyImport.profiles(Data(repeating: 0, count: ProxyImport.maximumBytes + 1), source: .happ) }
        rejects("too many profiles") { _ = try ProxyImport.profiles(Data(Array(repeating: uri, count: 101).joined(separator: "\n").utf8), source: .happ) }
        var invalid = original[0]
        invalid.host = "not a domain"
        rejects("invalid saved host") { try invalid.validate() }
        invalid = original[0]; invalid.transport = .ws
        rejects("flow on WebSocket") { try invalid.validate() }
        let websocket = "vless://00000000-0000-4000-8000-000000000001@ws.example.invalid:443?type=ws&security=tls&sni=ws.example.invalid&path=%2Fsocket&host=cdn.example.invalid#WebSocket"
        let ws = try ProxyProfile.fromURI(websocket, source: .happ)
        check(ws.transport == .ws && ws.path == "/socket" && ws.httpHost == "cdn.example.invalid", "WebSocket fields")
        let http = try ProxyProfile.fromURI(websocket.replacingOccurrences(of: "type=ws", with: "type=xhttp&mode=packet-up"), source: .incy)
        check(http.transport == .xhttp && http.mode == "packet-up", "XHTTP fields")
        let grpc = try ProxyProfile.fromURI("vless://00000000-0000-4000-8000-000000000001@grpc.example.invalid:443?type=grpc&security=tls&sni=grpc.example.invalid&serviceName=vpn_service-1&authority=front.example.invalid:8443&mode=multi&alpn=h2,http%2F1.1#GRPC", source: .incy)
        let grpcStream = try grpc.outbound()["streamSettings"] as! [String: Any]
        let grpcSettings = grpcStream["grpcSettings"] as! [String: Any]
        check(grpcSettings["authority"] as? String == "front.example.invalid:8443" && grpcSettings["multiMode"] as? Bool == true, "gRPC authority and multi mode preserved")
        let grpcRoundTrip = try ProxyProfile.fromOutbound(grpc.outbound(), name: grpc.name, source: .incy)
        check(grpcRoundTrip.grpcAuthority == grpc.grpcAuthority && grpcRoundTrip.grpcMultiMode == true, "gRPC JSON round trip")
        let download: [String: Any] = ["address": "download.example.invalid", "port": 8443, "network": "xhttp", "security": "tls", "tlsSettings": ["serverName": "download-sni.example.invalid", "allowInsecure": false], "xhttpSettings": ["path": "/down", "mode": "stream-up"]]
        let extra: [String: Any] = ["downloadSettings": download, "scMaxEachPostBytes": "1000000-2000000", "noGRPCHeader": true, "xmux": ["maxConcurrency": "16-32", "hKeepAlivePeriod": -1]]
        var components = URLComponents(string: websocket.replacingOccurrences(of: "type=ws", with: "type=xhttp&mode=stream-up"))!
        components.queryItems! += [URLQueryItem(name: "extra", value: String(data: try JSONSerialization.data(withJSONObject: extra), encoding: .utf8)!), URLQueryItem(name: "x_padding_bytes", value: "100-1000")]
        let split = try ProxyProfile.fromURI(components.string!, source: .happ)
        check(split.additionalEndpoints.count == 1 && split.additionalEndpoints[0].host == "download.example.invalid", "secondary endpoint retained")
        let splitPayload = ProxyTunnelPayload(profile: split)
        rejects("unresolved secondary endpoint") { _ = try splitPayload.configuration(resolvedHost: "192.0.2.10") }
        let splitJSON = try JSONSerialization.jsonObject(with: splitPayload.configuration(resolvedHost: "192.0.2.10", additionalHosts: ["download.example.invalid": "192.0.2.11"])) as! [String: Any]
        let splitOutbound = (splitJSON["outbounds"] as! [[String: Any]])[0]
        let splitHTTP = (splitOutbound["streamSettings"] as! [String: Any])["xhttpSettings"] as! [String: Any]
        let resolvedDownload = splitHTTP["downloadSettings"] as! [String: Any]
        check(splitHTTP["noGRPCHeader"] as? Bool == true && splitHTTP["xPaddingBytes"] as? String == "100-1000" && splitHTTP["scMaxEachPostBytes"] as? String == "1000000-2000000", "full XHTTP extras preserved")
        check(resolvedDownload["address"] as? String == "192.0.2.11" && (resolvedDownload["tlsSettings"] as! [String: Any])["serverName"] as? String == "download-sni.example.invalid", "bootstrap numeric download address preserves SNI")
        let splitRoundTrip = try ProxyProfile.fromOutbound(split.outbound(), name: split.name, source: .happ)
        check(splitRoundTrip.xhttpOptions == split.xhttpOptions, "canonical XHTTP JSON round trip")
        var unsafe = download; unsafe["tlsSettings"] = ["allowInsecure": true]
        var unsafeExtra = extra; unsafeExtra["downloadSettings"] = unsafe
        var unsafeURL = components
        unsafeURL.queryItems = components.queryItems!.filter { $0.name != "extra" } + [URLQueryItem(name: "extra", value: String(data: try JSONSerialization.data(withJSONObject: unsafeExtra), encoding: .utf8)!)]
        rejects("nested TLS bypass") { _ = try ProxyProfile.fromURI(unsafeURL.string!, source: .happ) }
        var noNetwork = download; noNetwork.removeValue(forKey: "network"); unsafeExtra["downloadSettings"] = noNetwork
        unsafeURL.queryItems = components.queryItems!.filter { $0.name != "extra" } + [URLQueryItem(name: "extra", value: String(data: try JSONSerialization.data(withJSONObject: unsafeExtra), encoding: .utf8)!)]
        rejects("invalid pinned-core download transport cannot panic extension") { _ = try ProxyProfile.fromURI(unsafeURL.string!, source: .happ) }
        rejects("unknown transport options not silently dropped") { _ = try ProxyProfile.fromURI(websocket.replacingOccurrences(of: "#WebSocket", with: "&unknownTransport=1#WebSocket"), source: .happ) }
        rejects("TLS bypass alias") { _ = try ProxyProfile.fromURI(websocket.replacingOccurrences(of: "#WebSocket", with: "&skipTLSVerify=true#WebSocket"), source: .happ) }
        var excessive = components
        excessive.queryItems = components.queryItems!.filter { !["extra", "x_padding_bytes"].contains($0.name) } + [URLQueryItem(name: "x_padding_bytes", value: "1000000000")]
        rejects("provider cannot request gigabyte padding") { _ = try ProxyProfile.fromURI(excessive.string!, source: .happ) }
        let ipv6 = try ProxyProfile.fromURI(websocket.replacingOccurrences(of: "@ws.example.invalid:443", with: "@[2001:db8::1]:443"), source: .happ)
        check(ipv6.endpoint == "[2001:db8::1]:443", "IPv6 endpoint")
        let normalizedDomain = try ProxyRoutingPolicy.domain(" YouTube.COM ")
        check(normalizedDomain == "youtube.com", "normalized domain")
        check(ProxyRoutingPolicy.validNetwork("192.0.2.0/24"), "IPv4 CIDR")
        check(ProxyRoutingPolicy.validNetwork("2001:db8::/32"), "IPv6 CIDR")
        check(!ProxyRoutingPolicy.validNetwork("192.0.2.0/33"), "invalid IPv4 prefix")
        check(!ProxyRoutingPolicy.validNetwork("2001:db8::/129"), "invalid IPv6 prefix")
        rejects("URL as domain") { _ = try ProxyRoutingPolicy.domain("https://example.invalid/path") }
        rejects("empty only-selected") { try ProxyRoutingPolicy(mode: .only).validate() }
        let payload = ProxyTunnelPayload(profile: ws, routing: ProxyRoutingPolicy(mode: .bypass, domains: ["example.invalid"], networks: ["192.0.2.0/24"]))
        let generated = try JSONSerialization.jsonObject(with: payload.configuration(resolvedHost: "192.0.2.10")) as! [String: Any]
        let rules = (generated["routing"] as! [String: Any])["rules"] as! [[String: Any]]
        check(rules[0]["port"] as? String == "53", "DNS traffic stays protected")
        check(rules[1]["outboundTag"] as? String == "vpn013-direct", "domain bypass")
        check(rules[2]["ip"] as? [String] == ["192.0.2.0/24"], "CIDR bypass")
        let restoredPayload = try JSONDecoder().decode(ProxyTunnelPayload.self, from: JSONEncoder().encode(payload))
        check(restoredPayload == payload, "lossless typed routing persistence")
        rejects("unresolved core host") { _ = try payload.configuration(resolvedHost: "example.invalid") }
        var automatic = payload; var reserve = ws; reserve.id = UUID(); reserve.name = "Reserve"; reserve.host = "reserve.example.invalid"
        automatic.automaticCandidates = [ws, reserve]; automatic.automaticEnabled = true
        try automatic.validate()
        check(automatic.selecting(1).profile.host == "reserve.example.invalid", "automatic selected identity retains original domain")
        let automaticRestored = try JSONDecoder().decode(ProxyTunnelPayload.self, from: JSONEncoder().encode(automatic))
        check(automaticRestored == automatic, "encrypted auto payload input round trip")
        var crossSection = reserve; crossSection.source = .blacktemple
        automatic.automaticCandidates = [ws, crossSection]
        rejects("cross-section automatic candidate") { try automatic.validate() }
        automatic.automaticCandidates = [ws, ws]
        rejects("duplicate automatic candidate identity") { try automatic.validate() }
        automatic.automaticCandidates = [reserve]
        rejects("missing automatic anchor") { try automatic.validate() }
        let probe = try JSONSerialization.jsonObject(with: payload.probeConfiguration(resolvedHost: "192.0.2.10")) as! [String: Any]
        check((probe["inbounds"] as? [Any])?.isEmpty == true && (probe["outbounds"] as? [Any])?.count == 1 && probe["routing"] == nil, "probe has no listener or direct routing fallback")
        rejects("unresolved probe endpoint") { _ = try payload.probeConfiguration(resolvedHost: "example.invalid") }
        let sources: [ProxyProfile] = (0..<19).map { index in
            var value = ws; value.id = UUID(); value.host = "node\(index).example.invalid"; value.name = "Country \(index)"; return value
        }
        var full: [[String: Any]] = []
        let padding = String(repeating: "x", count: 520_000)
        for selected in 0..<18 {
            let order = [selected] + sources.indices.filter { $0 != selected }
            let nodes = try order.enumerated().map { position, index -> [String: Any] in
                var node = try sources[index].outbound(); node["tag"] = position == 0 ? sources[index].name : "backup-\(index)"; return node
            }
            full.append(["remarks": sources[selected].name, "inbounds": [], "outbounds": nodes,
                         "routing": ["ignored": padding, "quoted": "brace } bracket ] quote \" escape \\" ]])
        }
        var auto = full[0]; auto["remarks"] = "Авто · минимальный пинг"
        auto["outbounds"] = try sources.enumerated().map { index, profile -> [String: Any] in var node = try profile.outbound(); node["tag"] = "auto-\(index)"; return node }
        full.insert(auto, at: 0)
        let large = try JSONSerialization.data(withJSONObject: full)
        check(large.count > 1_048_576 && large.count < ProxyImport.maximumBytes, "actual full-subscription size category")
        let largeImported = try ProxyImport.profiles(large, source: .happ)
        check(largeImported.count == 18, "361 outbound copies become the eighteen visible server entries")
        check(Set(largeImported.map { $0.name }) == Set(sources.prefix(18).map { $0.name }), "prefer each primary's original display name")
        check(!largeImported.contains(where: { $0.host == sources[18].host }), "internal reserve not invented as another visible server")
        let single = try JSONSerialization.data(withJSONObject: auto)
        let standalone = try ProxyImport.profiles(single, source: .happ)
        check(standalone.count == 19, "standalone multi-outbound config retains distinct candidates")
        rejects("JSON trailing comma") { _ = try ProxyImport.profiles(Data("[{\"outbounds\":[]},]".utf8), source: .happ) }
        rejects("JSON trailing content") { _ = try ProxyImport.profiles(Data("[{\"outbounds\":[]}]garbage".utf8), source: .happ) }
        var oversizedObject = auto; oversizedObject["ignored"] = String(repeating: "x", count: 1_048_577)
        let oversizedJSON = try JSONSerialization.data(withJSONObject: [oversizedObject])
        rejects("single JSON object resource bound") { _ = try ProxyImport.profiles(oversizedJSON, source: .happ) }
        print("Proxy profile checks: \(checks) passed (synthetic imports only; no VPN traffic claim)")
    }
}
