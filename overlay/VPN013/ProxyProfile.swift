// SPDX-License-Identifier: MIT
import Foundation
import CoreFoundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

enum VPN013ConnectionKind: String, Codable, CaseIterable {
    case happ, incy, amneziawg, blacktemple
    var title: String {
        switch self {
        case .happ: return "Happ"
        case .incy: return "INCY"
        case .amneziawg: return "AmneziaWG"
        case .blacktemple: return "BlackTemple"
        }
    }
}

enum ProxyProfileError: LocalizedError {
    case invalid, unsupported, tooLarge, configurationTooLarge, insecureTLS
    var errorDescription: String? {
        switch self {
        case .invalid: return "Конфигурация повреждена. Проверьте исходную ссылку или файл."
        case .unsupported: return "Этот формат пока не поддерживается. Нужна ссылка VLESS, совместимая подписка или JSON Xray."
        case .tooLarge: return "Подписка слишком велика. Допустимо до 32 МБ исходного текста и 100 разных серверов."
        case .configurationTooLarge: return "Один JSON-профиль превышает 1 МБ. Используйте совместимую VLESS-подписку этого провайдера."
        case .insecureTLS: return "Конфигурация отключает проверку TLS. Импортируйте вариант с действующим сертификатом."
        }
    }
}

/// Only fields required by a VLESS outbound are retained. Incoming listeners,
/// log paths, remote geodata, API listeners and arbitrary JSON are never executed.
struct ProxyProfile: Codable, Equatable {
    enum Transport: String, Codable { case tcp, ws, grpc, xhttp }
    enum Security: String, Codable { case tls, reality }
    var id: UUID
    var source: VPN013ConnectionKind
    var name: String
    var host: String
    var port: UInt16
    var userID: UUID
    var transport: Transport
    var security: Security
    var serverName: String
    var fingerprint: String
    var publicKey: String
    var shortID: String
    var flow: String
    var path: String
    var httpHost: String
    var serviceName: String
    var mode: String
    var alpn: [String]
    var grpcAuthority: String? = nil
    var grpcMultiMode: Bool? = nil
    var realitySpiderX: String? = nil
    var realityVerify: String? = nil
    // Canonical allow-listed transport fields only; never a raw executable config.
    var xhttpOptions: Data? = nil

    var endpoint: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    func validate() throws {
        func clean(_ value: String, maximum: Int) -> Bool {
            value.utf8.count <= maximum && !value.contains { $0.isNewline || $0.asciiValue.map { $0 < 32 || $0 == 127 } == true }
        }
        func validHost(_ value: String) -> Bool {
            if value.contains(":") {
                var address = in6_addr()
                return inet_pton(AF_INET6, value, &address) == 1
            }
            let labels = value.split(separator: ".", omittingEmptySubsequences: false)
            return !labels.isEmpty && labels.allSatisfy { label in
                (1...63).contains(label.utf8.count) && label.first != "-" && label.last != "-" &&
                label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
            }
        }
        guard source != .amneziawg, !name.isEmpty, clean(name, maximum: 128),
              !host.isEmpty, clean(host, maximum: 253), !host.contains(where: { $0.isWhitespace }),
              validHost(host), port > 0,
              clean(serverName, maximum: 253), !serverName.isEmpty,
              validHost(serverName),
              clean(path, maximum: 2048), clean(httpHost, maximum: 253),
              clean(serviceName, maximum: 256), clean(mode, maximum: 32),
              ["", "chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"].contains(fingerprint),
              ["", "xtls-rprx-vision"].contains(flow),
              flow.isEmpty || transport == .tcp,
              ["", "auto", "packet-up", "stream-up", "stream-one"].contains(mode),
              clean(grpcAuthority ?? "", maximum: 253), clean(realitySpiderX ?? "", maximum: 2048),
              clean(realityVerify ?? "", maximum: 4096),
              security != .reality || transport != .ws,
              alpn.count <= 4, alpn.allSatisfy({ ["h2", "http/1.1", "h3"].contains($0) })
        else { throw ProxyProfileError.invalid }
        if let options = xhttpOptions {
            guard transport == .xhttp, options.count <= 16_384,
                  let object = try JSONSerialization.jsonObject(with: options) as? [String: Any] else { throw ProxyProfileError.invalid }
            _ = try ProxyXHTTPOptions.canonical(object, source: source)
        }
        if security == .reality {
            let normalized = publicKey.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            guard normalized.count == 43, Data(base64Encoded: normalized + "=")?.count == 32,
                  shortID.count <= 16, shortID.count % 2 == 0,
                  shortID.allSatisfy({ $0.isASCII && $0.isHexDigit }) else { throw ProxyProfileError.invalid }
        }
    }

    static func fromURI(_ text: String, source: VPN013ConnectionKind) throws -> Self {
        guard text.utf8.count <= 16_384, let uri = URLComponents(string: text),
              uri.scheme?.lowercased() == "vless", let host = uri.host, let rawPort = uri.port,
              (1...65535).contains(rawPort), let rawID = uri.user, let userID = UUID(uuidString: rawID),
              uri.password == nil else { throw ProxyProfileError.invalid }
        var query = [String: String]()
        for item in uri.queryItems ?? [] {
            guard query[item.name] == nil, let value = item.value else { throw ProxyProfileError.invalid }
            query[item.name] = value
        }
        guard query["encryption", default: "none"] == "none" else { throw ProxyProfileError.unsupported }
        for key in ["allowInsecure", "insecure", "skipTLSVerify"] where query[key] != nil {
            guard ["0", "false"].contains(query[key]!.lowercased()) else { throw ProxyProfileError.insecureTLS }
        }
        let transportName = query["type", default: "tcp"].lowercased()
        guard let transport = Transport(rawValue: transportName == "raw" ? "tcp" : transportName == "splithttp" ? "xhttp" : transportName),
              let security = Security(rawValue: query["security", default: "tls"].lowercased()) else { throw ProxyProfileError.unsupported }
        let common: Set<String> = ["type", "security", "encryption", "flow", "sni", "fp", "pbk", "sid", "spx", "pqv", "alpn", "allowInsecure", "insecure", "skipTLSVerify", "support-x25519mlkem768"]
        let specific: Set<String> = transport == .xhttp ? ["host", "path", "mode", "extra", "x_padding_bytes"] : transport == .grpc ? ["serviceName", "authority", "mode"] : transport == .ws ? ["host", "path"] : ["headerType"]
        guard Set(query.keys).isSubset(of: common.union(specific)), query["headerType", default: "none"] == "none",
              transport != .grpc || ["", "gun", "multi"].contains(query["mode", default: "gun"]) else { throw ProxyProfileError.unsupported }
        var value = Self(id: UUID(), source: source, name: uri.fragment.flatMap { $0.isEmpty ? nil : $0 } ?? source.title,
            host: host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), port: UInt16(rawPort), userID: userID,
            transport: transport, security: security, serverName: query["sni"] ?? host,
            fingerprint: query["fp", default: security == .reality ? "chrome" : ""],
            publicKey: query["pbk", default: ""], shortID: query["sid", default: ""], flow: query["flow", default: ""],
            path: query["path", default: "/"], httpHost: query["host", default: ""],
            serviceName: query["serviceName", default: ""], mode: transport == .xhttp ? query["mode", default: "auto"] : "auto",
            alpn: query["alpn"].map { $0.split(separator: ",").map(String.init) } ?? [])
        value.grpcAuthority = query["authority"]; value.grpcMultiMode = transport == .grpc ? query["mode"] == "multi" : nil
        value.realitySpiderX = query["spx"]; value.realityVerify = query["pqv"]
        if transport == .xhttp {
            var extra: [String: Any] = [:]
            if let raw = query["extra"], !raw.isEmpty {
                guard let data = raw.data(using: .utf8), data.count <= 16_384,
                      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw ProxyProfileError.invalid }
                extra = object
            }
            // Issuers may repeat these transport fields inside `extra`. Move
            // them into the typed model, accepting only an identical alias.
            // Unknown extras still pass through the strict option validator.
            for field in ["mode", "path", "host"] {
                if let supplied = extra[field] {
                    guard let text = supplied as? String,
                          query[field] == nil || query[field] == text else { throw ProxyProfileError.invalid }
                    switch field {
                    case "mode": value.mode = text
                    case "path": value.path = text
                    default: value.httpHost = text
                    }
                    extra.removeValue(forKey: field)
                }
            }
            if let padding = query["x_padding_bytes"] {
                if let existing = extra["xPaddingBytes"] {
                    let sameText = (existing as? String) == padding
                    let number = existing as? NSNumber
                    let sameInteger = number.map {
                        CFGetTypeID($0) != CFBooleanGetTypeID() && $0.doubleValue.isFinite &&
                        $0.doubleValue >= 0 && $0.doubleValue <= 65_536 &&
                        $0.doubleValue.rounded(.towardZero) == $0.doubleValue && String($0.intValue) == padding
                    } ?? false
                    guard sameText || sameInteger else { throw ProxyProfileError.invalid }
                }
                extra["xPaddingBytes"] = padding
            }
            value.xhttpOptions = try ProxyXHTTPOptions.canonical(extra, source: source)
        }
        try value.validate()
        return value
    }

    static func fromOutbound(_ outbound: [String: Any], name: String, source: VPN013ConnectionKind) throws -> Self {
        guard outbound["protocol"] as? String == "vless",
              let settings = outbound["settings"] as? [String: Any], let nodes = settings["vnext"] as? [[String: Any]], nodes.count == 1,
              let node = nodes.first, let host = node["address"] as? String,
              let numericPort = node["port"] as? NSNumber, CFGetTypeID(numericPort) != CFBooleanGetTypeID(),
              numericPort.doubleValue.rounded(.towardZero) == numericPort.doubleValue,
              (1...65535).contains(numericPort.intValue),
              let users = node["users"] as? [[String: Any]], users.count == 1, let user = users.first,
              let rawID = user["id"] as? String, let userID = UUID(uuidString: rawID),
              (user["encryption"] as? String ?? "none") == "none",
              let stream = outbound["streamSettings"] as? [String: Any],
              let security = Security(rawValue: stream["security"] as? String ?? "tls") else { throw ProxyProfileError.invalid }
        let network = stream["network"] as? String ?? "tcp"
        let streamKeys: Set<String> = ["network", "security", "tlsSettings", "realitySettings", "xhttpSettings", "splithttpSettings", "wsSettings", "grpcSettings", "tcpSettings", "rawSettings"]
        guard Set(stream.keys).isSubset(of: streamKeys) else { throw ProxyProfileError.unsupported }
        guard let transport = Transport(rawValue: network == "raw" ? "tcp" : network == "splithttp" ? "xhttp" : network) else { throw ProxyProfileError.unsupported }
        let tls = stream[security == .reality ? "realitySettings" : "tlsSettings"] as? [String: Any] ?? [:]
        for key in ["allowInsecure", "insecure", "skipTLSVerify"] where tls[key] != nil {
            guard let value = tls[key] as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID(), !value.boolValue else { throw ProxyProfileError.insecureTLS }
        }
        let tlsKeys: Set<String> = ["serverName", "fingerprint", "alpn", "allowInsecure", "insecure", "skipTLSVerify", "publicKey", "shortId", "spiderX", "mldsa65Verify", "show"]
        guard Set(tls.keys).isSubset(of: tlsKeys), tls["show"] as? Bool != true else { throw ProxyProfileError.unsupported }
        for key in ["serverName", "fingerprint", "publicKey", "shortId", "spiderX", "mldsa65Verify"] where tls[key] != nil {
            guard tls[key] is String else { throw ProxyProfileError.invalid }
        }
        if let alpn = tls["alpn"] { guard alpn is [String] else { throw ProxyProfileError.invalid } }
        let http = stream[transport == .xhttp ? (stream["xhttpSettings"] != nil ? "xhttpSettings" : "splithttpSettings") : "wsSettings"] as? [String: Any] ?? [:]
        let headers = http["headers"] as? [String: String] ?? [:]
        if transport == .ws {
            guard Set(http.keys).isSubset(of: ["path", "headers"]), Set(headers.keys).isSubset(of: ["Host"]) else { throw ProxyProfileError.unsupported }
        }
        if let tcp = (stream["tcpSettings"] ?? stream["rawSettings"]) as? [String: Any], !tcp.isEmpty {
            guard Set(tcp.keys) == ["header"], let header = tcp["header"] as? [String: Any],
                  Set(header.keys) == ["type"], header["type"] as? String == "none" else { throw ProxyProfileError.unsupported }
        }
        let grpc = stream["grpcSettings"] as? [String: Any] ?? [:]
        guard Set(grpc.keys).isSubset(of: ["serviceName", "authority", "multiMode"]) else { throw ProxyProfileError.unsupported }
        if let flag = grpc["multiMode"] { guard let number = flag as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { throw ProxyProfileError.invalid } }
        var value = Self(id: UUID(), source: source, name: name, host: host, port: UInt16(numericPort.intValue), userID: userID,
            transport: transport, security: security, serverName: tls["serverName"] as? String ?? host,
            fingerprint: tls["fingerprint"] as? String ?? (security == .reality ? "chrome" : ""),
            publicKey: tls["publicKey"] as? String ?? "", shortID: tls["shortId"] as? String ?? "",
            flow: user["flow"] as? String ?? "", path: http["path"] as? String ?? "/",
            httpHost: http["host"] as? String ?? headers["Host"] ?? "", serviceName: grpc["serviceName"] as? String ?? "",
            mode: http["mode"] as? String ?? "auto", alpn: tls["alpn"] as? [String] ?? [])
        value.grpcAuthority = grpc["authority"] as? String; value.grpcMultiMode = grpc["multiMode"] as? Bool
        value.realitySpiderX = tls["spiderX"] as? String; value.realityVerify = tls["mldsa65Verify"] as? String
        if transport == .xhttp {
            var extra = http; extra.removeValue(forKey: "path"); extra.removeValue(forKey: "host"); extra.removeValue(forKey: "mode")
            value.xhttpOptions = try ProxyXHTTPOptions.canonical(extra, source: source)
        }
        try value.validate()
        return value
    }

    var additionalEndpoints: [(host: String, port: UInt16)] {
        guard let data = xhttpOptions, let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let download = object["downloadSettings"] as? [String: Any], let host = download["address"] as? String,
              let port = download["port"] as? NSNumber else { return [] }
        return [(host, UInt16(port.intValue))]
    }

    func outbound(resolvedHost: String? = nil, additionalHosts: [String: String] = [:]) throws -> [String: Any] {
        try validate()
        var user: [String: Any] = ["id": userID.uuidString.lowercased(), "encryption": "none", "level": 0]
        if !flow.isEmpty { user["flow"] = flow }
        var stream: [String: Any] = ["network": transport.rawValue, "security": security.rawValue]
        var tls: [String: Any] = ["serverName": serverName]
        if !fingerprint.isEmpty { tls["fingerprint"] = fingerprint }
        if !alpn.isEmpty { tls["alpn"] = alpn }
        if security == .reality {
            tls["publicKey"] = publicKey; tls["shortId"] = shortID
            if let value = realitySpiderX { tls["spiderX"] = value }
            if let value = realityVerify { tls["mldsa65Verify"] = value }
        }
        stream[security == .reality ? "realitySettings" : "tlsSettings"] = tls
        if transport == .ws { stream["wsSettings"] = ["path": path, "headers": httpHost.isEmpty ? [:] : ["Host": httpHost]] }
        if transport == .xhttp {
            var http: [String: Any] = [:]
            if let data = xhttpOptions {
                guard let decoded = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw ProxyProfileError.invalid }
                http = decoded
            }
            if var download = http["downloadSettings"] as? [String: Any], let original = download["address"] as? String {
                if let resolved = additionalHosts[original] { download["address"] = resolved }
                http["downloadSettings"] = download
            }
            http["path"] = path; http["host"] = httpHost; http["mode"] = mode; stream["xhttpSettings"] = http
        }
        if transport == .grpc {
            var grpc: [String: Any] = ["serviceName": serviceName]
            if let authority = grpcAuthority { grpc["authority"] = authority }
            if let multi = grpcMultiMode { grpc["multiMode"] = multi }; stream["grpcSettings"] = grpc
        }
        return ["tag": "vpn013-proxy", "protocol": "vless", "settings": ["vnext": [["address": resolvedHost ?? host, "port": Int(port), "users": [user]]]], "streamSettings": stream]
    }
}

/// Matches the pinned core's XHTTP client options. Unknown fields are refused,
/// not silently removed. Secondary downloads must explicitly select XHTTP:
/// the pinned core otherwise defaults to TCP, whose settings cannot be used by
/// its XHTTP download dialer. Nested downloads and local socket options are not
/// accepted. All executable configuration is rebuilt from validated fields.
private enum ProxyXHTTPOptions {
    static func canonical(_ input: [String: Any], source: VPN013ConnectionKind) throws -> Data {
        let ranges: Set<String> = ["xPaddingBytes", "scMaxEachPostBytes", "scMinPostsIntervalMs", "scStreamUpServerSecs", "uplinkChunkSize", "sessionIDLength"]
        let flags: Set<String> = ["noGRPCHeader", "noSSEHeader", "xPaddingObfsMode"]
        let numbers: Set<String> = ["scMaxBufferedPosts", "serverMaxHeaderBytes"]
        let strings: Set<String> = ["xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod", "uplinkHTTPMethod", "sessionIDPlacement", "sessionIDKey", "seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey", "sessionIDTable"]
        let permitted = ranges.union(flags).union(numbers).union(strings).union(["headers", "xmux", "downloadSettings"])
        guard Set(input.keys).isSubset(of: permitted) else { throw ProxyProfileError.unsupported }
        func integer(_ value: Any, signed: Bool = false) -> Bool {
            guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return false }
            return number.doubleValue.isFinite && number.doubleValue.rounded(.towardZero) == number.doubleValue && number.doubleValue >= (signed ? -1 : 0) && number.doubleValue <= 1_000_000_000
        }
        func range(_ value: Any) -> Bool {
            if integer(value) { return true }
            guard let string = value as? String, string.count <= 24 else { return false }
            let parts = string.split(separator: "-", omittingEmptySubsequences: false)
            guard (1...2).contains(parts.count), let first = Int(parts[0]), first >= 0, first <= 1_000_000_000,
                  String(first) == parts[0] else { return false }
            if parts.count == 1 { return true }
            guard let last = Int(parts[1]) else { return false }; return last >= first && last <= 1_000_000_000 && String(last) == parts[1]
        }
        func upper(_ value: Any) -> Int {
            if let number = value as? NSNumber { return number.intValue }
            return Int((value as? String ?? "").split(separator: "-").last ?? "") ?? Int.max
        }
        // Local iOS resource budgets, not changes to provider settings. Refuse
        // excessive requests rather than clamping them or allocating unbounded
        // padding, buffers or simultaneous connections in the VPN extension.
        let limits = ["xPaddingBytes": 65_536, "scMaxEachPostBytes": 4_194_304, "scMinPostsIntervalMs": 600_000,
                      "scStreamUpServerSecs": 3_600, "uplinkChunkSize": 1_048_576, "sessionIDLength": 256,
                      "scMaxBufferedPosts": 256, "serverMaxHeaderBytes": 65_536]
        func text(_ value: Any, maximum: Int = 1024) -> Bool {
            guard let value = value as? String else { return false }
            return value.utf8.count <= maximum && !value.contains { $0.isNewline || $0.asciiValue.map { $0 < 32 || $0 == 127 } == true }
        }
        for (key, value) in input {
            if ranges.contains(key) { guard range(value) else { throw ProxyProfileError.invalid } }
            if numbers.contains(key) { guard integer(value) else { throw ProxyProfileError.invalid } }
            if let limit = limits[key], upper(value) > limit { throw ProxyProfileError.unsupported }
            if strings.contains(key) { guard text(value) else { throw ProxyProfileError.invalid } }
            if flags.contains(key) { guard let value = value as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { throw ProxyProfileError.invalid } }
            if key == "headers" {
                guard let headers = value as? [String: String], headers.count <= 32,
                      headers.allSatisfy({ text($0.key, maximum: 128) && !$0.key.isEmpty && $0.key.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "-_.".contains($0)) } && $0.key.lowercased() != "host" && text($0.value) }) else { throw ProxyProfileError.invalid }
            }
            if key == "xmux" {
                guard let xmux = value as? [String: Any], Set(xmux.keys).isSubset(of: ["maxConcurrency", "maxConnections", "cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs", "hKeepAlivePeriod"]),
                      xmux.allSatisfy({ $0.key == "hKeepAlivePeriod" ? integer($0.value, signed: true) : range($0.value) }) else { throw ProxyProfileError.invalid }
                let budgets = ["maxConcurrency": 1_024, "maxConnections": 64, "cMaxReuseTimes": 1_000_000, "hMaxRequestTimes": 1_000_000, "hMaxReusableSecs": 86_400, "hKeepAlivePeriod": 3_600]
                guard xmux.allSatisfy({ upper($0.value) <= (budgets[$0.key] ?? 0) }) else { throw ProxyProfileError.unsupported }
            }
        }
        if let post = input["scMaxEachPostBytes"] {
            let lower = (post as? NSNumber)?.intValue ?? Int((post as? String ?? "").split(separator: "-").first ?? "") ?? 0
            guard lower > 0 else { throw ProxyProfileError.invalid }
        }
        var result = input
        if let raw = input["downloadSettings"] {
            guard var download = raw as? [String: Any],
                  Set(download.keys).isSubset(of: ["address", "port", "network", "security", "tlsSettings", "realitySettings", "xhttpSettings", "splithttpSettings"]),
                  let host = download["address"] as? String, let port = download["port"] as? NSNumber,
                  ["xhttp", "splithttp"].contains(download["network"] as? String ?? ""),
                  let http = (download["xhttpSettings"] ?? download["splithttpSettings"]) as? [String: Any],
                  http["downloadSettings"] == nil, http["extra"] == nil else { throw ProxyProfileError.unsupported }
            download.removeValue(forKey: "address"); download.removeValue(forKey: "port")
            let outbound: [String: Any] = ["protocol": "vless", "settings": ["vnext": [["address": host, "port": port, "users": [["id": "00000000-0000-4000-8000-000000000001", "encryption": "none"]]]]], "streamSettings": download]
            let profile = try ProxyProfile.fromOutbound(outbound, name: "Download", source: source)
            guard var clean = try profile.outbound()["streamSettings"] as? [String: Any] else { throw ProxyProfileError.invalid }
            clean["address"] = profile.host; clean["port"] = Int(profile.port)
            result["downloadSettings"] = clean
        }
        let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        guard data.count <= 16_384 else { throw ProxyProfileError.tooLarge }; return data
    }
}

enum ProxyImport {
    // Source-only budget. A full subscription repeats large routing tables in
    // every JSON object; only the small validated transport models are retained.
    // The encrypted profile and extension budgets remain unchanged at 1 MiB.
    static let maximumBytes = 32 * 1_048_576
    static func profiles(_ data: Data, source: VPN013ConnectionKind) throws -> [ProxyProfile] {
        guard data.count <= maximumBytes else { throw ProxyProfileError.tooLarge }
        guard source != .amneziawg, let raw = String(data: data, encoding: .utf8) else { throw ProxyProfileError.invalid }
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.first != "{" && text.first != "[" && !text.hasPrefix("vless://") && !text.hasPrefix("#") {
            let compact = text.filter { !$0.isWhitespace }
            guard compact.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "+/=_-".contains($0)) }) else { throw ProxyProfileError.unsupported }
            let padded = compact.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: (4 - compact.count % 4) % 4)
            guard let decoded = Data(base64Encoded: padded), let plain = String(data: decoded, encoding: .utf8) else { throw ProxyProfileError.invalid }
            text = plain.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        var result = [ProxyProfile]()
        if text.first == "{" || text.first == "[" {
            var ranked: [(profile: ProxyProfile, rank: Int)] = []
            var configCount = 0
            func add(_ profile: ProxyProfile, rank: Int) throws {
                func identity(_ value: ProxyProfile) -> ProxyProfile {
                    var value = value; value.id = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!; value.name = "identity"; return value
                }
                if let index = ranked.firstIndex(where: { identity($0.profile) == identity(profile) }) {
                    if rank >= ranked[index].rank { ranked[index] = (profile, rank) }
                } else {
                    guard ranked.count < 100 else { throw ProxyProfileError.tooLarge }
                    ranked.append((profile, rank))
                }
            }
            try ProxyJSONSource.forEachObject(Data(text.utf8)) { bytes in
                func decode() throws {
                guard let config = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { throw ProxyProfileError.invalid }
                guard let outbounds = config["outbounds"] as? [[String: Any]] else { throw ProxyProfileError.invalid }
                let meta = config["meta"] as? [String: Any] ?? [:]
                let name = meta["serverName"] as? String ?? config["remarks"] as? String ?? source.title
                let automatic = name.lowercased().contains("авто") || name.lowercased().contains("auto")
                var first = true
                for outbound in outbounds where outbound["protocol"] as? String == "vless" {
                    let tag = outbound["tag"] as? String ?? ""
                    let reserve = ["backup-", "reserve-", "auto-", "lte-entry-"].contains(where: { tag.hasPrefix($0) })
                    let rank = reserve || automatic ? 0 : (first ? 2 : 1)
                    var value = try ProxyProfile.fromOutbound(outbound, name: first && !automatic ? name : (tag.isEmpty || reserve || automatic ? source.title : tag), source: source)
                    if rank == 0 { value.name = String(value.host.prefix(128)) }
                    try add(value, rank: rank); first = false
                }
                configCount += 1
                }
                #if canImport(ObjectiveC)
                try autoreleasepool(invoking: decode)
                #else
                try decode()
                #endif
            }
            // A multi-config subscription's primary entries define its visible
            // roster. Backup copies and its old Auto entry are not extra servers.
            // For a single standalone config all distinct VLESS candidates remain.
            let visible = ranked.filter { $0.rank > 0 }
            result = (configCount > 1 && !visible.isEmpty ? visible : ranked).map { $0.profile }
        } else {
            for line in text.split(whereSeparator: { $0.isNewline }) {
                let value = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if value.isEmpty || value.hasPrefix("#") { continue }
                result.append(try ProxyProfile.fromURI(value, source: source))
                if result.count > 100 { throw ProxyProfileError.tooLarge }
            }
        }
        guard !result.isEmpty else { throw ProxyProfileError.invalid }
        return result
    }
}

/// A bounded top-level JSON array scanner. Deserialize one object at a time so
/// repeated routing tables never accumulate as Foundation object graphs. Every
/// object's syntax is still checked by JSONSerialization; no JSON is executed.
private enum ProxyJSONSource {
    static func forEachObject(_ bytes: Data, visit: (Data) throws -> Void) throws {
        let count = bytes.count
        func whitespace(_ index: Int) -> Bool { [UInt8(9), 10, 13, 32].contains(bytes[index]) }
        var cursor = 0
        func skipSpace() { while cursor < count && whitespace(cursor) { cursor += 1 } }
        skipSpace(); guard cursor < count else { throw ProxyProfileError.invalid }
        if bytes[cursor] == 123 {
            guard count <= 1_048_576 else { throw ProxyProfileError.configurationTooLarge }
            try visit(bytes); return
        }
        guard bytes[cursor] == 91 else { throw ProxyProfileError.invalid }
        cursor += 1; var objects = 0
        while true {
            skipSpace()
            guard cursor < count, bytes[cursor] == 123, objects < 128 else { throw ProxyProfileError.invalid }
            let start = cursor; var depth = 0; var quoted = false; var escaped = false
            while cursor < count {
                let byte = bytes[cursor]; cursor += 1
                guard cursor - start <= 1_048_576 else { throw ProxyProfileError.configurationTooLarge }
                if quoted {
                    if escaped { escaped = false }
                    else if byte == 92 { escaped = true }
                    else if byte == 34 { quoted = false }
                } else if byte == 34 { quoted = true }
                else if byte == 123 || byte == 91 { depth += 1; guard depth <= 128 else { throw ProxyProfileError.invalid } }
                else if byte == 125 || byte == 93 { depth -= 1; if depth == 0 { break }; guard depth > 0 else { throw ProxyProfileError.invalid } }
            }
            guard depth == 0, !quoted else { throw ProxyProfileError.invalid }
            try visit(bytes.subdata(in: start..<cursor)); objects += 1
            skipSpace(); guard cursor < count else { throw ProxyProfileError.invalid }
            if bytes[cursor] == 93 { cursor += 1; skipSpace(); guard cursor == count else { throw ProxyProfileError.invalid }; return }
            guard bytes[cursor] == 44 else { throw ProxyProfileError.invalid }; cursor += 1
        }
    }
}
