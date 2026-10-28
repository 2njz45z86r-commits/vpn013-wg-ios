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
    case invalid, unsupported, tooLarge, insecureTLS
    var errorDescription: String? {
        switch self {
        case .invalid: return "Конфигурация повреждена. Проверьте исходную ссылку или файл."
        case .unsupported: return "Этот формат пока не поддерживается. Нужна ссылка VLESS, совместимая подписка или JSON Xray."
        case .tooLarge: return "Конфигурация слишком велика. Допустимо до 1 МБ и 100 серверов."
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
              alpn.count <= 4, alpn.allSatisfy({ ["h2", "http/1.1", "h3"].contains($0) })
        else { throw ProxyProfileError.invalid }
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
        if ["1", "true"].contains(query["allowInsecure", default: "false"].lowercased()) { throw ProxyProfileError.insecureTLS }
        let transportName = query["type", default: "tcp"].lowercased()
        guard let transport = Transport(rawValue: transportName == "raw" ? "tcp" : transportName == "splithttp" ? "xhttp" : transportName),
              let security = Security(rawValue: query["security", default: "tls"].lowercased()) else { throw ProxyProfileError.unsupported }
        guard query["extra"] == nil || query["extra"] == "" || query["extra"] == "{}" else { throw ProxyProfileError.unsupported }
        let value = Self(id: UUID(), source: source, name: uri.fragment.flatMap { $0.isEmpty ? nil : $0 } ?? source.title,
            host: host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), port: UInt16(rawPort), userID: userID,
            transport: transport, security: security, serverName: query["sni"] ?? host,
            fingerprint: query["fp", default: security == .reality ? "chrome" : ""],
            publicKey: query["pbk", default: ""], shortID: query["sid", default: ""], flow: query["flow", default: ""],
            path: query["path", default: "/"], httpHost: query["host", default: ""],
            serviceName: query["serviceName", default: ""], mode: query["mode", default: "auto"],
            alpn: query["alpn"].map { $0.split(separator: ",").map(String.init) } ?? [])
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
        guard let transport = Transport(rawValue: network == "raw" ? "tcp" : network == "splithttp" ? "xhttp" : network) else { throw ProxyProfileError.unsupported }
        let tls = stream[security == .reality ? "realitySettings" : "tlsSettings"] as? [String: Any] ?? [:]
        if tls["allowInsecure"] as? Bool == true { throw ProxyProfileError.insecureTLS }
        let http = stream[transport == .xhttp ? "xhttpSettings" : "wsSettings"] as? [String: Any] ?? [:]
        guard http["extra"] == nil || (http["extra"] as? [String: Any])?.isEmpty == true else { throw ProxyProfileError.unsupported }
        let headers = http["headers"] as? [String: String] ?? [:]
        let grpc = stream["grpcSettings"] as? [String: Any] ?? [:]
        let value = Self(id: UUID(), source: source, name: name, host: host, port: UInt16(numericPort.intValue), userID: userID,
            transport: transport, security: security, serverName: tls["serverName"] as? String ?? host,
            fingerprint: tls["fingerprint"] as? String ?? (security == .reality ? "chrome" : ""),
            publicKey: tls["publicKey"] as? String ?? "", shortID: tls["shortId"] as? String ?? "",
            flow: user["flow"] as? String ?? "", path: http["path"] as? String ?? "/",
            httpHost: http["host"] as? String ?? headers["Host"] ?? "", serviceName: grpc["serviceName"] as? String ?? "",
            mode: http["mode"] as? String ?? "auto", alpn: tls["alpn"] as? [String] ?? [])
        try value.validate()
        return value
    }

    func outbound(resolvedHost: String? = nil) throws -> [String: Any] {
        try validate()
        var user: [String: Any] = ["id": userID.uuidString.lowercased(), "encryption": "none", "level": 0]
        if !flow.isEmpty { user["flow"] = flow }
        var stream: [String: Any] = ["network": transport.rawValue, "security": security.rawValue]
        var tls: [String: Any] = ["serverName": serverName]
        if !fingerprint.isEmpty { tls["fingerprint"] = fingerprint }
        if !alpn.isEmpty { tls["alpn"] = alpn }
        if security == .reality { tls["publicKey"] = publicKey; tls["shortId"] = shortID }
        stream[security == .reality ? "realitySettings" : "tlsSettings"] = tls
        if transport == .ws { stream["wsSettings"] = ["path": path, "headers": httpHost.isEmpty ? [:] : ["Host": httpHost]] }
        if transport == .xhttp { stream["xhttpSettings"] = ["path": path, "host": httpHost, "mode": mode] }
        if transport == .grpc { stream["grpcSettings"] = ["serviceName": serviceName] }
        return ["tag": "vpn013-proxy", "protocol": "vless", "settings": ["vnext": [["address": resolvedHost ?? host, "port": Int(port), "users": [user]]]], "streamSettings": stream]
    }
}

enum ProxyImport {
    static let maximumBytes = 1_048_576
    static func profiles(_ data: Data, source: VPN013ConnectionKind) throws -> [ProxyProfile] {
        guard data.count <= maximumBytes else { throw ProxyProfileError.tooLarge }
        guard source != .amneziawg, let raw = String(data: data, encoding: .utf8) else { throw ProxyProfileError.invalid }
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.first != "{" && text.first != "[" && !text.hasPrefix("vless://") {
            let compact = text.filter { !$0.isWhitespace }
            guard compact.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "+/=_-".contains($0)) }) else { throw ProxyProfileError.unsupported }
            let padded = compact.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: (4 - compact.count % 4) % 4)
            guard let decoded = Data(base64Encoded: padded), let plain = String(data: decoded, encoding: .utf8) else { throw ProxyProfileError.invalid }
            text = plain.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        var result = [ProxyProfile]()
        if text.first == "{" || text.first == "[" {
            let object = try JSONSerialization.jsonObject(with: Data(text.utf8))
            let configs: [[String: Any]]
            if let array = object as? [[String: Any]] { configs = array }
            else if let dictionary = object as? [String: Any] { configs = [dictionary] }
            else { throw ProxyProfileError.invalid }
            for config in configs {
                guard let outbounds = config["outbounds"] as? [[String: Any]] else { throw ProxyProfileError.invalid }
                let meta = config["meta"] as? [String: Any] ?? [:]
                let name = meta["serverName"] as? String ?? config["remarks"] as? String ?? source.title
                for outbound in outbounds where outbound["protocol"] as? String == "vless" {
                    result.append(try ProxyProfile.fromOutbound(outbound, name: name, source: source))
                    if result.count > 100 { throw ProxyProfileError.tooLarge }
                }
            }
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
