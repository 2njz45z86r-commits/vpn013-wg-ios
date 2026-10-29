// SPDX-License-Identifier: MIT
import Foundation
import CryptoKit

enum ProxySubscriptionError: LocalizedError {
    case identity, transport, http(Int), tooLarge
    var errorDescription: String? {
        switch self {
        case .identity: return "Не удалось сохранить идентификатор VPN013 для подписок. Проверьте свободное место и повторите попытку."
        case .transport: return "Не удалось загрузить подписку. Проверьте интернет и доступность её адреса."
        case .tooLarge: return ProxyProfileError.tooLarge.localizedDescription
        case .http(let status):
            if [401, 403, 404].contains(status) { return "Провайдер отклонил ссылку (HTTP \(status)). Проверьте срок и привязку устройства. У VPN013 свой идентификатор: получите для него ссылку нового устройства или восстановите выбранное устройство в кабинете провайдера." }
            return "Сервер подписки вернул HTTP \(status). Повторите загрузку позже."
        }
    }
}

/// A random installation secret, private to the host app. It survives updates;
/// deleting the app requires the provider's ordinary device recovery. A keyed
/// domain-specific UUID avoids sharing one identifier between unrelated sites.
enum VPN013SubscriptionIdentity {
    private static let lock = NSLock()
    static func identifier(for host: String, directory: URL) throws -> String {
        lock.lock(); defer { lock.unlock() }
        let file = directory.appendingPathComponent("subscription-device-v1")
        let root: String
        if FileManager.default.fileExists(atPath: file.path) {
            guard let handle = try? FileHandle(forReadingFrom: file) else { throw ProxySubscriptionError.identity }
            defer { try? handle.close() }
            guard let data = try? handle.read(upToCount: 37), data.count == 36,
                  let text = String(data: data, encoding: .utf8), UUID(uuidString: text)?.uuidString == text else { throw ProxySubscriptionError.identity }
            root = text
        } else {
            root = UUID().uuidString
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                #if os(iOS)
                try Data(root.utf8).write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
                #else
                try Data(root.utf8).write(to: file, options: .atomic)
                #endif
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                var values = URLResourceValues(); values.isExcludedFromBackup = true
                var excluded = file; try excluded.setResourceValues(values)
            } catch { throw ProxySubscriptionError.identity }
        }
        let digest = HMAC<SHA256>.authenticationCode(for: Data(("VPN013-subscription-device-v1\n" + host.lowercased()).utf8), using: SymmetricKey(data: Data(root.utf8)))
        let hex = digest.prefix(16).map { String(format: "%02x", $0) }.joined()
        let chars = Array(hex)
        let text = String(chars[0..<8])+"-"+String(chars[8..<12])+"-"+String(chars[12..<16])+"-"+String(chars[16..<20])+"-"+String(chars[20..<32])
        return UUID(uuidString: text)!.uuidString
    }
}

enum VPN013SubscriptionRequest {
    /// Original-app handoff links wrap an HTTPS subscription; they are not executable configs.
    /// Preserve escaped tokens/query bytes when an ordinary HTTPS URL is already present.
    static func importText(_ raw: String) throws -> String {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let prefix = "blacktemple://import/"
        guard text.prefix(prefix.count).lowercased() == prefix else { return text }
        guard text.utf8.count <= 16_384 else { throw ProxyProfileError.tooLarge }
        let payload = String(text.dropFirst(prefix.count))
        let result: String
        if payload.prefix(8).lowercased() == "https://" { result = payload }
        else if let decoded = payload.removingPercentEncoding { result = decoded }
        else { throw ProxyProfileError.invalid }
        guard let url = URL(string: result), isSecure(url), url.fragment == nil,
              !result.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { throw ProxyProfileError.invalid }
        return result
    }
    static func isSecure(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https" && url.host != nil && url.user == nil && url.password == nil
    }
    static func compatibilityURL(_ original: URL) -> URL {
        // An optimization for the deployed issuer's documented URI contract.
        // Unknown publishers retain their original URL. Rejection falls back
        // once to the original URL without changing the device identifier.
        guard original.host?.lowercased() == "connect.vpn555.shop", [8443, 8444].contains(original.port ?? 443),
              original.path.range(of: "^/sub/[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
              var parts = URLComponents(url: original, resolvingAgainstBaseURL: false),
              !(parts.queryItems ?? []).contains(where: { $0.name == "format" }) else { return original }
        parts.queryItems = (parts.queryItems ?? []) + [URLQueryItem(name: "format", value: "uri")]
        return parts.url ?? original
    }
    static func make(_ url: URL, kind: VPN013ConnectionKind, identifier: String, version: String) -> URLRequest {
        var request = URLRequest(url: url)
        let safeVersion = version.filter { $0.isASCII && ($0.isNumber || $0 == ".") }.prefix(24)
        request.setValue("VPN013/\(safeVersion) (iOS; source=\(kind.title))", forHTTPHeaderField: "User-Agent")
        request.setValue("VPN013", forHTTPHeaderField: "X-Client")
        request.setValue(identifier, forHTTPHeaderField: "X-HWID")
        request.setValue("ios", forHTTPHeaderField: "X-Device-OS")
        request.setValue("application/json, text/plain;q=0.9", forHTTPHeaderField: "Accept")
        return request
    }
}
