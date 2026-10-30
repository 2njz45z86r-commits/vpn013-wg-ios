// Synthetic reproduction of issuer field shapes. No personal keys or network.
import Foundation

@main struct ProxyIssuerCompatibilityTests {
    static var checks = 0
    static let base = "vless://00000000-0000-4000-8000-000000000001@server.example.invalid:443?security=tls&type=xhttp&sni=server.example.invalid"
    static func link(_ extra: [String: Any], query: [String: String] = [:]) throws -> String {
        var value = URLComponents(string: base)!
        value.queryItems! += query.sorted(by: { $0.key < $1.key }).map { URLQueryItem(name: $0.key, value: $0.value) }
        value.queryItems!.append(URLQueryItem(name: "extra", value: String(data: try JSONSerialization.data(withJSONObject: extra), encoding: .utf8)!))
        return value.string!
    }
    static func check(_ valid: Bool) { checks += 1; precondition(valid, "Issuer compatibility invariant") }
    static func rejects(_ body: () throws -> Void) {
        do { try body(); preconditionFailure("Conflicting or unsafe issuer fields accepted") }
        catch { checks += 1 }
    }
    static func main() throws {
        let issued = try link(["mode": "auto", "xPaddingBytes": "100-1000"], query: ["mode": "auto", "x_padding_bytes": "100-1000"])
        if CommandLine.arguments.contains("--expect-current-rejection") {
            rejects { _ = try ProxyProfile.fromURI(issued, source: .incy) }
            rejects { _ = try ProxyProfile.fromURI(link(["mode": "auto"], query: ["mode": "auto"]), source: .incy) }
            print("Reproduced both old parser rejections using synthetic issuer shapes")
            return
        }
        for section in [VPN013ConnectionKind.happ, .incy, .blacktemple] {
            let rows = try ProxyImport.profiles(Data((issued + "\n").utf8), source: section)
            check(rows.count == 1 && rows[0].mode == "auto")
            let stream = try rows[0].outbound()["streamSettings"] as! [String: Any]
            let http = stream["xhttpSettings"] as! [String: Any]
            check(http["mode"] as? String == "auto" && http["xPaddingBytes"] as? String == "100-1000")
            let nested = try ProxyProfile.fromURI(link(["mode": "stream-up", "path": "/upload", "host": "front.example.invalid"]), source: section)
            check(nested.mode == "stream-up" && nested.path == "/upload" && nested.httpHost == "front.example.invalid")
            let integer = try ProxyProfile.fromURI(link(["xPaddingBytes": 100], query: ["x_padding_bytes": "100"]), source: section)
            check((try integer.outbound()["streamSettings"] as! [String: Any])["xhttpSettings"] != nil)
            for field in ["mode", "path", "host"] {
                rejects { _ = try ProxyProfile.fromURI(link([field: "one"], query: [field: "two"]), source: section) }
            }
            for extra in [["xPaddingBytes": "200-1000"], ["xPaddingBytes": true], ["xPaddingBytes": 100.5]] as [[String: Any]] {
                rejects { _ = try ProxyProfile.fromURI(link(extra, query: ["x_padding_bytes": "100-1000"]), source: section) }
            }
            rejects { _ = try ProxyProfile.fromURI(link(["mode": 12]), source: section) }
            rejects { _ = try ProxyProfile.fromURI(link(["unreviewedOption": true]), source: section) }
            rejects { _ = try ProxyProfile.fromURI(link(["xPaddingBytes": "1000000000"]), source: section) }
            rejects { _ = try ProxyProfile.fromURI(link(["allowInsecure": true]), source: section) }
        }
        print("Issuer XHTTP aliases: \(checks) checks passed; synthetic data only")
    }
}
