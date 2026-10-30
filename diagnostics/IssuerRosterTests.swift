// Sanitized protocol shapes only. No real keys, URLs, file import or network.
import Foundation
@main struct IssuerRosterTests {
    static func main() throws {
        let input = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let fixture = try JSONSerialization.jsonObject(with: input) as! [String: Any]
        let legacyRejected = CommandLine.arguments.contains("--legacy-unfiltered")
        let currentUnfiltered = CommandLine.arguments.contains("--current-unfiltered")
        let rows = fixture[legacyRejected || currentUnfiltered ? "synthetic_uris" : "filtered_uris"] as! [String]
        precondition(rows.count == 18)
        var successes = 0; var failures = 0; var rosterChecks = 0
        for kind in [VPN013ConnectionKind.happ, .incy, .blacktemple] {
            for (index, row) in rows.enumerated() {
                do {
                    _ = try ProxyProfile.fromURI(row, source: kind)
                    precondition(!legacyRejected || index < 13, "Old parser did not reproduce LTE rejection")
                    successes += 1
                } catch {
                    precondition(legacyRejected && index >= 13, "Unexpected typed import failure at synthetic index \(index)")
                    guard case ProxyProfileError.unsupported = error else { preconditionFailure("Expected unsupported LTE metadata") }
                    failures += 1
                }
            }
            if !legacyRejected {
                let values = try ProxyImport.profiles(Data(rows.joined(separator: "\n").utf8), source: kind)
                precondition(values.count == 18); rosterChecks += 1
                let base64 = Data(rows.joined(separator: "\n").utf8).base64EncodedData()
                let decoded = try ProxyImport.profiles(base64, source: kind)
                precondition(decoded.count == 18); rosterChecks += 1
            }
            if currentUnfiltered {
                let json = fixture["full_json"] as! String
                let values = try ProxyImport.profiles(Data(json.utf8), source: kind)
                precondition(values.count == 18); rosterChecks += 1
            }
        }
        precondition(failures == (legacyRejected ? 15 : 0))
        print("Issuer roster: \(successes) individual imports, \(failures) expected legacy rejections, \(rosterChecks) full-roster checks; synthetic data only")
    }
}
