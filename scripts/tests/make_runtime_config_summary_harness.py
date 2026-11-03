"""Exercise the actual runtime-summary function using only synthetic input."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
source = (root / 'overlay/Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift').read_text(encoding='utf-8')
start = source.index('    private func logRuntimeConfigSummary(_ settings: String) {')
end = source.index('\n    }\n', start) + len('\n    }')
function = source[start:end]
swift = '''import Foundation
enum LogLevel { case debug }
var messages: [String] = []
func wg_log(_ level: LogLevel, message: String) { messages.append(message) }
final class Harness {
''' + function + '''
    func run(_ input: String) { logRuntimeConfigSummary(input) }
}
@main struct Run {
    static func main() {
        let input = [
            "public_key=SYNTHETIC_SECRET_MARKER",
            "last_handshake_time_sec=1700000000", "last_handshake_time_sec=1_SYNTHETIC_SECRET_MARKER",
            "rx_bytes=42", "rx_bytes=+12", "rx_bytes=42_SYNTHETIC_SECRET_MARKER",
            "tx_bytes=18446744073709551615", "tx_bytes=18446744073709551616",
            "tx_bytes=999999999999999999999999999999999999999", "tx_bytes=", "tx_bytes=１２",
            "private_key=SYNTHETIC_SECRET_MARKER"
        ].joined(separator: "\\n")
        Harness().run(input)
        precondition(messages.count == 1)
        let result = messages[0]
        precondition(result.contains("peers=1"))
        precondition(result.contains("last_handshake_time_sec=[\\"1700000000\\"]"))
        precondition(result.contains("rx_bytes=[\\"42\\"]"))
        precondition(result.contains("tx_bytes=[\\"18446744073709551615\\"]"))
        precondition(!result.contains("SYNTHETIC_SECRET_MARKER"))
        precondition(!result.contains("18446744073709551616"))
        print("PASS runtime summary: unsigned decimal metrics only; synthetic secrets and malformed values omitted")
    }
}
'''
Path(sys.argv[1]).write_text(swift, encoding='utf-8', newline='\n')
