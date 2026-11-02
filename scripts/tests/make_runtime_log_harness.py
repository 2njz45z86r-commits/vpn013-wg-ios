"""Test the real runtime parse-failure handler with synthetic Swift errors."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
source = (root / 'overlay/Sources/WireGuardApp/Tunnel/TunnelsManager.swift').read_text(encoding='utf8')
start = source.index('let runtime = try TunnelConfiguration(')
start = source.index('} catch {', start) + len('} catch {')
end = source.index('completionHandler(self.tunnelConfiguration)', start)
block = source[start:end]
swift = '''import Foundation
enum LogLevel { case error }
enum FakeError: Error { case invalidPrivateKey(String); case invalidLine(String) }
var messages: [String] = []
func wg_log(_ type: LogLevel, message: String) { messages.append(message) }
func wg_log(_ type: LogLevel, staticMessage: StaticString) { messages.append("\\(staticMessage)") }
@main struct Run {
    static func main() {
        let marker = "SYNTHETIC_PRIVATE_MARKER"
        let errors: [FakeError] = [.invalidPrivateKey(marker), .invalidLine(marker)]
        let settings = "private_key=" + marker + "\\n" + marker
        for failure in errors {
            do { throw failure } catch {
''' + block + '''
            }
        }
        precondition(messages.count == errors.count)
        precondition(!messages.contains { $0.contains(marker) })
        print("Runtime log privacy: \\(errors.count) synthetic errors passed")
    }
}
'''
Path(sys.argv[1]).write_text(swift, encoding='utf8', newline='\n')
