"""Generate a synthetic Swift harness from one committed runtime catch block."""
from pathlib import Path
import subprocess
import sys

revision, output = sys.argv[1:]
source = subprocess.check_output([
    'git', 'show', revision + ':overlay/Sources/WireGuardApp/Tunnel/TunnelsManager.swift'
], text=True)
start = source.index('let runtime = try TunnelConfiguration(')
start = source.index('} catch {', start) + len('} catch {')
end = source.index('completionHandler(self.tunnelConfiguration)', start)
block = source[start:end]
expected = 'true' if revision.startswith('fbfde') else 'false'
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
        let leaked = messages.contains { $0.contains(marker) }
        precondition(messages.count == errors.count && leaked == ''' + expected + ''')
        print("Synthetic runtime logging: \\(errors.count) cases passed")
    }
}
'''
Path(output).write_text(swift, encoding='utf-8', newline='\n')
