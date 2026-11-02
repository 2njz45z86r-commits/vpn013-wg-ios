"""Generate isolated Swift tests from the exact managed-version source."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
protocol = (root / 'overlay/VPN013/ClientUpdateProtocol.swift').read_text(encoding='utf-8')
registry = (root / 'overlay/VPN013/ClientSubscriptions.swift').read_text(encoding='utf-8')
start = protocol.index('    static func legacyChoice(')
end = protocol.index('\n    }', start) + len('\n    }')
method = protocol[start:end]
start = registry.index('struct ClientBinding: Codable {')
end = registry.index('\n}\n\nstruct ClientAutoBinding', start) + 2
binding = registry[start:end]
assert method.count('throw ClientUpdateError.versionChoiceRequired(name)') == 1
assert binding.count('awgVersionChoices: [String: Bool]? = nil') == 1
source = '''import Foundation
enum ClientUpdateError: Error { case versionChoiceRequired(String) }
struct ClientAccessDocument: Codable { var marker: String }
struct ClientSnapshot: Codable { var marker: String }
enum ClientUpdateProtocol {
''' + method + '''
}
''' + binding + '''
@main struct ChoiceTests {
    static func main() throws {
        var count = 0
        func check(_ value: Bool) { precondition(value); count += 1 }
        check(try ClientUpdateProtocol.legacyChoice(ambiguous: false, explicit: nil, existing: nil, name: "x") == nil)
        check(try ClientUpdateProtocol.legacyChoice(ambiguous: true, explicit: true, existing: false, name: "x") == true)
        check(try ClientUpdateProtocol.legacyChoice(ambiguous: true, explicit: false, existing: true, name: "x") == false)
        check(try ClientUpdateProtocol.legacyChoice(ambiguous: true, explicit: nil, existing: true, name: "x") == true)
        check(try ClientUpdateProtocol.legacyChoice(ambiguous: true, explicit: nil, existing: false, name: "x") == false)
        do { _ = try ClientUpdateProtocol.legacyChoice(ambiguous: true, explicit: nil, existing: nil, name: "x"); preconditionFailure() }
        catch ClientUpdateError.versionChoiceRequired(_) { count += 1 }
        var binding = ClientBinding(document: ClientAccessDocument(marker: "synthetic"))
        binding.profileIDs = ["node": "synthetic-profile"]
        binding.awgVersionChoices = ["node": true, "node2": false]
        let encoded = try JSONEncoder().encode(binding)
        let decoded = try JSONDecoder().decode(ClientBinding.self, from: encoded)
        check(decoded.awgVersionChoices == binding.awgVersionChoices && decoded.profileIDs == binding.profileIDs)
        var old = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        old.removeValue(forKey: "awgVersionChoices")
        let migrated = try JSONDecoder().decode(ClientBinding.self, from: JSONSerialization.data(withJSONObject: old))
        check(migrated.awgVersionChoices == nil && migrated.profileIDs == binding.profileIDs)
        print("ManagedVersionChoice: \\(count) passed")
    }
}
'''
Path(sys.argv[1]).write_text(source, encoding='utf-8', newline='\n')
