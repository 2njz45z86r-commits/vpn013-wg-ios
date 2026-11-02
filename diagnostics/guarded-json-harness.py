"""Compile the exact guarded registry conversion with synthetic Swift models."""
from pathlib import Path
import sys

source = Path('overlay/VPN013/tests/ClientUpdateTests.swift').read_text(encoding='utf-8')
start = source.index('        guard let currentBinding = registry.bindings[valid.orderID]')
end = source.index('        oldBinding.removeValue(forKey: "awgVersionChoices")', start)
end += len('        oldBinding.removeValue(forKey: "awgVersionChoices")')
snippet = source[start:end]
assert ' as! ' not in snippet and ' as? [String: Any]' in snippet
harness = '''import Foundation
struct Binding: Codable { var profileIDs: [String: String]; var awgVersionChoices: [String: Bool]? }
struct Registry { var bindings: [String: Binding] }
struct Snapshot { var orderID: String }
@main struct GuardedJSONDiagnostic {
    static func main() throws {
        let valid = Snapshot(orderID: "synthetic")
        let registry = Registry(bindings: [valid.orderID: Binding(profileIDs: ["test": "profile"], awgVersionChoices: ["test": true])])
''' + snippet + '''
        let restored = try JSONDecoder().decode(Binding.self, from: JSONSerialization.data(withJSONObject: oldBinding))
        precondition(restored.awgVersionChoices == nil && restored.profileIDs == ["test": "profile"])
        print("ExactGuardedRegistryConversion: synthetic compatibility passed")
    }
}
'''
Path(sys.argv[1]).write_text(harness, encoding='utf-8', newline='\n')
