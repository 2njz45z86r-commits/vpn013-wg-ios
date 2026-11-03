"""Compile the actual iOS cleanup loop with fake preference managers on macOS."""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[2]
source = (root / 'overlay/Sources/WireGuardApp/Tunnel/TunnelsManager.swift').read_text(encoding='utf-8')
begin = '                for (index, tunnelManager) in tunnelManagers.enumerated().reversed() {'
end = '                #if os(macOS)\n                Keychain.deleteReferences(except: refs)'
assert source.count(begin) == 1 and source.count(end) == 1
loop = source[source.index(begin):source.index(end)].replace('#if os(iOS)', '#if true')
assert loop.count('tunnelManager.removeFromPreferences') == 1
assert loop.index('PrivateTunnelStore.idKey') < loop.index('tunnelManager.removeFromPreferences')
prelude = r'''
import Foundation
enum PrivateTunnelStore { static let idKey = "private-id"; static let dataKey = "private-data" }
enum AutoTunnelProfile { static let referenceKey = "legacy-auto-ref" }
enum LogLevel { case info }
func wg_log(_ level: LogLevel, message: String) {}
class NETunnelProviderProtocol {
    var providerConfiguration: [String: Any]?
    var passwordReference: Data?
    var isVPN013Proxy = false
    var validLegacy = false
    var migrationCalls = 0
    var verifyCalls = 0
    init(_ values: [String: Any]?, legacy: Bool = false, proxy: Bool = false) {
        providerConfiguration = values; validLegacy = legacy; isVPN013Proxy = proxy
        if legacy { passwordReference = Data([1]) }
    }
    func verifyConfigurationReference() -> Bool { verifyCalls += 1; return validLegacy }
    func migrateConfigurationIfNeeded(called: String) -> Bool { migrationCalls += 1; return false }
}
class FakeManager {
    let protocolConfiguration: Any?
    let localizedDescription: String?
    var preferenceRemovals = 0
    init(_ name: String, _ proto: NETunnelProviderProtocol) { localizedDescription = name; protocolConfiguration = proto }
    func removeFromPreferences(completionHandler: (Error?) -> Void) { preferenceRemovals += 1; completionHandler(nil) }
    func saveToPreferences(completionHandler: (Error?) -> Void) { completionHandler(nil) }
}
@main struct Tests {
    static func main() {
        let goodPrivate = NETunnelProviderProtocol([PrivateTunnelStore.idKey: "valid-id", PrivateTunnelStore.dataKey: Data([1])])
        let unreadable = NETunnelProviderProtocol([PrivateTunnelStore.idKey: "missing-key", PrivateTunnelStore.dataKey: Data([2])])
        let malformedID = NETunnelProviderProtocol([PrivateTunnelStore.idKey: 123])
        let malformedCipher = NETunnelProviderProtocol([PrivateTunnelStore.dataKey: "invalid"])
        let legacyGood = NETunnelProviderProtocol(nil, legacy: true)
        let legacyMissing = NETunnelProviderProtocol(nil)
        let proxy = NETunnelProviderProtocol(nil, proxy: true)
        let all = [FakeManager("good", goodPrivate), FakeManager("unreadable", unreadable),
                   FakeManager("malformed-id", malformedID), FakeManager("malformed-data", malformedCipher),
                   FakeManager("legacy-good", legacyGood), FakeManager("legacy-orphan", legacyMissing),
                   FakeManager("proxy", proxy)]
        var tunnelManagers = all
        var refs: Set<Data> = []
        var tunnelNames: Set<String> = []
'''
postlude = r'''
        let retained = Set(tunnelManagers.compactMap { $0.localizedDescription })
        precondition(retained == Set(["good", "unreadable", "malformed-id", "malformed-data", "legacy-good"]))
        precondition(all[0].preferenceRemovals == 0 && all[1].preferenceRemovals == 0 &&
                     all[2].preferenceRemovals == 0 && all[3].preferenceRemovals == 0 &&
                     all[4].preferenceRemovals == 0 && all[5].preferenceRemovals == 1 && all[6].preferenceRemovals == 0)
        precondition(goodPrivate.verifyCalls == 0 && unreadable.verifyCalls == 0 &&
                     malformedID.migrationCalls == 0 && malformedCipher.migrationCalls == 0)
        precondition(refs == Set([Data([1])]))
        print("PASS: real cleanup loop preserves unreadable/malformed private profiles; legacy control and proxy boundaries")
    }
}
'''
pathlib.Path(sys.argv[1]).write_text(prelude + loop + postlude, encoding='utf-8')
