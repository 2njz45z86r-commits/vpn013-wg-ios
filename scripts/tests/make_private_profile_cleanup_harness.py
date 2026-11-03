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
func wg_log(_ level: LogLevel, staticMessage: String) {}
class NETunnelProviderProtocol {
    var providerConfiguration: [String: Any]?
    var passwordReference: Data?
    var isVPN013Proxy = false
    var validLegacy = false
    var migrationCalls = 0
    var verifyCalls = 0
    var migrateSuccessfully = false
    init(_ values: [String: Any]?, legacy: Bool = false, proxy: Bool = false) {
        providerConfiguration = values; validLegacy = legacy; isVPN013Proxy = proxy
        if legacy { passwordReference = Data([1]) }
    }
    func verifyConfigurationReference() -> Bool { verifyCalls += 1; return validLegacy }
    func migrateConfigurationIfNeeded(called: String) -> Bool {
        migrationCalls += 1
        if migrateSuccessfully { providerConfiguration = [PrivateTunnelStore.idKey: "migrated", PrivateTunnelStore.dataKey: Data([3])]; return true }
        return false
    }
}
class FakeManager {
    let protocolConfiguration: Any?
    let localizedDescription: String?
    var preferenceRemovals = 0
    var preferenceSaves = 0
    init(_ name: String, _ proto: NETunnelProviderProtocol) { localizedDescription = name; protocolConfiguration = proto }
    func removeFromPreferences(completionHandler: (Error?) -> Void) { preferenceRemovals += 1; completionHandler(nil) }
    func saveToPreferences(completionHandler: (Error?) -> Void) { preferenceSaves += 1; completionHandler(nil) }
}
@main struct Tests {
    static func main() {
        let goodPrivate = NETunnelProviderProtocol([PrivateTunnelStore.idKey: "valid-id", PrivateTunnelStore.dataKey: Data([1])])
        let unreadable = NETunnelProviderProtocol([PrivateTunnelStore.idKey: "missing-key", PrivateTunnelStore.dataKey: Data([2])])
        let malformedID = NETunnelProviderProtocol([PrivateTunnelStore.idKey: 123])
        let malformedCipher = NETunnelProviderProtocol([PrivateTunnelStore.dataKey: "invalid"])
        let legacyGood = NETunnelProviderProtocol(nil, legacy: true)
        let legacyMissing = NETunnelProviderProtocol(nil)
        let migrationFailure = NETunnelProviderProtocol(["WgQuickConfig": "synthetic-old-profile"])
        let migrationSuccess = NETunnelProviderProtocol(["WgQuickConfig": "synthetic-old-profile"])
        migrationSuccess.migrateSuccessfully = true
        let proxy = NETunnelProviderProtocol(nil, proxy: true)
        let all = [FakeManager("good", goodPrivate), FakeManager("unreadable", unreadable),
                   FakeManager("malformed-id", malformedID), FakeManager("malformed-data", malformedCipher),
                   FakeManager("legacy-good", legacyGood), FakeManager("legacy-unavailable", legacyMissing),
                   FakeManager("migration-failed", migrationFailure), FakeManager("migration-succeeded", migrationSuccess),
                   FakeManager("proxy", proxy)]
        var tunnelManagers = all
        var refs: Set<Data> = []
        var tunnelNames: Set<String> = []
'''
postlude = r'''
        let retained = Set(tunnelManagers.compactMap { $0.localizedDescription })
        precondition(retained == Set(["good", "unreadable", "malformed-id", "malformed-data", "legacy-good", "legacy-unavailable", "migration-failed", "migration-succeeded"]))
        precondition(all[0].preferenceRemovals == 0 && all[1].preferenceRemovals == 0 &&
                     all[2].preferenceRemovals == 0 && all[3].preferenceRemovals == 0 &&
                     all.allSatisfy({ $0.preferenceRemovals == 0 }))
        precondition(goodPrivate.verifyCalls == 0 && unreadable.verifyCalls == 0 &&
                     malformedID.migrationCalls == 0 && malformedCipher.migrationCalls == 0)
        precondition(refs == Set([Data([1])]))
        precondition(migrationFailure.migrationCalls == 1 && all[6].preferenceSaves == 0 &&
                     migrationSuccess.migrationCalls == 1 && all[7].preferenceSaves == 1)
        print("PASS: actual iOS cleanup loop preserves private and legacy profiles including migration failure; proxy remains separate")
    }
}
'''
pathlib.Path(sys.argv[1]).write_text(prelude + loop + postlude, encoding='utf-8')
