import Foundation

@main struct ConnectionSummaryTests {
    static func main() throws {
        var checks = 0
        func expect(_ condition: @autoclosure () -> Bool, _ reason: String) {
            checks += 1; precondition(condition(), reason)
        }
        typealias Row = (name: String, automatic: Bool)
        func before(_ a: Row, _ b: Row) -> Bool {
            VPN013ProfileOrdering.isBefore(name: a.name, automatic: a.automatic, name: b.name, automatic: b.automatic)
        }
        let ordinary: [Row] = [("!First", false), ("0 Server", false), ("Авто · обычный профиль", false),
                               ("Дом", false), ("Finland10", false), ("Finland2", false)]
        for count in 1...30 {
            var rows = ordinary + (0..<count).map { ("Server \($0)", false) }
            rows.append(("ZZZ renamed Auto", true))
            for _ in 0..<100 {
                let sorted = rows.shuffled().sorted(by: before)
                expect(sorted.first?.automatic == true, "Auto must precede ASCII, Cyrillic and numeric names")
                expect(sorted.dropFirst().allSatisfy { !$0.automatic }, "Only real metadata pins Auto")
                expect(sorted.filter { $0.name == "Авто · обычный профиль" }.first?.automatic == false, "Names cannot grant Auto identity")
                expect(sorted.dropFirst().map(\.name) == rows.filter { !$0.automatic }.sorted(by: before).map(\.name), "Ordinary natural order is preserved")
            }
        }
        expect(!before(("Auto", true), ("Auto", true)), "Ordering is irreflexive")
        expect(before(("Zulu", true), ("A", false)), "Renamed Auto stays first")
        expect(before(("Finland2", false), ("Finland10", false)), "Numeric ordering survives")

        let raw = "private_key=never-export-this\npublic_key=a\nrx_bytes=0\ntx_bytes=1024\nlast_handshake_time_sec=1000\npublic_key=b\nrx_bytes=2048\ntx_bytes=4096\nlast_handshake_time_sec=2000\n"
        let stats = VPN013ConnectionSnapshot.Statistics.parse(raw)
        expect(stats.received == 2048 && stats.sent == 5120, "All current peers contribute")
        expect(stats.handshake == Date(timeIntervalSince1970: 2000), "Newest real handshake wins")
        expect(stats.manualHandshakeSummary == "Данные рукопожатия получены", "Returned handshake data drives the manual summary")
        expect(VPN013ConnectionSnapshot.Statistics().manualHandshakeSummary == "Данные рукопожатия пока недоступны", "Unavailable statistics are not a failed handshake")
        expect(VPN013ConnectionSnapshot.Statistics(received: 0, sent: 0, handshakeReported: true).manualHandshakeSummary == "Рукопожатие пока не получено", "Explicit zero handshake differs from missing statistics")
        expect(VPN013ConnectionSnapshot.Statistics.parse("public_key=a\nrx_bytes=0\ntx_bytes=0\n").manualHandshakeSummary == "Данные рукопожатия пока недоступны", "Traffic counters do not invent a missing handshake field")
        expect(VPN013ConnectionSnapshot.Statistics.parse("public_key=a\nlast_handshake_time_sec=0\n").manualHandshakeSummary == "Рукопожатие пока не получено", "A returned zero handshake is explicitly known")
        expect(!VPN013ConnectionSnapshot.Statistics().hasCounters, "Missing counters are not reported as measured")
        expect(VPN013ConnectionSnapshot.Statistics(received: 0).hasCounters, "A measured zero remains available")
        let issues: [VPN013SnapshotIssue] = [.notRunning, .noSession, .requestFailed, .emptyResponse, .oversizedResponse, .invalidResponse, .timedOut, .runtimeUnavailable]
        expect(Set(issues.map(\.explanation)).count == issues.count, "Safe diagnostic categories remain distinct")
        expect(VPN013ConnectionSnapshot.Statistics.parse(nil).received == nil, "Missing stats are not zero")
        expect(VPN013ConnectionSnapshot.Statistics.parse("public_key=a\nrx_bytes=0\ntx_bytes=0\n").received == 0, "Measured zero is retained")
        for bad in ["public_key=a\nrx_bytes=-1", "public_key=a\nrx_bytes=abc", "public_key=a\nrx_bytes=", "rx_bytes=10", "public_key=a\npublic_key=b\nrx_bytes=10", "public_key=a\nrx_bytes=10\nrx_bytes=20", "public_key=a\nrx_bytes=18446744073709551615\npublic_key=b\nrx_bytes=1"] {
            expect(VPN013ConnectionSnapshot.Statistics.parse(bad).received == nil, "Reject incomplete, malformed or overflowing counter")
        }
        for bad in ["NaN", "inf", "-1", "0", String(Date().timeIntervalSince1970 + 86400)] {
            expect(VPN013ConnectionSnapshot.Statistics.parse("public_key=a\nlast_handshake_time_sec=" + bad).handshake == nil, "Invalid/future handshake must not confirm anything")
        }
        var snapshot = VPN013ConnectionSnapshot(name: "Home", endpoints: ["example.com:443"], hosts: ["example.com"], phase: nil, revision: 4, statistics: stats)
        expect(snapshot.isValid, "Bounded snapshot accepted")
        snapshot.hourlyComparison = "Других VPN проверено: 12 · задержка DNS"
        let encoded = try JSONEncoder().encode(snapshot)
        let firstKey = String(repeating: "a", count: 64), secondKey = String(repeating: "b", count: 64)
        let directRaw = raw.replacingOccurrences(of: "public_key=a\n", with: "public_key=" + firstKey + "\n")
            .replacingOccurrences(of: "public_key=b\n", with: "public_key=" + secondKey + "\n")
        let directReply = VPN013RuntimeStatisticsReply(runtime: directRaw)
        expect(directReply.hasMeasurements && directReply.statistics == stats, "Direct running-engine statistics need no saved profile")
        let directEncoded = try JSONEncoder().encode(directReply)
        let directText = String(decoding: directEncoded, as: UTF8.self)
        expect(!directText.contains("never-export-this") && !directText.contains("private_key") && !directText.contains("public_key"), "Only parsed statistics cross direct IPC")
        expect(!directText.contains(firstKey) && !directText.contains(secondKey), "Peer keys themselves never cross direct statistics IPC")
        expect(directReply.peerIdentity == VPN013RuntimeStatisticsReply.identity([secondKey, firstKey]), "Identity is independent of peer enumeration order")
        expect(directReply.peerIdentity != VPN013RuntimeStatisticsReply.identity([firstKey]), "A different running peer set is rejected")
        expect(VPN013RuntimeStatisticsReply.identity([firstKey, firstKey]) == nil, "Duplicate peers are invalid")
        expect(VPN013RuntimeStatisticsReply.identity(["malformed"]) == nil, "Malformed peers cannot identify the running engine")
        let directDecoded = try JSONDecoder().decode(VPN013RuntimeStatisticsReply.self, from: directEncoded)
        expect(directDecoded == directReply, "Direct statistics reply roundtrip")
        expect(!VPN013RuntimeStatisticsReply(runtime: nil).hasMeasurements, "Unavailable engine must not invent counters")
        expect(!VPN013RuntimeStatisticsReply(runtime: "private_key=never-export-this\n").hasMeasurements, "Missing peers must not invent measured zero")
        expect(VPN013RuntimeStatisticsReply(runtime: "public_key=a\nrx_bytes=0\ntx_bytes=0\nlast_handshake_time_sec=0\n").hasMeasurements, "Real zero counters remain available")
        expect(!String(decoding: encoded, as: UTF8.self).contains("never-export-this"), "No raw runtime keys cross boundary")
        let decoded = try JSONDecoder().decode(VPN013ConnectionSnapshot.self, from: encoded)
        expect(decoded == snapshot, "Snapshot roundtrip")
        let changed = VPN013ConnectionSnapshot(name: "Home", endpoints: ["new.example:443"], hosts: ["new.example"], phase: nil, revision: 5, statistics: stats)
        expect(changed.targetIdentity != snapshot.targetIdentity, "Auto change invalidates stale Ping")
        let duplicateStats = VPN013ConnectionSnapshot(name: "Home", endpoints: snapshot.endpoints, hosts: snapshot.hosts, phase: "Checking", revision: 4, statistics: .init())
        expect(duplicateStats.targetIdentity == snapshot.targetIdentity, "Statistics refresh does not cancel Ping")
        func ping(_ automatic: Bool, _ runtime: VPN013ConnectionSnapshot?) -> VPN013ConnectionSnapshot? {
            VPN013ConnectionSnapshot.pingTarget(isAutomatic: automatic, profileName: "Home",
                configuredEndpoints: snapshot.endpoints, configuredHosts: snapshot.hosts, runtime: runtime)
        }
        let manualFallback = ping(false, nil)
        expect(manualFallback?.hosts == snapshot.hosts, "Missing runtime must not disable an ordinary profile's endpoint Ping")
        expect(manualFallback?.statistics == VPN013ConnectionSnapshot.Statistics(), "A saved address is never presented as measured traffic or handshake")
        expect(manualFallback?.targetIdentity == ping(false, snapshot)?.targetIdentity,
               "Runtime recovery cannot discard a Ping for the same ordinary address")
        expect(manualFallback?.targetIdentity == ping(false, duplicateStats)?.targetIdentity,
               "Runtime refresh cannot discard a Ping result for the same ordinary address")
        let unnamedRuntime = VPN013ConnectionSnapshot(name: "Сервер", endpoints: snapshot.endpoints,
            hosts: snapshot.hosts, phase: nil, revision: 0, statistics: stats)
        expect(manualFallback?.targetIdentity == ping(false, unnamedRuntime)?.targetIdentity,
               "Provider's generic manual name cannot invalidate the profile's Ping target")
        expect(ping(false, changed)?.targetIdentity != manualFallback?.targetIdentity,
               "Changed endpoint must invalidate the old Ping")
        expect(ping(true, nil) == nil, "Auto must never guess its current member from the saved seed")
        expect(ping(true, changed)?.targetIdentity == changed.targetIdentity, "Auto retains the actual member revision")
        expect(ping(true, duplicateStats)?.targetIdentity == snapshot.targetIdentity,
               "Auto traffic counters do not invalidate Ping")
        for (endpoints, hosts) in [([String](), [String]()), (["example.com:443"], []),
                                    ([], ["example.com"]), (["example.com:443"], [String(repeating: "x", count: 256)])] {
            expect(VPN013ConnectionSnapshot.pingTarget(isAutomatic: false, profileName: "Home",
                configuredEndpoints: endpoints, configuredHosts: hosts, runtime: nil) == nil,
                "A missing or invalid saved address cannot enable Ping")
        }
        var invalid = snapshot; invalid.schema = 2
        expect(!invalid.isValid, "Unknown schema rejected")
        expect(ping(true, invalid) == nil, "Invalid Auto member data cannot enable Ping")
        expect(ping(false, invalid)?.targetIdentity == manualFallback?.targetIdentity,
               "Ordinary profile remains usable when runtime schema is rejected")
        expect(VPN013ConnectionSnapshot.Statistics.parse(String(repeating: "x", count: 262145)).sent == nil, "Bounded runtime parser")
        print("Connection card and Auto-first core checks passed: \(checks)")
    }
}
