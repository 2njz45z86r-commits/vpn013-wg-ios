import Foundation

private final class MessageClock {
    private struct Job { let at: Double; let order: Int; let run: () -> Void }
    private var jobs: [Job] = []
    private var sequence = 0
    var now: Double = 0
    func advance(_ seconds: Double) {
        let end = now + seconds
        while let job = jobs.filter({ $0.at <= end }).min(by: { ($0.at, $0.order) < ($1.at, $1.order) }) {
            jobs.removeAll { $0.order == job.order }; now = job.at; job.run()
        }
        now = end
    }
    func client() -> VPN013StatisticsMessageClient {
        VPN013StatisticsMessageClient(schedule: { [weak self] delay, run in
            guard let self = self else { return }; self.sequence += 1
            self.jobs.append(Job(at: self.now + delay, order: self.sequence, run: run))
        }, deliver: { $0() }, clock: { [weak self] in self?.now ?? 0 })
    }
}

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
        let issues: [VPN013SnapshotIssue] = [.notRunning, .noSession, .requestFailed, .emptyResponse, .oversizedResponse, .invalidResponse, .timedOut, .runtimeUnavailable, .backendStopped, .backendOffline, .transportBusy, .sessionRefreshFailed]
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
        try checkMessages { ok, reason in expect(ok, reason) }
        print("Connection card and Auto-first core checks passed: \(checks)")
    }

    /// Injected transport responses test ownership and failure handling, not physical NE IPC.
    static func checkMessages(expect: @escaping (Bool, String) -> Void) throws {
        typealias Client = VPN013StatisticsMessageClient
        enum FixtureError: Error { case rejected }
        let provider = VPN013ProviderIdentity(version: "1.5.6", build: "18")
        let peer = String(repeating: "c", count: 64)
        let runtime = "private_key=must-never-leave-provider\npublic_key=\(peer)\nrx_bytes=42\ntx_bytes=77\nlast_handshake_time_sec=1000\n"
        let sample = VPN013RuntimeStatisticsReply(runtime: runtime)
        let reply = VPN013ProviderStatistics(provider: provider, state: .available, sample: sample)
        let metrics = try JSONEncoder().encode(reply)
        let legacy = try JSONEncoder().encode(sample)
        let hello = try JSONEncoder().encode(provider)
        let text = String(decoding: metrics, as: UTF8.self)
        expect(!text.contains("must-never-leave-provider") && !text.contains(peer), "New reply contains neither private nor public keys")
        expect(reply.isValid && provider.isValid, "Current statistics protocol is accepted")
        expect(!VPN013ProviderIdentity(version: "1.5.6\nforged", build: "18").isValid, "Diagnostic identity rejects newlines")
        expect(!VPN013ProviderIdentity(version: "1.5.6", build: String(repeating: "1", count: 33)).isValid, "Diagnostic identity is bounded")
        func failure(_ result: Result<Client.Output, VPN013SnapshotIssue>) -> VPN013SnapshotIssue? {
            if case .failure(let issue) = result { return issue }; return nil
        }

        do {
            let clock = MessageClock(), client = clock.client()
            var calls: [UInt8] = []; var lookups = 0; var outputs: [Client.Output] = []
            client.read(automatic: false, send: { data, done in calls.append(data[0]); done(metrics); done(metrics) },
                refresh: { _ in lookups += 1 }) { if case .success(let output) = $0 { outputs.append(output) } }
            expect(calls == [6] && outputs.count == 1 && outputs.first?.data == metrics, "Direct real-value reply completes exactly once")
            expect(lookups == 0, "A working session never reloads preferences")
            let diagnostic = client.diagnostic; clock.advance(7)
            expect(client.diagnostic == diagnostic && outputs.count == 1, "Old timeout cannot overwrite completed statistics")
            let decoded = try JSONDecoder().decode(VPN013ProviderStatistics.self, from: outputs[0].data)
            expect(decoded.sample?.statistics?.received == 42 && decoded.sample?.statistics?.sent == 77 &&
                decoded.sample?.statistics?.handshake == Date(timeIntervalSince1970: 1000), "Reported counters/time equal the supplied engine values")
        }
        do {
            let clock = MessageClock(), client = clock.client()
            var old: [UInt8] = [], fresh: [UInt8] = []; var lookups = 0; var output: Client.Output?
            client.read(automatic: false, send: { data, done in old.append(data[0]); done(data[0] == 5 ? hello : nil) },
                refresh: { done in lookups += 1; done { data, response in fresh.append(data[0]); response(metrics) } }) {
                    if case .success(let value) = $0 { output = value }
                }
            expect(old == [6, 5] && fresh == [6] && lookups == 1 && output?.data == metrics, "Empty old session recovers through exactly one refreshed sender")
            expect(client.diagnostic.contains("capability=1.5.6/18") && client.diagnostic.contains("preferences.exact-match"), "Safe stages identify delivery versus backend")
        }
        do {
            let clock = MessageClock(), client = clock.client()
            var calls: [UInt8] = []; var output: Client.Output?
            client.read(automatic: false, send: { data, _ in calls.append(data[0]); throw FixtureError.rejected },
                refresh: { done in done { data, response in
                    calls.append(data[0]); if data[0] == 6 { throw FixtureError.rejected }; response(legacy)
                } }) { if case .success(let value) = $0 { output = value } }
            expect(calls == [6, 5, 6, 4] && output?.data == legacy, "Throwing sends release ownership before nested compatibility recovery")
            if let output = output, case .legacyManual = output.format { expect(true, "Legacy parsed metrics are explicitly labelled") }
            else { expect(false, "Expected legacy parsed metrics") }
            expect(!calls.contains(0), "Statistics recovery never requests raw UAPI")
        }
        for (state, expected) in [(VPN013ProviderStatistics.State.stopped, VPN013SnapshotIssue.backendStopped),
                                  (.offline, .backendOffline), (.unavailable, .runtimeUnavailable), (.noMeasurements, .runtimeUnavailable)] {
            let clock = MessageClock(), client = clock.client()
            let data = try JSONEncoder().encode(VPN013ProviderStatistics(provider: provider, state: state, sample: nil))
            var issue: VPN013SnapshotIssue?; var lookup = false
            client.read(automatic: false, send: { _, done in done(data) }, refresh: { _ in lookup = true }) { issue = failure($0) }
            expect(issue == expected && !lookup, "A delivered backend status remains distinct from transport failure")
        }
        do {
            let clock = MessageClock(), client = clock.client(); var issue: VPN013SnapshotIssue?
            client.read(automatic: false, send: { _, done in done(nil) }, refresh: { $0(nil) }) { issue = failure($0) }
            expect(issue == .sessionRefreshFailed, "No exact active session never yields invented statistics")
        }
        do {
            let clock = MessageClock(), client = clock.client(); var issue: VPN013SnapshotIssue?
            let oversized = Data(repeating: 32, count: 32_769)
            let sender: Client.Sender = { _, done in done(oversized) }
            client.read(automatic: false, send: sender, refresh: { $0(sender) }) { issue = failure($0) }
            expect(issue == .oversizedResponse, "All oversized fallback replies are rejected before decoding")
        }
        do {
            let clock = MessageClock(), client = clock.client(); var issue: VPN013SnapshotIssue?
            var invalid = reply; invalid.schema = 2
            let data = try JSONEncoder().encode(invalid)
            client.read(automatic: false, send: { _, done in done(data) }, refresh: { _ in expect(false, "Invalid delivered schema must not trigger lookups") }) { issue = failure($0) }
            expect(issue == .invalidResponse, "Unknown statistics schema cannot be displayed")
        }
        do {
            let clock = MessageClock(), client = clock.client()
            var callbacks: [(Data?) -> Void] = []; var completions = 0; var issue: VPN013SnapshotIssue?
            let blocked: Client.Sender = { _, done in callbacks.append(done) }
            client.read(automatic: false, send: blocked, refresh: { $0(blocked) }) { completions += 1; issue = failure($0) }
            clock.advance(7)
            expect(callbacks.count == 2 && completions == 1 && issue == .transportBusy, "Two unreturned system calls bound the entire recovery chain")
            client.read(automatic: false, send: blocked, refresh: { $0(blocked) }) { _ in }
            expect(callbacks.count == 2, "Failure cooldown prevents additional system calls")
            callbacks[0](metrics)
            expect(completions == 1, "Late reply cannot complete a timed-out request twice")
            clock.advance(6); var current: Client.Output?
            client.read(automatic: false, send: { _, done in done(metrics) }, refresh: { $0(nil) }) { if case .success(let output) = $0 { current = output } }
            callbacks[1](nil)
            expect(current?.data == metrics && completions == 1, "Released old call capacity permits a fresh request without stale overwrite")
        }
        do {
            let clock = MessageClock(), client = clock.client()
            var old: ((Data?) -> Void)?; var obsolete = 0; var current = 0
            client.read(automatic: false, send: { _, done in old = done }, refresh: { $0(nil) }) { _ in obsolete += 1 }
            client.invalidate()
            client.read(automatic: false, send: { _, done in done(metrics) }, refresh: { $0(nil) }) { if case .success = $0 { current += 1 } }
            let diagnostic = client.diagnostic; old?(metrics); clock.advance(7)
            expect(obsolete == 0 && current == 1 && diagnostic == client.diagnostic, "Disconnect or profile replacement fences all old replies and timers")
        }
        do {
            let clock = MessageClock(), client = clock.client()
            var lookup: ((Client.Sender?) -> Void)?; var lookups = 0; var completions = 0; var last: VPN013SnapshotIssue?
            weak var retainedUI: NSObject?
            let sender: Client.Sender = { _, done in done(nil) }
            let refresh: Client.Refresh = { done in lookups += 1; lookup = done }
            do {
                let marker = NSObject(); retainedUI = marker
                client.read(automatic: false, send: sender, refresh: refresh) { [marker] result in
                    _ = marker; completions += 1; last = failure(result)
                }
            }
            expect(retainedUI != nil, "In-flight completion retains its owner only while needed")
            clock.advance(7)
            expect(completions == 1 && last == .timedOut && retainedUI == nil, "Global deadline releases UI even if preferences never returns")
            clock.advance(11)
            client.read(automatic: false, send: sender, refresh: refresh) { last = failure($0) }
            expect(lookups == 1 && last == .transportBusy, "A hung preferences lookup cannot accumulate more lookups")
            lookup?({ _, done in done(metrics) }); clock.advance(7)
            expect(completions == 1, "Late preferences completion cannot resurrect an expired request")
        }
        do {
            let clock = MessageClock(), client = clock.client(); var calls: [UInt8] = []; var output: Client.Output?
            let snapshot = VPN013ConnectionSnapshot(name: "Actual member", endpoints: ["actual.example:443"], hosts: ["actual.example"], phase: nil, revision: 9, statistics: sample.statistics!)
            let data = try JSONEncoder().encode(snapshot)
            client.read(automatic: true, send: { message, done in calls.append(message[0]); done(nil) },
                refresh: { done in done { message, response in calls.append(message[0]); response(data) } }) { if case .success(let value) = $0 { output = value } }
            expect(calls == [3, 5, 3] && output?.data == data, "Auto recovery reads actual-member reply and never falls back to a manual seed")
        }
    }
}
