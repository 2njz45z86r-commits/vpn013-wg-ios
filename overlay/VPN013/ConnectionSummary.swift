// SPDX-License-Identifier: MIT
import Foundation
import CryptoKit

/// Only presentation data crosses this message boundary. Never encode a config or keys.
struct VPN013ConnectionSnapshot: Codable, Equatable {
    var schema = 1
    var hourlyComparison: String? = nil
    let name: String
    let endpoints: [String]
    let hosts: [String]
    let phase: String?
    let revision: Int
    let statistics: Statistics

    struct Statistics: Codable, Equatable {
        var received: UInt64?
        var sent: UInt64?
        var handshake: Date?
        var handshakeReported: Bool? = nil

        var hasCounters: Bool { received != nil || sent != nil }

        var manualHandshakeSummary: String {
            if handshake != nil { return "Данные рукопожатия получены" }
            return handshakeReported == true ? "Рукопожатие пока не получено" : "Данные рукопожатия пока недоступны"
        }

        static func parse(_ runtime: String?) -> Self {
            guard let runtime = runtime, runtime.utf8.count <= 262_144 else { return Self() }
            var received: [UInt64] = [], sent: [UInt64] = [], handshakes: [Date] = []
            var peers = 0, invalidReceived = false, invalidSent = false
            var validHandshakeFields = 0
            for line in runtime.split(separator: "\n") {
                let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2 else { continue }
                switch parts[0] {
                case "public_key": peers += 1
                case "rx_bytes":
                    if let value = UInt64(parts[1]) { received.append(value) } else { invalidReceived = true }
                case "tx_bytes":
                    if let value = UInt64(parts[1]) { sent.append(value) } else { invalidSent = true }
                case "last_handshake_time_sec":
                    if let value = Double(parts[1]), value.isFinite, value >= 0,
                       value <= Date().timeIntervalSince1970 + 60 {
                        validHandshakeFields += 1
                        if value > 0 { handshakes.append(Date(timeIntervalSince1970: value)) }
                    }
                default: break
                }
            }
            func total(_ values: [UInt64], invalid: Bool) -> UInt64? {
                guard peers > 0, peers <= 64, !invalid, values.count == peers else { return nil }
                var sum: UInt64 = 0
                for value in values {
                    let result = sum.addingReportingOverflow(value)
                    guard !result.overflow else { return nil }; sum = result.partialValue
                }
                return sum
            }
            return Self(received: total(received, invalid: invalidReceived),
                        sent: total(sent, invalid: invalidSent), handshake: handshakes.max(),
                        handshakeReported: peers > 0 && peers <= 64 && validHandshakeFields == peers)
        }
    }

    var targetIdentity: String { "\(revision)\n\(name)\n" + endpoints.joined(separator: "\n") }

    /// Endpoint echo needs an address, not runtime traffic statistics. Auto must
    /// still identify its actual member; its saved seed is not the current server.
    static func pingTarget(isAutomatic: Bool, profileName: String,
                           configuredEndpoints: [String], configuredHosts: [String],
                           runtime: Self?) -> Self? {
        let target: Self
        if let runtime = runtime, runtime.isValid {
            target = isAutomatic ? runtime : Self(name: profileName,
                endpoints: runtime.endpoints, hosts: runtime.hosts, phase: nil,
                revision: 0, statistics: .init())
        } else {
            guard !isAutomatic else { return nil }
            target = Self(name: profileName, endpoints: configuredEndpoints,
                hosts: configuredHosts, phase: nil, revision: 0, statistics: .init())
        }
        return target.isValid && !target.endpoints.isEmpty && !target.hosts.isEmpty ? target : nil
    }

    var isValid: Bool {
        schema == 1 && !name.isEmpty && name.utf8.count <= 512 &&
            endpoints.count <= 64 && hosts.count <= 64 &&
            endpoints.allSatisfy { !$0.isEmpty && $0.utf8.count <= 1024 } &&
            hosts.allSatisfy { !$0.isEmpty && $0.utf8.count <= 255 } &&
            (phase?.utf8.count ?? 0) <= 1024 && (hourlyComparison?.utf8.count ?? 0) <= 1024
    }
}

/// Manual statistics do not require reopening the saved encrypted profile.
/// Raw UAPI (including keys) stays inside the extension; only parsed metrics leave it.
struct VPN013RuntimeStatisticsReply: Codable, Equatable {
    var schema = 1
    let statistics: VPN013ConnectionSnapshot.Statistics?
    let peerIdentity: String?

    init(runtime: String?) {
        statistics = runtime.map { VPN013ConnectionSnapshot.Statistics.parse($0) }
        let peers = runtime.flatMap { text -> [String]? in
            guard text.utf8.count <= 262_144 else { return nil }
            return text.split(separator: "\n").filter { $0.hasPrefix("public_key=") }.map { String($0.dropFirst(11)) }
        }
        peerIdentity = peers.flatMap(Self.identity)
    }

    static func identity(_ peers: [String]) -> String? {
        let keys = peers.map { $0.lowercased() }
        guard (1...64).contains(keys.count), Set(keys).count == keys.count,
              keys.allSatisfy({ $0.utf8.count == 64 && $0.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }) else { return nil }
        let value = Data(("vpn013-manual-statistics-v1\n" + keys.sorted().joined(separator: "\n")).utf8)
        return SHA256.hash(data: value).map { String(format: "%02x", $0) }.joined()
    }

    var hasMeasurements: Bool {
        statistics.map { $0.hasCounters || $0.handshakeReported == true } ?? false
    }
}

enum VPN013SnapshotIssue: Error, Equatable {
    case notRunning, noSession, requestFailed, emptyResponse, oversizedResponse, invalidResponse, timedOut, runtimeUnavailable
    case backendStopped, backendOffline, transportBusy, sessionRefreshFailed

    var explanation: String {
        switch self {
        case .notRunning: return "VPN сейчас не запущен"
        case .noSession: return "Сеанс VPN-расширения недоступен"
        case .requestFailed: return "iOS не приняла запрос статистики"
        case .emptyResponse: return "VPN-расширение не вернуло данные статистики"
        case .oversizedResponse: return "Ответ VPN-расширения превысил допустимый размер"
        case .invalidResponse: return "Ответ VPN-расширения не прошёл проверку формата"
        case .timedOut: return "Нет ответа VPN-расширения за 6 секунд"
        case .runtimeUnavailable: return "VPN-движок пока не вернул измеренные счётчики"
        case .backendStopped: return "VPN-движок не предоставил активный сеанс статистики"
        case .backendOffline: return "Счётчики временно недоступны при изменении сети"
        case .transportBusy: return "Предыдущий запрос статистики ещё обрабатывается"
        case .sessionRefreshFailed: return "Не удалось подтвердить текущий сеанс статистики"
        }
    }
}

/// A capability response does not touch the adapter queue or reopen any profile.
struct VPN013ProviderIdentity: Codable, Equatable {
    var schema = 1
    var statisticsProtocol = 1
    let version: String
    let build: String
    static var current: Self {
        Self(version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown",
             build: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown")
    }
    var isValid: Bool {
        func number(_ text: String) -> Bool {
            text == "unknown" || (!text.isEmpty && text.utf8.count <= 32 &&
                text.utf8.allSatisfy { (48...57).contains($0) || $0 == 46 })
        }
        return schema == 1 && statisticsProtocol == 1 && number(version) && number(build)
    }
    var safeDescription: String { isValid ? version + "/" + build : "invalid" }
}

/// Only fixed status codes and measured fields cross the provider boundary.
struct VPN013ProviderStatistics: Codable {
    enum State: String, Codable { case available, stopped, offline, unavailable, noMeasurements }
    var schema = 1
    let provider: VPN013ProviderIdentity
    let state: State
    let sample: VPN013RuntimeStatisticsReply?
    var isValid: Bool {
        schema == 1 && provider.isValid &&
            (state == .available ? sample?.hasMeasurements == true : sample == nil)
    }
    var issue: VPN013SnapshotIssue? {
        switch state {
        case .available: return nil
        case .stopped: return .backendStopped
        case .offline: return .backendOffline
        case .unavailable, .noMeasurements: return .runtimeUnavailable
        }
    }
}

/// Main-thread, read-only RPC recovery. At most two unreturned IPC calls per connection.
/// A nil reply causes one exact-profile preferences lookup, never stop/start/save.
final class VPN013StatisticsMessageClient {
    typealias Sender = (Data, @escaping (Data?) -> Void) throws -> Void
    typealias Refresh = (@escaping (Sender?) -> Void) -> Void
    typealias LocalRead = (UInt8, @escaping (Result<Data, Error>) -> Void) -> (() -> Void)
    typealias Schedule = (TimeInterval, @escaping () -> Void) -> Void
    enum Format { case manual, legacyManual, automatic }
    struct Output { let data: Data; let format: Format }
    static let deadline: TimeInterval = 6
    private let schedule: Schedule
    private let deliver: (@escaping () -> Void) -> Void
    private let clock: () -> TimeInterval
    private final class PendingReply {
        let generation: UUID
        var handler: ((Result<Data, VPN013SnapshotIssue>) -> Void)?
        init(_ generation: UUID, handler: @escaping (Result<Data, VPN013SnapshotIssue>) -> Void) {
            self.generation = generation; self.handler = handler
        }
    }
    private final class PendingRefresh {
        let generation: UUID
        var handler: ((Sender?) -> Void)?
        init(_ generation: UUID, handler: @escaping (Sender?) -> Void) {
            self.generation = generation; self.handler = handler
        }
    }
    private var generation = UUID()
    private var pending: [UUID: PendingReply] = [:]
    private var pendingRefresh: PendingRefresh?
    private var active = false
    private var cancelLocalRead: (() -> Void)?
    private var retryAfter: TimeInterval = 0
    private var previousIssue: VPN013SnapshotIssue = .emptyResponse
    private(set) var diagnostic = "not-requested"

    init(schedule: @escaping Schedule = { delay, block in DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: block) },
         deliver: @escaping (@escaping () -> Void) -> Void = { DispatchQueue.main.async(execute: $0) },
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.schedule = schedule; self.deliver = deliver; self.clock = clock
    }

    func invalidate() {
        cancelLocalRead?(); cancelLocalRead = nil
        generation = UUID(); active = false; retryAfter = 0
        // Caller only invalidates across a stopped/replaced system connection.
        pending.removeAll(); pendingRefresh?.handler = nil; diagnostic = "connection-changed"
    }

    func read(automatic: Bool, send: @escaping Sender, refresh: @escaping Refresh,
              local: LocalRead? = nil,
              completion: @escaping (Result<Output, VPN013SnapshotIssue>) -> Void) {
        guard !active else { completion(.failure(.transportBusy)); return }
        guard clock() >= retryAfter else { completion(.failure(previousIssue)); return }
        active = true; generation = UUID(); let stamp = generation
        var ended = false
        let began = clock()
        var triedLocal = false
        var stages: [String] = []
        func note(_ text: String) { if stages.count < 10 { stages.append(text) }; self.diagnostic = stages.joined(separator: ";") }
        func finish(_ value: Result<Output, VPN013SnapshotIssue>) {
            guard self.generation == stamp, !ended else { return }
            if case .failure(let issue) = value, !triedLocal, let local = local,
               self.clock() - began < Self.deadline {
                triedLocal = true; note("local.begin")
                let cancel = local(automatic ? 3 : 6) { result in
                    guard self.generation == stamp, !ended else { return }
                    switch result {
                    case .success(let data):
                        guard !data.isEmpty, data.count <= 32_768 else {
                            note("local.invalid"); finish(.failure(.invalidResponse)); return
                        }
                        note("local.authenticated"); consume(data, legacy: false)
                    case .failure: note("local.no-reply"); finish(.failure(issue))
                    }
                }
                if ended || self.generation != stamp { cancel() }
                else { self.cancelLocalRead = cancel }
                return
            }
            ended = true; self.active = false
            self.cancelLocalRead?(); self.cancelLocalRead = nil
            for reply in self.pending.values where reply.generation == stamp { reply.handler = nil }
            if self.pendingRefresh?.generation == stamp { self.pendingRefresh?.handler = nil }
            if case .failure(let issue) = value { self.previousIssue = issue; self.retryAfter = self.clock() + 10 }
            else { self.retryAfter = 0 }
            completion(value)
        }
        func exchange(_ sender: @escaping Sender, byte: UInt8, timeout: TimeInterval,
                      done: @escaping (Result<Data, VPN013SnapshotIssue>) -> Void) {
            guard self.generation == stamp, !ended else { return }
            guard self.pending.count < 2 else { done(.failure(.transportBusy)); return }
            let call = UUID(); let waiter = PendingReply(stamp, handler: done); self.pending[call] = waiter
            let once: (Result<Data, VPN013SnapshotIssue>) -> Void = { [weak self, weak waiter] result in
                guard let self = self, let waiter = waiter else { return }
                let callback = waiter.handler; waiter.handler = nil
                guard self.generation == stamp, !ended else { return }; callback?(result)
            }
            self.schedule(timeout) { once(.failure(.timedOut)) }
            do {
                try sender(Data([byte])) { [weak self] data in
                    self?.deliver { [weak self] in
                        guard let self = self else { return }
                        // Keep the waiter alive through once(), then release it.
                        let retained = self.pending.removeValue(forKey: call)
                        withExtendedLifetime(retained) {
                            guard let data = data, !data.isEmpty else { once(.failure(.emptyResponse)); return }
                            guard data.count <= 32_768 else { once(.failure(.oversizedResponse)); return }
                            once(.success(data))
                        }
                    }
                }
            } catch {
                let retained = self.pending.removeValue(forKey: call)
                withExtendedLifetime(retained) { once(.failure(.requestFailed)) }
            }
        }
        func consume(_ data: Data, legacy: Bool) {
            if automatic { note("auto.reply"); finish(.success(Output(data: data, format: .automatic))); return }
            if legacy { note("legacy.reply"); finish(.success(Output(data: data, format: .legacyManual))); return }
            guard let value = try? JSONDecoder().decode(VPN013ProviderStatistics.self, from: data), value.isValid else {
                note("metrics.invalid"); finish(.failure(.invalidResponse)); return
            }
            note("provider=" + value.provider.safeDescription); note("engine=" + value.state.rawValue)
            if let issue = value.issue { finish(.failure(issue)); return }
            finish(.success(Output(data: data, format: .manual)))
        }
        func fresh() {
            guard self.pendingRefresh == nil else {
                note("preferences.busy"); finish(.failure(.transportBusy)); return
            }
            note("preferences.lookup")
            let waiter = PendingRefresh(stamp) { sender in
                    guard self.generation == stamp, !ended else { return }
                    guard let sender = sender else { note("preferences.no-match"); finish(.failure(.sessionRefreshFailed)); return }
                    note("preferences.exact-match")
                    exchange(sender, byte: automatic ? 3 : 6, timeout: 1.5) { result in
                        if case .success(let data) = result { consume(data, legacy: false); return }
                        guard !automatic else { note("fresh.failed"); finish(result.map { Output(data: $0, format: .automatic) }); return }
                        note("fresh.failed")
                        // Compatibility request4 returns parsed metrics only, never raw UAPI0.
                        exchange(sender, byte: 4, timeout: 1.5) { value in
                            if case .success(let data) = value { consume(data, legacy: true) }
                            else { note("legacy.failed"); finish(value.map { Output(data: $0, format: .legacyManual) }) }
                        }
                    }
            }
            self.pendingRefresh = waiter
            // The system lookup cannot be cancelled. Keep one ownership slot,
            // but drop its handler at the deadline so it cannot retain the UI.
            refresh { [weak self, weak waiter] sender in
                self?.deliver { [weak self, weak waiter] in
                    guard let self = self, let waiter = waiter,
                          self.pendingRefresh === waiter else { return }
                    self.pendingRefresh = nil
                    let callback = waiter.handler; waiter.handler = nil
                    callback?(sender)
                }
            }
        }
        self.schedule(Self.deadline) {
            guard self.generation == stamp, !ended else { return }
            note("request.deadline"); finish(.failure(.timedOut))
        }
        exchange(send, byte: automatic ? 3 : 6, timeout: 1.5) { result in
            if case .success(let data) = result { consume(data, legacy: false); return }
            note("current.failed")
            exchange(send, byte: 5, timeout: 0.5) { probe in
                if case .success(let data) = probe, data.count <= 1024,
                   let info = try? JSONDecoder().decode(VPN013ProviderIdentity.self, from: data), info.isValid {
                    note("capability=" + info.safeDescription)
                } else { note("capability.no-reply") }
                fresh()
            }
        }
    }
}

enum VPN013ProfileOrdering {
    static func isBefore(name lhs: String, automatic lhsAutomatic: Bool,
                         name rhs: String, automatic rhsAutomatic: Bool) -> Bool {
        if lhsAutomatic != rhsAutomatic { return lhsAutomatic }
        return lhs.compare(rhs, options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive, .numeric]) == .orderedAscending
    }
}
