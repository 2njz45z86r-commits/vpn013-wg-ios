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

enum VPN013SnapshotIssue {
    case notRunning, noSession, requestFailed, emptyResponse, oversizedResponse, invalidResponse, timedOut, runtimeUnavailable

    var explanation: String {
        switch self {
        case .notRunning: return "VPN сейчас не запущен"
        case .noSession: return "Сеанс VPN-расширения недоступен"
        case .requestFailed: return "iOS не приняла запрос статистики"
        case .emptyResponse: return "VPN-расширение не вернуло данные статистики"
        case .oversizedResponse: return "Ответ VPN-расширения превысил допустимый размер"
        case .invalidResponse: return "Ответ VPN-расширения не прошёл проверку формата"
        case .timedOut: return "Нет ответа VPN-расширения за 3 секунды"
        case .runtimeUnavailable: return "VPN-движок пока не вернул измеренные счётчики"
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
