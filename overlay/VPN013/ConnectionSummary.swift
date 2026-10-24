// SPDX-License-Identifier: MIT
import Foundation

/// Only presentation data crosses this message boundary. Never encode a config or keys.
struct VPN013ConnectionSnapshot: Codable, Equatable {
    var schema = 1
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

        static func parse(_ runtime: String?) -> Self {
            guard let runtime = runtime, runtime.utf8.count <= 262_144 else { return Self() }
            var received: [UInt64] = [], sent: [UInt64] = [], handshakes: [Date] = []
            var peers = 0, invalidReceived = false, invalidSent = false
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
                    if let value = Double(parts[1]), value.isFinite, value > 0,
                       value <= Date().timeIntervalSince1970 + 60 {
                        handshakes.append(Date(timeIntervalSince1970: value))
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
                        sent: total(sent, invalid: invalidSent), handshake: handshakes.max())
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
            (phase?.utf8.count ?? 0) <= 1024
    }
}

enum VPN013ProfileOrdering {
    static func isBefore(name lhs: String, automatic lhsAutomatic: Bool,
                         name rhs: String, automatic rhsAutomatic: Bool) -> Bool {
        if lhsAutomatic != rhsAutomatic { return lhsAutomatic }
        return lhs.compare(rhs, options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive, .numeric]) == .orderedAscending
    }
}
