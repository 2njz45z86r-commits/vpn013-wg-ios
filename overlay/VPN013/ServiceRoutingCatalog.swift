// SPDX-License-Identifier: MIT
import Foundation
import CryptoKit

enum ServiceCatalogError: Error, LocalizedError {
    case invalid, wireGuardDomains, automaticStart
    case overlappingServices(String, String)
    var errorDescription: String? {
        switch self {
        case .invalid: return "Каталог маршрутизации недоступен или выбор не прошёл проверку. Прежние правила сохранены."
        case .wireGuardDomains: return "Этот сервис требует маршрутизации по доменам, которая здесь пока недоступна для WireGuard. Прежние правила сохранены."
        case .automaticStart: return "Сначала отключите подключение по требованию для выбранных серверов. Действующие подключения не изменены."
        case .overlappingServices(let selected, let other): return "Сервисы «\(selected)» и «\(other)» используют общие IPv4-сети и могут маршрутизироваться вместе. Точное разделение пока не подтверждено, поэтому новые правила не применены. Прежние правила сохранены."
        }
    }
}

/// Compare the actual pinned IPv4 ranges, including containment, without
/// exposing technical addresses in the UI. This is a guard for *new* saves,
/// not a change to resolution of already saved or active configurations.
struct ServiceIPv4Overlap {
    struct Interval {
        let first: UInt64
        let last: UInt64
        let service: String
    }

    static func interval(_ text: String, service: String) throws -> Interval {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix),
              String(prefix) == parts[1] else { throw ServiceCatalogError.invalid }
        let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { throw ServiceCatalogError.invalid }
        var address: UInt64 = 0
        for octet in octets {
            guard let value = UInt8(octet), String(value) == octet else { throw ServiceCatalogError.invalid }
            address = (address << 8) | UInt64(value)
        }
        let count = UInt64(1) << (32 - prefix)
        guard address % count == 0 else { throw ServiceCatalogError.invalid }
        return Interval(first: address, last: address + count - 1, service: service)
    }

    static func firstConflict(networks: [String: [String]], selected: Set<String>) throws -> (String, String)? {
        guard selected.isSubset(of: Set(networks.keys)) else { throw ServiceCatalogError.invalid }
        var chosen = [Interval](); var others = [Interval]()
        for (service, values) in networks {
            for value in values {
                let range = try interval(value, service: service)
                if selected.contains(service) { chosen.append(range) } else { others.append(range) }
            }
        }
        func ordered(_ lhs: Interval, _ rhs: Interval) -> Bool {
            lhs.first == rhs.first ? lhs.last < rhs.last : lhs.first < rhs.first
        }
        chosen.sort(by: ordered); others.sort(by: ordered)
        var left = 0; var right = 0
        while left < chosen.count && right < others.count {
            let a = chosen[left]; let b = others[right]
            if a.first <= b.last && b.first <= a.last { return (a.service, b.service) }
            if a.last < b.first { left += 1 } else { right += 1 }
        }
        return nil
    }
}

struct ServiceRoutingSelection: Codable, Equatable {
    enum Mode: String, Codable { case unchanged, only, bypass }
    var mode: Mode = .unchanged
    var only: [String] = []
    var bypass: [String] = []
    mutating func setOnly(_ enabled: Bool) { if enabled { mode = .only } else if mode == .only { mode = .unchanged } }
    mutating func setBypass(_ enabled: Bool) { if enabled { mode = .bypass } else if mode == .bypass { mode = .unchanged } }
    var activeIDs: [String] { mode == .only ? only : mode == .bypass ? bypass : [] }
    mutating func toggle(_ id: String) {
        guard mode != .unchanged else { return }
        var values = Set(activeIDs)
        if !values.insert(id).inserted { values.remove(id) }
        if mode == .only { only = values.sorted() } else { bypass = values.sorted() }
    }
}

struct ServiceCatalogDisplay: Decodable, Equatable {
    struct Icon: Decodable, Equatable { let kind: String; let text: String }
    let id: String
    let name: String
    let icon: Icon
    let category: String
    let archivedOnly: Bool
}

struct ServiceCatalogGroup: Decodable {
    let id: String
    let title: String
    let services: [ServiceCatalogDisplay]
}

/// Only release-pinned inert resources are read. A caller cannot choose a path,
/// inject rules, start a tunnel, or execute the source router's BAT files.
final class ServiceRoutingCatalog {
    struct Plan { let mode: ServiceRoutingSelection.Mode; let domains: [String]; let networks: [String] }
    private struct DisplayFile: Decodable { let version: Int; let services: [ServiceCatalogDisplay] }
    private struct Rules: Decodable { let ipv4: [String]; let domains: [String] }
    private struct RulesFile: Decodable { let version: Int; let services: [String: Rules] }
    private struct GroupsFile: Decodable { let version: Int; let groups: [ServiceCatalogGroup] }
    private let rules: [String: Rules]
    private let ids: Set<String>
    private let names: [String: String]
    let groups: [ServiceCatalogGroup]
    static let shared: Result<ServiceRoutingCatalog, Error> = Result { try load(bundle: .main) }

    static func load(bundle: Bundle) throws -> ServiceRoutingCatalog {
        func data(_ name: String) throws -> Data {
            guard let url = bundle.url(forResource: name, withExtension: "json"),
                  let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize,
                  (1...2_097_152).contains(size) else { throw ServiceCatalogError.invalid }
            return try Data(contentsOf: url)
        }
        return try ServiceRoutingCatalog(ui: data("ServiceCatalogUI"), rules: data("ServiceCatalogRules"), groups: data("ServiceCatalogGroups"))
    }

    init(ui: Data, rules: Data, groups: Data) throws {
        func pinned(_ data: Data, _ expected: String) throws {
            guard data.count <= 2_097_152,
                  SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == expected else { throw ServiceCatalogError.invalid }
        }
        try pinned(ui, "4fbaf9d8985c50b47465034165180393e11546c396027e5ded57e7c53f5475a3")
        try pinned(rules, "f69a0c79f3077981dca0600657b49a4a085610f76ef407a5f5e0d4874083476b")
        try pinned(groups, "a88d52da61ab4e596bb6050843bf11619148de40235a00a8162c660aba1ab882")
        let decoder = JSONDecoder()
        let display = try decoder.decode(DisplayFile.self, from: ui)
        let technical = try decoder.decode(RulesFile.self, from: rules)
        let grouped = try decoder.decode(GroupsFile.self, from: groups)
        let flat = grouped.groups.flatMap { $0.services }
        let ids = Set(display.services.map { $0.id })
        guard display.version == 1, technical.version == 1, grouped.version == 1,
              display.services.count == 412, ids.count == display.services.count,
              Set(technical.services.keys) == ids, flat.count == ids.count,
              Set(flat.map { $0.id }) == ids,
              Set(grouped.groups.map { $0.id }).count == grouped.groups.count,
              flat.allSatisfy({ display.services.contains($0) }) else { throw ServiceCatalogError.invalid }
        self.rules = technical.services; self.ids = ids; self.groups = grouped.groups
        self.names = Dictionary(uniqueKeysWithValues: display.services.map { ($0.id, $0.name) })
    }

    func resolve(_ selection: ServiceRoutingSelection) throws -> Plan? {
        for values in [selection.only, selection.bypass] {
            guard values.count <= ids.count, Set(values).count == values.count,
                  values.allSatisfy({ ids.contains($0) }) else { throw ServiceCatalogError.invalid }
        }
        guard selection.mode != .unchanged else { return nil }
        guard !selection.activeIDs.isEmpty else { throw ServiceCatalogError.invalid }
        var networks = Set<String>(); var domains = Set<String>()
        for id in selection.activeIDs {
            guard let entry = rules[id] else { throw ServiceCatalogError.invalid }
            networks.formUnion(entry.ipv4); domains.formUnion(entry.domains)
        }
        guard networks.count <= 16_384, domains.count <= 200 else { throw ServiceCatalogError.invalid }
        return Plan(mode: selection.mode, domains: domains.sorted(), networks: networks.sorted())
    }

    func displayGroups(matching query: String) -> [ServiceCatalogGroup] {
        let value = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return groups }
        return groups.compactMap { group in
            let services = group.title.localizedCaseInsensitiveContains(value) ? group.services : group.services.filter { $0.name.localizedCaseInsensitiveContains(value) }
            return services.isEmpty ? nil : ServiceCatalogGroup(id: group.id, title: group.title, services: services)
        }
    }

    func supportsWireGuard(_ id: String) -> Bool {
        guard let value = rules[id] else { return false }
        return value.domains.isEmpty && !value.ipv4.isEmpty
    }

    func resolveWireGuard(_ selection: ServiceRoutingSelection) throws -> Plan? {
        guard let plan = try resolve(selection) else { return nil }
        guard plan.domains.isEmpty, !plan.networks.isEmpty else { throw ServiceCatalogError.wireGuardDomains }
        return plan
    }

    /// Refuse an inaccurate new distinction; existing selections still resolve.
    func validateNewSelection(_ selection: ServiceRoutingSelection) throws {
        guard try resolve(selection) != nil else { return }
        let conflicts = try ServiceIPv4Overlap.firstConflict(networks: rules.mapValues { $0.ipv4 }, selected: Set(selection.activeIDs))
        if let (selected, other) = conflicts {
            guard let selectedName = names[selected], let otherName = names[other] else { throw ServiceCatalogError.invalid }
            throw ServiceCatalogError.overlappingServices(selectedName, otherName)
        }
    }
}
