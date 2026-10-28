// SPDX-License-Identifier: MIT
import Foundation

struct ProxySubscriptionRecord: Codable, Equatable {
    var id: UUID
    var kind: VPN013ConnectionKind
    var url: URL
    var members: [ProxyProfile]
    var checkedAt: Date?

    func replacing(with fresh: [ProxyProfile]) throws -> Self {
        guard !fresh.isEmpty, fresh.count <= 100, fresh.allSatisfy({ $0.source == kind }) else { throw ProxyProfileError.invalid }
        var used = Set<UUID>()
        func identity(_ value: ProxyProfile) -> ProxyProfile {
            var value = value; value.id = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!; value.name = "identity"; return value
        }
        let next = try fresh.map { incoming -> ProxyProfile in
            try incoming.validate()
            var value = incoming
            let exact = members.filter { !used.contains($0.id) && identity($0) == identity(value) }
            let named = members.filter { !used.contains($0.id) && $0.name == value.name && $0.host == value.host && $0.port == value.port }
            if let old = exact.first ?? (named.count == 1 ? named.first : nil) { value.id = old.id }
            else { value.id = UUID() }
            // Ignore externally supplied duplicate/random identities: IDs are
            // local ownership markers, never an instruction to edit another group.
            if used.contains(value.id) { value.id = UUID() }
            used.insert(value.id); return value
        }
        var value = self; value.members = next; value.checkedAt = nil; return value
    }
}

/// Host-only encrypted source manifest. Bearer URLs never enter UserDefaults,
/// VPN preferences, the extension, diagnostic logs or public UI labels.
final class ProxySubscriptionStore {
    private struct DiskEnvelope: Codable { let id: String; let ciphertext: Data }
    private let secrets: PrivateTunnelStore
    private let file: URL
    init(directory: URL = PrivateTunnelStore.defaultDirectory) {
        secrets = PrivateTunnelStore(directory: directory)
        file = directory.appendingPathComponent("proxy-subscriptions-v1.encrypted")
    }
    private func envelope() throws -> DiskEnvelope? {
        guard FileManager.default.fileExists(atPath: file.path) else { return nil }
        let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
        let data = try handle.read(upToCount: 2_097_153) ?? Data()
        guard data.count <= 2_097_152 else { throw PrivateStoreError.oversized }
        return try JSONDecoder().decode(DiskEnvelope.self, from: data)
    }
    func load() throws -> [ProxySubscriptionRecord] {
        guard let stored = try envelope() else { return [] }
        let data = try secrets.open(.init(id: stored.id, ciphertext: stored.ciphertext))
        let records = try JSONDecoder().decode([ProxySubscriptionRecord].self, from: data)
        try validate(records)
        return records
    }
    private func validate(_ records: [ProxySubscriptionRecord]) throws {
        guard records.count <= 20, Set(records.map { $0.id }).count == records.count else { throw PrivateStoreError.invalidEnvelope }
        for record in records {
            guard record.kind != .amneziawg, VPN013SubscriptionRequest.isSecure(record.url), record.url.absoluteString.utf8.count <= 16_384,
                  !record.members.isEmpty, record.members.count <= 100, Set(record.members.map { $0.id }).count == record.members.count,
                  record.members.allSatisfy({ $0.source == record.kind }) else { throw PrivateStoreError.invalidEnvelope }
            for profile in record.members { try profile.validate() }
        }
    }
    func save(_ records: [ProxySubscriptionRecord]) throws {
        try validate(records)
        // Read/authenticate existing content before replacing it. Corruption
        // cannot silently create a new source identity or overwrite a manifest.
        _ = try load()
        let previous = try envelope()
        let plaintext = try JSONEncoder().encode(records)
        let sealed = try secrets.seal(plaintext, reusing: previous?.id)
        let data = try JSONEncoder().encode(DiskEnvelope(id: sealed.id, ciphertext: sealed.ciphertext))
        #if os(iOS)
        try data.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try data.write(to: file, options: .atomic)
        #endif
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var excluded = file; try excluded.setResourceValues(values)
    }
}
