// SPDX-License-Identifier: MIT
import Foundation
import CryptoKit

enum PrivateStoreError: LocalizedError {
    case invalidEnvelope, missingKey, oversized, keyConflict
    var errorDescription: String? {
        switch self {
        case .missingKey: return "Один раз включите этот VPN из VPN013 WG, чтобы подготовить защищённое хранилище расширения. Если приложение переустановлено, импортируйте прежний ZIP."
        case .oversized: return "Конфигурация слишком велика для защищённого профиля."
        case .keyConflict: return "Ключ защищённого профиля не совпадает. Создайте профиль заново из прежних конфигураций."
        case .invalidEnvelope: return "Не удалось проверить зашифрованную конфигурацию."
        }
    }
}

/// Each process uses its OWN sandbox. No shared App Group or Keychain group.
/// VPN preferences contain only authenticated ciphertext and a random identifier.
final class PrivateTunnelStore {
    struct Envelope { let id: String; let ciphertext: Data }
    static let idKey = "VPN013PrivateProfileID"
    static let dataKey = "VPN013EncryptedProfileV1"
    static let startKey = "VPN013BootstrapKeyV1"
    static var lastError: Error?
    static let maximumBytes = 1048576
    static var defaultDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("VPN013Private", isDirectory: true)
    }
    static var current: PrivateTunnelStore { PrivateTunnelStore(directory: defaultDirectory) }
    let directory: URL
    init(directory: URL) { self.directory = directory }

    private func keyURL(_ id: String) throws -> URL {
        guard let value = UUID(uuidString: id), value.uuidString == id else { throw PrivateStoreError.invalidEnvelope }
        return directory.appendingPathComponent(id + ".key", isDirectory: false)
    }
    private func authenticatedID(_ id: String) throws -> Data {
        _ = try keyURL(id)
        return Data(("VPN013-private-v1:" + id).utf8)
    }
    func key(for id: String) throws -> Data {
        let url = try keyURL(id)
        guard let data = try? Data(contentsOf: url), data.count == 32 else { throw PrivateStoreError.missingKey }
        return data
    }
    private func saveKey(_ data: Data, id: String) throws {
        guard data.count == 32 else { throw PrivateStoreError.invalidEnvelope }
        let url = try keyURL(id)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        #if os(iOS)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: directory.path)
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try data.write(to: url, options: .atomic)
        #endif
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var protectedURL = url; try protectedURL.setResourceValues(values)
    }
    func seal(_ plaintext: Data, reusing id: String? = nil) throws -> Envelope {
        guard plaintext.count <= Self.maximumBytes else { throw PrivateStoreError.oversized }
        let identifier = id ?? UUID().uuidString
        let secret: Data
        if id != nil { secret = try key(for: identifier) }
        else {
            secret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
            try saveKey(secret, id: identifier)
        }
        do {
            let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: secret), authenticating: authenticatedID(identifier))
            guard let combined = box.combined else { throw PrivateStoreError.invalidEnvelope }
            return Envelope(id: identifier, ciphertext: combined)
        } catch {
            if id == nil { remove(identifier) }
            throw error
        }
    }
    private func open(_ envelope: Envelope, with secret: Data) throws -> Data {
        guard secret.count == 32, envelope.ciphertext.count >= 28,
              envelope.ciphertext.count <= Self.maximumBytes + 28 else { throw PrivateStoreError.invalidEnvelope }
        let box = try AES.GCM.SealedBox(combined: envelope.ciphertext)
        return try AES.GCM.open(box, using: SymmetricKey(data: secret), authenticating: authenticatedID(envelope.id))
    }
    func open(_ envelope: Envelope) throws -> Data { try open(envelope, with: key(for: envelope.id)) }
    /// The foreground app supplies this once through Apple's VPN start options.
    /// Validate before persisting; never replace an existing key with a different one.
    func receive(_ secret: Data, for envelope: Envelope) throws {
        _ = try open(envelope, with: secret)
        if let existing = try? key(for: envelope.id) {
            guard existing == secret else { throw PrivateStoreError.keyConflict }
        } else { try saveKey(secret, id: envelope.id) }
    }
    func remove(_ id: String) {
        guard let url = try? keyURL(id) else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
