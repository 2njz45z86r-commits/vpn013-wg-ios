import Foundation

// Kept independent of WireGuardKit so the same budget can be checked before
// importing a full config and before saving an edited interface.
enum VPN013PrimaryResourceBudget {
    enum ConfigReadError: Error { case tooLarge, invalidEncoding }
    static let maximumConfigFileBytes = 1_048_576 // Same per-file limit as ZIP import.

    static func readConfigFile(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var data = Data()
        while data.count <= maximumConfigFileBytes {
            let limit = min(65_536, maximumConfigFileBytes + 1 - data.count)
            guard let chunk = try handle.read(upToCount: limit), !chunk.isEmpty else { break }
            data.append(chunk)
        }
        return try decodeConfig(data)
    }

    static func decodeConfig(_ source: Data) throws -> String {
        var data = source
        guard data.count <= maximumConfigFileBytes else { throw ConfigReadError.tooLarge }
        // Preserve common text files from Windows and remove the BOM before parsing.
        let encoding: String.Encoding
        if data.starts(with: [0x00, 0x00, 0xfe, 0xff]) {
            data.removeFirst(4); encoding = .utf32BigEndian
        } else if data.starts(with: [0xff, 0xfe, 0x00, 0x00]) {
            data.removeFirst(4); encoding = .utf32LittleEndian
        } else if data.starts(with: [0xfe, 0xff]) {
            data.removeFirst(2); encoding = .utf16BigEndian
        } else if data.starts(with: [0xff, 0xfe]) {
            data.removeFirst(2); encoding = .utf16LittleEndian
        } else {
            if data.starts(with: [0xef, 0xbb, 0xbf]) { data.removeFirst(3) }
            encoding = .utf8
        }
        guard let text = String(data: data, encoding: encoding) else { throw ConfigReadError.invalidEncoding }
        return text
    }
    static let maximumJunkPacketCount = 64
    static let maximumJunkPacketSize = 4_096
    static let maximumJunkBytesPerHandshake = 262_144
    static let maximumInitialPacketSize = 4_096
    static let maximumInitialSpecBytes = 16_384
    static let maximumInitialTags = 128

    static func needsLegacyVersionChoice(initialPackets: [String?]) -> Bool {
        guard initialPackets.compactMap({ $0 }).contains(where: {
            $0.range(of: #"<\s*t\s*>"#, options: .regularExpression) != nil
        }) else { return false }
        return validLegacy(initialPackets: initialPackets, controlledPackets: [], intervalSeconds: nil)
    }

    // AWG 1.5's <t> and <c> are eight bytes, and <wt> delays generation.
    // These limits match the separately staged legacy engine; never discard
    // an unsafe field or reinterpret it as a newer AWG packet.
    static func validLegacy(initialPackets: [String?], controlledPackets: [String?],
                            intervalSeconds: UInt32?) -> Bool {
        guard initialPackets.count <= 5, controlledPackets.count <= 3 else { return false }
        var totalWait = 0
        for group in [initialPackets, controlledPackets] {
            for optional in group {
                guard let spec = optional, !spec.isEmpty else { continue }
                guard let wait = legacyPacketWait(spec) else { return false }
                totalWait += wait
                guard totalWait <= 15_000 else { return false }
            }
        }
        return true
    }

    private static func legacyPacketWait(_ spec: String) -> Int? {
        guard spec.utf8.count <= maximumInitialSpecBytes else { return nil }
        var remaining = spec[...]
        var length = 0, tags = 0, wait = 0
        var hasCounter = false, hasTimestamp = false
        while let opening = remaining.firstIndex(of: "<") {
            let start = remaining.index(after: opening)
            guard let closing = remaining[start...].firstIndex(of: ">") else { return nil }
            let fields = remaining[start..<closing].split(whereSeparator: { $0.isWhitespace })
            tags += 1
            guard tags <= maximumInitialTags, let tag = fields.first, fields.count <= 2 else { return nil }
            let arg = fields.count == 2 ? fields[1] : nil
            switch tag {
            case "b":
                guard let value = arg, value.hasPrefix("0x") || value.hasPrefix("0X") else { return nil }
                let hex = value.dropFirst(2)
                guard !hex.isEmpty, hex.utf8.count <= maximumInitialPacketSize * 2,
                      hex.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else { return nil }
                length += (hex.utf8.count + 1) / 2
            case "r", "wt":
                guard let value = arg, !value.isEmpty, let number = Int(value), number >= 0 else { return nil }
                let digits = (value.first == "+" || value.first == "-") ? value.dropFirst() : value[...]
                guard !digits.isEmpty, digits.utf8.allSatisfy({ (48...57).contains($0) }) else { return nil }
                if tag == "r" {
                    guard number <= 1_000 else { return nil }
                    length += number
                } else {
                    guard number <= 5_000 else { return nil }
                    wait += number
                }
            case "c":
                guard arg == nil, !hasCounter else { return nil }
                hasCounter = true
                length += 8
            case "t":
                guard arg == nil, !hasTimestamp else { return nil }
                hasTimestamp = true
                length += 8
            default: return nil
            }
            guard length <= maximumInitialPacketSize, wait <= 15_000 else { return nil }
            remaining = remaining[remaining.index(after: closing)...]
        }
        return tags > 0 ? wait : nil
    }

    static func valid(jc: UInt16? = nil,
                      jmin: UInt16? = nil,
                      jmax: UInt16? = nil,
                      paddings: [UInt16?] = [],
                      initialPackets: [String?] = []) -> Bool {
        let count = Int(jc ?? 0)
        let minimum = Int(jmin ?? 0)
        let maximum = Int(jmax ?? 0)
        guard paddings.count <= 4,
              initialPackets.count <= 5,
              count <= maximumJunkPacketCount,
              minimum <= maximumJunkPacketSize,
              maximum <= maximumJunkPacketSize,
              minimum <= maximum,
              count * maximum <= maximumJunkBytesPerHandshake,
              paddings.allSatisfy({ Int($0 ?? 0) <= maximumJunkPacketSize }) else {
            return false
        }
        return initialPackets.allSatisfy { spec in
            guard let spec = spec else { return true }
            return validInitialPacket(spec)
        }
    }

    private static func validInitialPacket(_ spec: String) -> Bool {
        guard spec.utf8.count <= maximumInitialSpecBytes else { return false }
        var remaining = spec[...]
        var encodedLength = 0
        var tagCount = 0
        while let opening = remaining.firstIndex(of: "<") {
            let contentStart = remaining.index(after: opening)
            guard let closing = remaining[contentStart...].firstIndex(of: ">") else { return false }
            let fields = remaining[contentStart..<closing].split(whereSeparator: { $0.isWhitespace })
            tagCount += 1
            guard tagCount <= maximumInitialTags, let tag = fields.first, fields.count <= 2 else {
                return false
            }
            let argument = fields.count == 2 ? fields[1] : nil
            let additionalLength: Int
            switch tag {
            case "r", "rc", "rd", "dz":
                guard let argument = argument,
                      !argument.isEmpty,
                      argument.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                      let length = Int(argument),
                      length <= maximumInitialPacketSize else { return false }
                additionalLength = length
            case "b":
                guard let argument = argument else { return false }
                let hex = argument.hasPrefix("0x") ? argument.dropFirst(2) : argument[...]
                guard !hex.isEmpty,
                      hex.utf8.count % 2 == 0,
                      hex.utf8.count / 2 <= maximumInitialPacketSize,
                      hex.utf8.allSatisfy({ byte in
                          (byte >= 48 && byte <= 57) ||
                          (byte >= 65 && byte <= 70) ||
                          (byte >= 97 && byte <= 102)
                      }) else { return false }
                additionalLength = hex.utf8.count / 2
            case "t":
                guard argument == nil else { return false }
                additionalLength = 4
            case "d", "ds":
                guard argument == nil else { return false }
                // These copy/encode the source packet. At the initial allocation,
                // the source is empty, so their incremental length is zero.
                additionalLength = 0
            default:
                return false
            }
            encodedLength += additionalLength
            guard encodedLength <= maximumInitialPacketSize else { return false }
            remaining = remaining[remaining.index(after: closing)...]
        }
        return true
    }
}
