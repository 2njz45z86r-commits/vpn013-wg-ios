// Kept independent of WireGuardKit so the same budget can be checked before
// importing a full config and before saving an edited interface.
enum VPN013PrimaryResourceBudget {
    static let maximumJunkPacketCount = 64
    static let maximumJunkPacketSize = 4_096
    static let maximumJunkBytesPerHandshake = 262_144
    static let maximumInitialPacketSize = 4_096
    static let maximumInitialSpecBytes = 16_384
    static let maximumInitialTags = 128

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
