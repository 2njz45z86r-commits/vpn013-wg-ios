// Run on macOS: swiftc scripts/PrimaryResourceBudget.swift tests/PrimaryResourceBudgetTests.swift
//     -o /tmp/vpn013-primary-resource-tests && /tmp/vpn013-primary-resource-tests
import Foundation
@main
enum PrimaryResourceBudgetTests {
    private static var checks = 0

    private static func check(_ expected: Bool, _ actual: Bool, _ name: String) {
        checks += 1
        precondition(actual == expected, "resource budget case failed: \(name)")
    }

    static func main() throws {
        check(true, VPN013PrimaryResourceBudget.needsLegacyVersionChoice(initialPackets: ["<b 0x01><t>"]), "ambiguous legacy timestamp")
        check(false, VPN013PrimaryResourceBudget.needsLegacyVersionChoice(initialPackets: ["<r 1>"]), "version-neutral initial packet")
        check(false, VPN013PrimaryResourceBudget.needsLegacyVersionChoice(initialPackets: ["<t><ds>"]), "newer-only initial tag")
        check(false, VPN013PrimaryResourceBudget.needsLegacyVersionChoice(initialPackets: ["<t><b ff>"]), "newer-only bytes syntax")
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("vpn013-config-budget-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        let text = "[Interface]\nAddress = 192.0.2.1/32\n"
        try Data(text.utf8).write(to: file)
        check(true, try VPN013PrimaryResourceBudget.readConfigFile(file) == text, "ordinary UTF-8 config")
        try (Data([0xef, 0xbb, 0xbf]) + Data(text.utf8)).write(to: file)
        check(true, try VPN013PrimaryResourceBudget.readConfigFile(file) == text, "UTF-8 BOM config")
        try (Data([0xff, 0xfe]) + text.data(using: .utf16LittleEndian)!).write(to: file)
        check(true, try VPN013PrimaryResourceBudget.readConfigFile(file) == text, "Windows UTF-16 config")
        check(true, try VPN013PrimaryResourceBudget.decodeConfig(Data([0xff, 0xfe]) + text.data(using: .utf16LittleEndian)!) == text, "ZIP UTF-16 config")
        try (Data([0xfe, 0xff]) + text.data(using: .utf16BigEndian)!).write(to: file)
        check(true, try VPN013PrimaryResourceBudget.readConfigFile(file) == text, "big-endian UTF-16 config")
        try (Data([0xff, 0xfe, 0x00, 0x00]) + text.data(using: .utf32LittleEndian)!).write(to: file)
        check(true, try VPN013PrimaryResourceBudget.readConfigFile(file) == text, "little-endian UTF-32 config")
        try (Data([0x00, 0x00, 0xfe, 0xff]) + text.data(using: .utf32BigEndian)!).write(to: file)
        check(true, try VPN013PrimaryResourceBudget.readConfigFile(file) == text, "big-endian UTF-32 config")
        let limit = VPN013PrimaryResourceBudget.maximumConfigFileBytes
        try Data(repeating: 0x61, count: limit).write(to: file)
        check(true, try VPN013PrimaryResourceBudget.readConfigFile(file).utf8.count == limit, "exact direct-file size limit")
        try Data(repeating: 0x61, count: limit + 1).write(to: file)
        do {
            _ = try VPN013PrimaryResourceBudget.readConfigFile(file)
            preconditionFailure("oversized direct config accepted")
        } catch VPN013PrimaryResourceBudget.ConfigReadError.tooLarge { checks += 1 }
        try Data([0xff, 0x41]).write(to: file)
        do {
            _ = try VPN013PrimaryResourceBudget.readConfigFile(file)
            preconditionFailure("invalidly encoded direct config accepted")
        } catch VPN013PrimaryResourceBudget.ConfigReadError.invalidEncoding { checks += 1 }
        check(true, VPN013PrimaryResourceBudget.validLegacy(initialPackets: ["<b 0xABC><r 1000><c><t><wt 5000>"],
                    controlledPackets: ["<b 0Xaa>"], intervalSeconds: 86_400), "legacy bounded 1.5 fields")
        check(false, VPN013PrimaryResourceBudget.validLegacy(initialPackets: ["<wt 5001>"],
                     controlledPackets: [], intervalSeconds: 0), "legacy wait above limit")
        check(false, VPN013PrimaryResourceBudget.validLegacy(initialPackets: ["<wt 5000><wt 5000>"],
                     controlledPackets: ["<wt 5000><wt 1>"], intervalSeconds: nil), "legacy aggregate wait")
        check(true, VPN013PrimaryResourceBudget.validLegacy(initialPackets: [nil, "<r 1>"],
                    controlledPackets: [nil, nil, "<b 0x01>"], intervalSeconds: nil), "legacy sparse sequence")
        check(false, VPN013PrimaryResourceBudget.validLegacy(initialPackets: ["<c><c>"],
                     controlledPackets: [], intervalSeconds: nil), "legacy duplicate counter")
        check(false, VPN013PrimaryResourceBudget.validLegacy(initialPackets: ["<r 1001>"],
                     controlledPackets: [], intervalSeconds: nil), "legacy excessive random allocation")
        check(true, VPN013PrimaryResourceBudget.validLegacy(initialPackets: ["<r +1><wt +0>"],
                    controlledPackets: [], intervalSeconds: nil), "legacy explicit positive sign")
        check(false, VPN013PrimaryResourceBudget.validLegacy(initialPackets: ["<r -1>"],
                     controlledPackets: [], intervalSeconds: nil), "legacy negative allocation")
        check(true, VPN013PrimaryResourceBudget.validLegacy(initialPackets: [],
                    controlledPackets: [], intervalSeconds: UInt32.max), "legacy long interval")
        check(true, VPN013PrimaryResourceBudget.valid(), "plain WireGuard without AWG fields")
        check(true, VPN013PrimaryResourceBudget.valid(jc: 0), "explicit zero junk count")
        check(true, VPN013PrimaryResourceBudget.valid(jc: 64, jmin: 4_096, jmax: 4_096,
                          paddings: [4_096, 0, nil, 4_096],
                          initialPackets: ["<t><r 10><rc 11><rd 12><d><ds><dz 13><b 0xA0>"]),
              "bounded AWG fields and all supported initial tags")
        check(false, VPN013PrimaryResourceBudget.valid(jc: 65), "excessive junk count")
        check(false, VPN013PrimaryResourceBudget.valid(jc: 64, jmin: 1, jmax: 4_097), "excessive junk packet size")
        check(false, VPN013PrimaryResourceBudget.valid(jc: 1, jmin: 100, jmax: 10), "reversed junk range")
        check(false, VPN013PrimaryResourceBudget.valid(jc: 0, jmin: 100, jmax: 10), "reversed junk range with zero count")
        check(false, VPN013PrimaryResourceBudget.valid(paddings: [4_097]), "excessive S field")
        check(false, VPN013PrimaryResourceBudget.valid(paddings: [0, 0, 0, 0, 0]),
              "more than four S fields")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: ["<r -1>"]), "negative I allocation")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: ["<r 999999999999999999999999999999999>"]),
              "overflowing I allocation")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: ["<r 4097>"]), "oversize I allocation")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: ["<unknown 1>"]), "unknown I tag")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: ["<b 0x0>"]), "invalid I hex")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: ["<r 3000><b " +
                                             Array(repeating: "aa", count: 1_097).joined() + ">"]),
              "combined I chain over 4096 bytes")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: ["<r 1"]), "unclosed I tag")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: [Array(repeating: "<d>", count: 129).joined()]),
              "too many I tags")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: [Array(repeating: "x", count: 16_385).joined()]),
              "oversize I specification")
        check(true, VPN013PrimaryResourceBudget.valid(initialPackets: ["<r 4096>", "<b 00>"]),
              "per-chain I limits")
        check(false, VPN013PrimaryResourceBudget.valid(initialPackets: [nil, nil, nil, nil, nil, nil]),
              "more than five I fields")
        print("PrimaryResourceBudget: \(checks) passed")
    }
}
