#!/usr/bin/env python3
"""Add full-config AWG resource checks to the pinned Apple Swift sources.

Run against a fresh checkout of 9d5ee60edefa95b933a738dd7cda671dd18021fc.
The hash and anchor checks deliberately reject another upstream revision.
"""

import argparse
import hashlib
from pathlib import Path


PARSER = Path("Sources/Shared/Model/TunnelConfiguration+WgQuickConfig.swift")
EDITOR = Path("Sources/WireGuardApp/UI/TunnelViewModel.swift")
PINNED_SHA256 = {
    PARSER: "50a74eaba8076a9d279271f7226f8fa8fbd9a93cf4332308ee6e0d529aca3821",
    EDITOR: "85fb862c462bd168a76211b103332b8f79e4d9236478cd14a5f628f9638463fd",
}
MARKER = "// VPN013 full-config primary AWG resource budget"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected one pinned source anchor, got {count}")
    return text.replace(old, new, 1)


def patch(root: Path) -> None:
    originals = {}
    for relative, expected in PINNED_SHA256.items():
        raw = (root / relative).read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError(f"{relative}: pinned source SHA-256 mismatch")
        originals[relative] = raw.decode("utf-8")

    helper = (Path(__file__).resolve().parent / "PrimaryResourceBudget.swift").read_text(encoding="utf-8")
    if "enum VPN013PrimaryResourceBudget" not in helper or MARKER in helper:
        raise ValueError("Swift budget helper is absent or contains a duplicate marker")

    parser = originals[PARSER]
    parser = replace_once(parser, '        let lines = wgQuickConfig.split { $0.isNewline }',
        '''        // A comment is standards-compatible and preserves an explicit local
        // choice when the original I fields do not identify their AWG version.
        let vpn013LegacyMarker = wgQuickConfig.split(whereSeparator: { $0.isNewline }).contains {
            $0.trimmingCharacters(in: .whitespacesAndNewlines) == "# VPN013-AmneziaWG = 1.5"
        }
        let lines = wgQuickConfig.split { $0.isNewline }''', 'legacy marker')
    parser = replace_once(parser, '                        "i1",\n',
        '                        "j1", "j2", "j3", "itime",\n                        "i1",\n', 'legacy input keys')
    parser = replace_once(parser, 'TunnelConfiguration.collate(interfaceAttributes: attributes)',
        'TunnelConfiguration.collate(interfaceAttributes: attributes, legacyMarker: vpn013LegacyMarker)', 'legacy marker passing')
    parser = replace_once(parser, 'private static func collate(interfaceAttributes attributes: [String: String]) throws -> InterfaceConfiguration {',
        'private static func collate(interfaceAttributes attributes: [String: String], legacyMarker: Bool) throws -> InterfaceConfiguration {', 'legacy collate')
    parser = replace_once(parser, '        var interface = InterfaceConfiguration(privateKey: privateKey)\n',
        '''        var interface = InterfaceConfiguration(privateKey: privateKey)
        let initialValues = [attributes["i1"], attributes["i2"], attributes["i3"], attributes["i4"], attributes["i5"]]
        let hasLegacyTags = initialValues.compactMap { $0 }.contains {
            $0.range(of: #"<\\s*(c|wt)(\\s|>)"#, options: .regularExpression) != nil
        }
        interface.legacyAWG15 = legacyMarker || hasLegacyTags || ["j1", "j2", "j3", "itime"].contains { attributes[$0] != nil }
        interface.legacyJunk1 = attributes["j1"]
        interface.legacyJunk2 = attributes["j2"]
        interface.legacyJunk3 = attributes["j3"]
        if let value = attributes["itime"] {
            guard let seconds = UInt32(value) else { throw ParseError.interfaceHasInvalidCustomParam("ITime") }
            interface.legacyIntervalSeconds = seconds
        }
''', 'legacy interface properties')
    parser = replace_once(parser, '        var output = "[Interface]\\n"\n',
        '''        var output = "[Interface]\\n"
        if interface.legacyAWG15 { output.append("# VPN013-AmneziaWG = 1.5\\n") }
        if let value = interface.legacyJunk1 { output.append("J1 = \\(value)\\n") }
        if let value = interface.legacyJunk2 { output.append("J2 = \\(value)\\n") }
        if let value = interface.legacyJunk3 { output.append("J3 = \\(value)\\n") }
        if let value = interface.legacyIntervalSeconds { output.append("ITime = \\(value)\\n") }
''', 'legacy config export')
    for variable, safe_label in (
        ("junkPacketCountString", "Jc"),
        ("junkPacketMinSizeString", "Jmin"),
        ("junkPacketMaxSizeString", "Jmax"),
        ("initPacketJunkSizeString", "S1"),
        ("responsePacketJunkSizeString", "S2"),
        ("cookieReplyPacketJunkSizeString", "S3"),
        ("transportPacketJunkSizeString", "S4"),
    ):
        parser = replace_once(
            parser,
            f"throw ParseError.interfaceHasInvalidCustomParam({variable})",
            f'throw ParseError.interfaceHasInvalidCustomParam("{safe_label}")',
            f"{PARSER}:{safe_label}",
        )

    validation = """        guard VPN013PrimaryResourceBudget.valid(
            jc: interface.junkPacketCount,
            jmin: interface.junkPacketMinSize,
            jmax: interface.junkPacketMaxSize,
            paddings: [interface.initPacketJunkSize, interface.responsePacketJunkSize,
                       interface.cookieReplyPacketJunkSize, interface.transportPacketJunkSize],
            initialPackets: interface.legacyAWG15 ? [] : [interface.specialJunk1, interface.specialJunk2, interface.specialJunk3,
                             interface.specialJunk4, interface.specialJunk5]
        ) else {
            throw ParseError.interfaceHasInvalidCustomParam("J/S/I resource limits")
        }
        if interface.legacyAWG15 {
            guard interface.headerProtectionKey == nil, interface.contentPaddingAddition == nil,
                  interface.rekeyAfterTime == nil, interface.rekeyTimeout == nil,
                  interface.rejectAfterTime == nil, interface.keepaliveTimeout == nil,
                  interface.maxHandshakeAttempts == nil, interface.randomTrailers == nil,
                  interface.disableCookies == nil,
                  VPN013PrimaryResourceBudget.validLegacy(
                    initialPackets: [interface.specialJunk1, interface.specialJunk2, interface.specialJunk3,
                                     interface.specialJunk4, interface.specialJunk5],
                    controlledPackets: [interface.legacyJunk1, interface.legacyJunk2, interface.legacyJunk3],
                    intervalSeconds: interface.legacyIntervalSeconds) else {
                throw ParseError.interfaceHasInvalidCustomParam("AWG 1.5 J/I resource limits")
            }
        }
"""
    parser = replace_once(
        parser,
        "        return interface\n    }\n\n    private static func collate(peerAttributes",
        validation + "        return interface\n    }\n\n    private static func collate(peerAttributes",
        str(PARSER),
    )
    parser += "\n" + MARKER + "\n" + helper.rstrip() + "\n"

    editor = originals[EDITOR]
    editor = replace_once(editor, '        case specialJunk5\n',
        '        case specialJunk5\n        case legacyAWGVersion\n        case legacyJunk1\n        case legacyJunk2\n        case legacyJunk3\n        case legacyInterval\n', 'legacy editor fields')
    editor = replace_once(editor, '            case .specialJunk5: return tr("I5")\n',
        '''            case .specialJunk5: return tr("I5")
            case .legacyAWGVersion: return "Версия AmneziaWG (1.5 или авто)"
            case .legacyJunk1: return "J1 (AmneziaWG 1.5)"
            case .legacyJunk2: return "J2 (AmneziaWG 1.5)"
            case .legacyJunk3: return "J3 (AmneziaWG 1.5)"
            case .legacyInterval: return "ITime (AmneziaWG 1.5)"
''', 'legacy editor labels')
    editor = replace_once(editor, '            if let headerProtectionKey = config.headerProtectionKey {\n',
        '''            if config.legacyAWG15 { scratchpad[.legacyAWGVersion] = "1.5" }
            scratchpad[.legacyJunk1] = config.legacyJunk1
            scratchpad[.legacyJunk2] = config.legacyJunk2
            scratchpad[.legacyJunk3] = config.legacyJunk3
            if let seconds = config.legacyIntervalSeconds { scratchpad[.legacyInterval] = String(seconds) }
            if let headerProtectionKey = config.headerProtectionKey {
''', 'legacy editor populate')
    editor = replace_once(editor, '            if let headerProtectionKeyString = scratchpad[.headerProtectionKey], !headerProtectionKeyString.isEmpty {\n',
        '''            let legacyVersion = scratchpad[.legacyAWGVersion]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard legacyVersion.isEmpty || legacyVersion == "1.5" || legacyVersion.lowercased() == "авто" else {
                return .error("Укажите версию AmneziaWG 1.5 или оставьте поле пустым.")
            }
            config.legacyAWG15 = legacyVersion == "1.5"
            config.legacyJunk1 = scratchpad[.legacyJunk1]
            config.legacyJunk2 = scratchpad[.legacyJunk2]
            config.legacyJunk3 = scratchpad[.legacyJunk3]
            if let interval = scratchpad[.legacyInterval], !interval.isEmpty {
                guard let seconds = UInt32(interval) else { return .error("ITime должен быть числом секунд.") }
                config.legacyIntervalSeconds = seconds
            }
            if !config.legacyAWG15 && [config.legacyJunk1, config.legacyJunk2, config.legacyJunk3].contains(where: { $0 != nil }) {
                return .error("Для J1–J3 укажите версию AmneziaWG 1.5.")
            }
            if !config.legacyAWG15 && config.legacyIntervalSeconds != nil {
                return .error("Для ITime укажите версию AmneziaWG 1.5.")
            }
            if let headerProtectionKeyString = scratchpad[.headerProtectionKey], !headerProtectionKeyString.isEmpty {
''', 'legacy editor values')
    editor_validation = """            guard VPN013PrimaryResourceBudget.valid(
                jc: config.junkPacketCount,
                jmin: config.junkPacketMinSize,
                jmax: config.junkPacketMaxSize,
                paddings: [config.initPacketJunkSize, config.responsePacketJunkSize,
                           config.cookieReplyPacketJunkSize, config.transportPacketJunkSize],
                initialPackets: config.legacyAWG15 ? [] : [config.specialJunk1, config.specialJunk2, config.specialJunk3,
                                 config.specialJunk4, config.specialJunk5]
            ) else {
                return .error("Параметры маскировки AmneziaWG превышают безопасные пределы или несовместимы.")
            }
            if config.legacyAWG15 {
                guard config.headerProtectionKey == nil, config.contentPaddingAddition == nil,
                      config.rekeyAfterTime == nil, config.rekeyTimeout == nil,
                      config.rejectAfterTime == nil, config.keepaliveTimeout == nil,
                      config.maxHandshakeAttempts == nil, config.randomTrailers == nil,
                      config.disableCookies == nil,
                      VPN013PrimaryResourceBudget.validLegacy(
                        initialPackets: [config.specialJunk1, config.specialJunk2, config.specialJunk3,
                                         config.specialJunk4, config.specialJunk5],
                        controlledPackets: [config.legacyJunk1, config.legacyJunk2, config.legacyJunk3],
                        intervalSeconds: config.legacyIntervalSeconds) else {
                    return .error("Параметры AmneziaWG 1.5 несовместимы или превышают безопасные пределы.")
                }
            }

"""
    editor = replace_once(
        editor,
        "            guard errorMessages.isEmpty else { return .error(errorMessages.first!) }\n\n"
        "            validatedConfiguration = config\n            validatedName = name",
        "            guard errorMessages.isEmpty else { return .error(errorMessages.first!) }\n\n"
        + editor_validation + "            validatedConfiguration = config\n            validatedName = name",
        str(EDITOR),
    )

    # All source and anchor checks have completed before either target is changed.
    (root / PARSER).write_text(parser, encoding="utf-8", newline="\n")
    (root / EDITOR).write_text(editor, encoding="utf-8", newline="\n")


def main() -> None:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("root", type=Path, help="fresh pinned Apple source checkout")
    args = argument_parser.parse_args()
    patch(args.root.resolve())
    print("VPN013 Swift primary resource validation patched into pinned Apple source")


if __name__ == "__main__":
    main()
