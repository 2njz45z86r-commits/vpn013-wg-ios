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
            initialPackets: [interface.specialJunk1, interface.specialJunk2, interface.specialJunk3,
                             interface.specialJunk4, interface.specialJunk5]
        ) else {
            throw ParseError.interfaceHasInvalidCustomParam("J/S/I resource limits")
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
    editor_validation = """            guard VPN013PrimaryResourceBudget.valid(
                jc: config.junkPacketCount,
                jmin: config.junkPacketMinSize,
                jmax: config.junkPacketMaxSize,
                paddings: [config.initPacketJunkSize, config.responsePacketJunkSize,
                           config.cookieReplyPacketJunkSize, config.transportPacketJunkSize],
                initialPackets: [config.specialJunk1, config.specialJunk2, config.specialJunk3,
                                 config.specialJunk4, config.specialJunk5]
            ) else {
                return .error("Параметры маскировки AmneziaWG превышают безопасные пределы или несовместимы.")
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
