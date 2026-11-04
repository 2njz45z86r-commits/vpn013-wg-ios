#!/usr/bin/env python3
"""Validate a bounded owner-signing IPA without treating it as a signed release."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import sys
import unicodedata
import zipfile

APP = "Payload/AmneziaWG.app"
EXTENSION = APP + "/PlugIns/WireGuardNetworkExtension.appex"
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_UNPACKED = 1024 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_PLIST = 1024 * 1024


def validate(ipa, build_report):
    if not ipa.is_file() or not 0 < ipa.stat().st_size <= MAX_ARCHIVE:
        raise ValueError("IPA missing or outside the size limit")
    if build_report.get("appID") != "com.vpn013.awg" or build_report.get("extensionID") != "com.vpn013.awg.network-extension":
        raise ValueError("Unexpected build bundle identities")
    if build_report.get("appleDistributionSigned") is not False or build_report.get("adHocIntegrityChecked") is not True:
        raise ValueError("Expected an integrity-checked ad-hoc owner-signing build")
    if build_report.get("physicalDeviceTested") is not False:
        raise ValueError("Unexpected physical-device status")
    with zipfile.ZipFile(ipa) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > MAX_ENTRIES or sum(x.file_size for x in entries) > MAX_UNPACKED:
            raise ValueError("IPA entries exceed bounds")
        names = set()
        logical_paths = {}
        for entry in entries:
            name = entry.filename
            parts = PurePosixPath(name).parts
            components = name.rstrip("/").split("/")
            archive_type = stat.S_IFMT(entry.external_attr >> 16)
            expected_type = stat.S_IFDIR if entry.is_dir() else stat.S_IFREG
            # zipfile normalizes embedded NULs (and platform separators) in
            # filename; inspect the unmodified central-directory name too.
            if (entry.orig_filename != name or not parts or len(components) > 64 or len(name.encode("utf-8")) > 4096
                    or name.startswith("/") or "\\" in name or any(p in ("", ".", "..") for p in components)
                    or not (name == "Payload/" or name == APP + "/" or name.startswith(APP + "/"))
                    or name in names or archive_type not in (0, expected_type)):
                raise ValueError("Unsafe, duplicate, or unexpected archive entry")
            names.add(name)
            # Default macOS volumes may compare case and Unicode spelling
            # differently from ZIP. Reject ambiguous names before extraction.
            for length in range(1, len(components) + 1):
                path = "/".join(components[:length])
                key = unicodedata.normalize("NFD", path).casefold()
                kind = "directory" if length < len(components) or entry.is_dir() else "file"
                previous = logical_paths.get(key)
                if previous is not None and previous != (path, kind):
                    raise ValueError("Ambiguous path or file/directory collision")
                logical_paths[key] = (path, kind)
        if archive.testzip() is not None:
            raise ValueError("IPA CRC verification failed")
        versions = []
        for root, expected in ((APP, "com.vpn013.awg"), (EXTENSION, "com.vpn013.awg.network-extension")):
            info_path = root + "/Info.plist"
            info_entry = archive.getinfo(info_path)
            if info_entry.file_size > MAX_PLIST:
                raise ValueError("Bundle metadata is too large")
            info = plistlib.loads(archive.read(info_entry))
            executable = info.get("CFBundleExecutable")
            if (info.get("CFBundleIdentifier") != expected or not isinstance(executable, str)
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", executable)):
                raise ValueError("Invalid bundle identity or executable name")
            if root == EXTENSION and info.get("NSExtension", {}).get("NSExtensionPointIdentifier") != "com.apple.networkextension.packet-tunnel":
                raise ValueError("Bundle is not a packet-tunnel extension")
            versions.append((info.get("CFBundleShortVersionString"), info.get("CFBundleVersion")))
            binary_entry = archive.getinfo(root + "/" + executable)
            if not 8 <= binary_entry.file_size <= 256 * 1024 * 1024:
                raise ValueError("Executable size outside bounds")
            binary = archive.read(binary_entry)
            if len(binary) < 8 or binary[:4] != bytes.fromhex("cffaedfe") or int.from_bytes(binary[4:8], "little") != 0x0100000C:
                raise ValueError("Bundle executable is not a 64-bit ARM Mach-O")
        if versions[0] != versions[1] or any(not isinstance(x, str) or not x for x in versions[0]):
            raise ValueError("App and extension versions do not match")
    return {"sha256": hashlib.sha256(ipa.read_bytes()).hexdigest(), "bytes": ipa.stat().st_size,
            "appID": "com.vpn013.awg", "extensionID": "com.vpn013.awg.network-extension",
            "sourceSha": os.environ["SOURCE_SHA"], "runId": os.environ["RUN_ID"],
            "distributionSigned": False, "physicalIPhoneTested": False,
            "requiresOwnerSigning": True, "version": versions[0][0], "build": versions[0][1]}


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: verify_owner_ipa.py IPA BUILD_REPORT OUTPUT")
    ipa, report, output = map(Path, sys.argv[1:])
    result = validate(ipa, json.loads(report.read_text(encoding="utf-8")))
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("Owner-signing IPA structure checked; distribution signing and device testing remain required.")


if __name__ == "__main__":
    main()
