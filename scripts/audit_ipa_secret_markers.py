#!/usr/bin/env python3
"""Check a disposable IPA for a limited set of high-confidence secret markers.

Only aggregate counts are emitted; no matched bytes or archive entry names are
printed. A clean result does not establish the absence of every secret.
"""
import argparse
import json
import re
import zipfile
from pathlib import Path

PATTERNS = {
    "private_pem": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "github_token": re.compile(rb"(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_])"),
    "github_fine_grained_token": re.compile(rb"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{30,255}(?![A-Za-z0-9_])"),
    "slack_token": re.compile(rb"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{16,255}(?![A-Za-z0-9-])"),
    "google_api_key": re.compile(rb"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
}
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRY = 192 * 1024 * 1024
MAX_ENTRIES = 20000
CHUNK_SIZE = 1024 * 1024
OVERLAP = 512


def audit(path):
    counts = {name: 0 for name in PATTERNS}
    total = 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ValueError("Archive entry count exceeds audit limit")
        for entry in entries:
            if entry.is_dir():
                continue
            if entry.file_size > MAX_ENTRY:
                raise ValueError("Archive entry exceeds audit limit")
            total += entry.file_size
            if total > MAX_TOTAL:
                raise ValueError("Archive total exceeds audit limit")
            previous = b""
            with archive.open(entry) as stream:
                while True:
                    chunk = stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    data = previous + chunk
                    for name, pattern in PATTERNS.items():
                        counts[name] += sum(1 for match in pattern.finditer(data) if match.end() > len(previous))
                    previous = data[-OVERLAP:]
    return {"entries": len(entries), "uncompressedBytes": total, "matchesByClass": counts,
            "matchCount": sum(counts.values()), "scope": "limited markers in disposable IPA; not a complete secret audit"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ipa", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    result = audit(args.ipa)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    if result["matchCount"]:
        raise SystemExit("Secret marker found: inspect privately before release")


if __name__ == "__main__":
    main()
