#!/usr/bin/env python3
"""Verify the completeness and freshness of a 34-control review. Not a vulnerability scanner."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys

IDS = tuple([f"1.{n}" for n in range(1,5)] + [f"2.{n}" for n in range(1,6)] +
            [f"3.{n}" for n in range(1,5)] + [f"4.{n}" for n in range(1,12)] +
            [f"5.{n}" for n in range(1,4)] + [f"6.{n}" for n in range(1,8)])
REPORT = "security-review.json"

def git(*args):
    return subprocess.check_output(["git", *args])

def fingerprint():
    entries = []
    for row in git("ls-tree", "-rz", "HEAD").split(b"\0"):
        if not row:
            continue
        meta, path = row.split(b"\t", 1)
        mode, kind, sha = meta.decode("ascii").split()
        name = path.decode("utf-8", "surrogateescape")
        if name == REPORT:
            continue
        entries.append([name, mode, kind, sha])
    entries.sort(key=lambda row: row[0].encode("utf-8", "surrogateescape"))
    payload = json.dumps(entries, ensure_ascii=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()

def validate(report, digest, now):
    errors = []
    if not isinstance(report, dict):
        return ["invalid review object"]
    if report.get("schema_version") != 1:
        errors.append("unsupported review schema")
    if report.get("source_sha256") != digest:
        errors.append("review does not match the complete tracked source")
    if report.get("scope_complete") is not True:
        errors.append("source or infrastructure scope is incomplete")
    if not isinstance(report.get("private_report_ref"), str) or not report["private_report_ref"].strip():
        errors.append("private evidence report reference is missing")
    try:
        reviewed = dt.datetime.fromisoformat(report["reviewed_at"].replace("Z", "+00:00"))
        age = now - reviewed.astimezone(dt.timezone.utc)
        if reviewed.tzinfo is None or age < dt.timedelta(minutes=-5) or age > dt.timedelta(days=7):
            errors.append("review must be dated within the last 7 days")
    except (KeyError, TypeError, ValueError, AttributeError):
        errors.append("invalid review date")
    checks = report.get("checks")
    if not isinstance(checks, list):
        return errors + ["review must contain all 34 controls"]
    ids = [c.get("id") if isinstance(c, dict) else None for c in checks]
    if len(checks) != len(IDS) or any(ids.count(i) != 1 for i in IDS):
        errors.append("review must contain each of the 34 control IDs exactly once")
    for c in checks:
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        if cid not in IDS:
            errors.append("unknown control ID")
            continue
        if c.get("status") not in ("pass", "not_applicable"):
            errors.append("control " + cid + " has an unresolved finding or verification gap")
        if not isinstance(c.get("evidence_ref"), str) or not c["evidence_ref"].strip():
            errors.append("control " + cid + " has no private evidence reference")
    return errors

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fingerprint", action="store_true")
    args = parser.parse_args()
    try:
        if args.fingerprint:
            print(fingerprint())
            return 0
        tracked = git("status", "--porcelain", "--untracked-files=no").strip()
        untracked = git("ls-files", "--others", "--exclude-standard").strip()
        if tracked or untracked:
            print("Security release gate: BLOCKED (worktree differs from committed review scope)")
            return 1
        report = json.loads(Path(REPORT).read_text(encoding="utf-8"))
        errors = validate(report, fingerprint(), dt.datetime.now(dt.timezone.utc))
    except (OSError, ValueError, subprocess.CalledProcessError):
        print("Security release gate: BLOCKED (missing/invalid review or Git metadata)")
        return 1
    if errors:
        print("Security release gate: BLOCKED")
        for error in errors:
            print("- " + error)
        return 1
    print("Security release gate: PASS (34 current review records; this is not a vulnerability scan)")
    return 0

if __name__ == "__main__":
    sys.exit(main())

