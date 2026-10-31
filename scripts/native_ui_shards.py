#!/usr/bin/env python3
"""Select, verify, and combine exact-source native iPhone UI test shards."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zipfile


ROOT = Path(__file__).resolve().parents[1]
ADDED = frozenset({
    "testFivePersonalServers",
    "testFourteenPersonalServers",
    "testMoreThanThirteenPersonalServers",
    "testSinglePersonalServerExplainsNoReserve",
    "testCreateAutomaticFromThirteenImportedFixtures",
})
PREFIX = "AutoTunnelUITests/AutoTunnelUITests/"
SHARDS = ("coreA", "coreB", "coreC", "added5")
# The bound includes simulator compilation and xcresult export. The coreC
# run 41172679943 finished all 16 tests just before the old 40-minute limit,
# then timed out before exporting evidence. Keep a finite 45-minute budget.
MAX_WATCHDOG_SECONDS = 2700
# The 54 UI method bodies and the native WireGuard fixture assertions must
# remain the reviewed b9ecff4 sources. Updating them requires a new review.
UI_TEST_SOURCE_SHA256 = "707ffc71eef6c1c3bc55eb36adbabf2b9c9014ebee1374113c7f9f9a4613faad"
WG_FIXTURE_SHA256 = "042857ae089e4ec98d5b2d3da4e3079c1373656429800b4cda22ddf87f568be1"
CASE = re.compile(r"Test Case '-\[AutoTunnelUITests\.AutoTunnelUITests (test[A-Za-z0-9_]+)\]' (started|passed|failed)")


def safe_review_member(name):
    """Validate ZIP spelling before PurePosixPath can normalize it."""
    if not isinstance(name, str) or name.startswith("/") or "\\" in name or ":" in name or "\x00" in name:
        raise ValueError("unsafe review artifact path")
    parts = name.split("/")
    if len(parts) < 2 or parts[0] != "review" or any(part in ("", ".", "..") for part in parts):
        raise ValueError("unsafe review artifact path")
    relative = PurePosixPath(*parts[1:])
    if relative.suffix not in (".json", ".png"):
        raise ValueError("unexpected review artifact member")
    return relative


def selectors():
    data = (ROOT / "overlay/VPN013/UITests.swift").read_bytes()
    if hashlib.sha256(data).hexdigest() != UI_TEST_SOURCE_SHA256:
        raise ValueError("reviewed 54-test source changed; inspect its assertions and update the pinned hash")
    manager = (ROOT / "overlay/Sources/WireGuardApp/Tunnel/TunnelsManager.swift").read_text(encoding="utf-8")
    start = manager.index("    private func exerciseServiceRoutingFixture()")
    end = manager.index("\n    }\n", start) + 6
    if hashlib.sha256(manager[start:end].encode()).hexdigest() != WG_FIXTURE_SHA256:
        raise ValueError("reviewed WireGuard persistence fixture changed; inspect its assertions and update the pinned hash")
    source = data.decode("utf-8")
    names = re.findall(r"^\s+func\s+(test[A-Za-z0-9_]+)\s*\(", source, re.M)
    if len(names) != 54 or len(set(names)) != 54 or not ADDED.issubset(names):
        raise ValueError("UI source must define exactly 54 unique expected tests, including the five new tests")
    return tuple(sorted(names))


def expected(shard):
    all_names = selectors()
    if shard in ("coreA", "coreB", "coreC", "core49"):
        core = tuple(name for name in all_names if name not in ADDED)
        if len(core) != 49:
            raise ValueError("core shard is not 49 tests")
        return {"coreA": core[:17], "coreB": core[17:33], "coreC": core[33:], "core49": core}[shard]
    if shard == "added5":
        return tuple(name for name in all_names if name in ADDED)
    if shard == "all54":
        return all_names
    raise ValueError("unknown UI shard")


def exact_summary(summary, count):
    if not isinstance(summary, dict) or any(summary.get(key) != value for key, value in {
        "result": "Passed", "passedTests": count, "totalTestCount": count,
        "failedTests": 0, "skippedTests": 0, "expectedFailures": 0,
        "testFailures": [],
    }.items()):
        raise ValueError("xcresult summary is incomplete or not exactly passed")
    devices = summary.get("devicesAndConfigurations")
    if not isinstance(devices, list) or len(devices) != 1:
        raise ValueError("xcresult must report exactly one simulator configuration")
    row = devices[0]
    if any(row.get(key) != value for key, value in {
        "passedTests": count, "failedTests": 0, "skippedTests": 0, "expectedFailures": 0,
    }.items()) or row.get("device", {}).get("platform") != "iOS Simulator":
        raise ValueError("xcresult device counts or platform do not match")


def exact_log(log, names):
    completed = []
    failures = []
    for match in CASE.finditer(log):
        if match.group(2) == "passed":
            completed.append(match.group(1))
        elif match.group(2) == "failed":
            failures.append(match.group(1))
    if failures or len(completed) != len(names) or set(completed) != set(names) or len(set(completed)) != len(completed):
        raise ValueError("XCTest pass lines omit, duplicate, or add a selector")


def check_pngs(flow):
    images = sorted(flow.glob("*.png"))
    if not images or any(not p.read_bytes().startswith(b"\x89PNG\r\n\x1a\n") for p in images):
        raise ValueError("real XCUITest PNG attachments are missing")
    return len(images)


def verify(shard, review, log_path):
    names = expected(shard)
    summary_path = review / "test-summary.json"
    summary_bytes = summary_path.read_bytes()
    exact_summary(json.loads(summary_bytes), len(names))
    exact_log(log_path.read_text(encoding="utf-8", errors="replace"), names)
    images = check_pngs(review / "flow")
    source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha) or source_sha != os.environ.get("GITHUB_SHA"):
        raise ValueError("runner source SHA differs from current GitHub run")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    job = os.environ.get("GITHUB_JOB", "")
    if not run_id.isdecimal() or not attempt.isdecimal() or job != "native":
        raise ValueError("missing current GitHub run, attempt, or native job identity")
    proof = {
        "schema": 1, "shard": shard, "sourceSha": source_sha, "runId": run_id,
        "runAttempt": attempt, "jobId": job,
        "passedSelectors": list(names), "passedTests": len(names),
        "summarySha256": hashlib.sha256(summary_bytes).hexdigest(),
        "attachmentImages": images, "physicalIPhoneTested": False,
    }
    (review / "shard-proof.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    print(f"Native UI shard {shard}: {len(names)}/{len(names)} passed; source={source_sha}; run={run_id}; attachments={images}", flush=True)


def from_artifact(path, shard, source_sha, run_id, attempt):
    with zipfile.ZipFile(path) as archive:
        names_in_zip = archive.namelist()
        if len(set(names_in_zip)) != len(names_in_zip):
            raise ValueError(f"{shard}: duplicate archive member")
        for name in names_in_zip:
            safe_review_member(name)
        if any(stat.S_ISLNK(info.external_attr >> 16) for info in archive.infolist()):
            raise ValueError(f"{shard}: symbolic links are not allowed")
        members = set(names_in_zip)
        required = {"review/shard-proof.json", "review/test-summary.json"}
        if not required.issubset(members):
            raise ValueError(f"{shard}: missing proof or actual xcresult summary")
        proof = json.loads(archive.read("review/shard-proof.json"))
        raw = archive.read("review/test-summary.json")
        summary = json.loads(raw)
        names = expected(shard)
        if (proof.get("schema") != 1 or proof.get("shard") != shard or
                proof.get("sourceSha") != source_sha or proof.get("runId") != run_id or
                proof.get("runAttempt") != attempt or proof.get("jobId") != "native" or
                proof.get("passedSelectors") != list(names) or proof.get("passedTests") != len(names) or
                proof.get("summarySha256") != hashlib.sha256(raw).hexdigest() or
                proof.get("physicalIPhoneTested") is not False):
            raise ValueError(f"{shard}: proof differs from exact run, source, or expected selectors")
        exact_summary(summary, len(names))
        images = {name: archive.read(name) for name in members if name.startswith("review/flow/") and name.endswith(".png")}
        if not images or any(not data.startswith(b"\x89PNG\r\n\x1a\n") for data in images.values()):
            raise ValueError(f"{shard}: missing actual PNG attachments")
        if proof.get("attachmentImages") != len(images):
            raise ValueError(f"{shard}: PNG count mismatch")
        diagnostic = archive.read("review/simulator-test.log.summary.json") if "review/simulator-test.log.summary.json" in members else None
        return proof, summary, raw, images, diagnostic


def aggregate(core_a_path, core_b_path, core_c_path, added_path, output, source_sha, run_id, attempt):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha) or not run_id.isdecimal() or not attempt.isdecimal():
        raise ValueError("invalid source SHA, run ID, or attempt")
    items = [(shard, from_artifact(path, shard, source_sha, run_id, attempt)) for shard, path in zip(
        SHARDS, (core_a_path, core_b_path, core_c_path, added_path))]
    all_names = [name for _shard, item in items for name in item[0]["passedSelectors"]]
    if len(all_names) != 54 or set(all_names) != set(selectors()) or len(set(all_names)) != 54:
        raise ValueError("combined shards do not cover each of the 54 selectors exactly once")
    attachments = sum(len(item[3]) for _shard, item in items)
    merged = {
        "result": "Passed", "passedTests": 54, "totalTestCount": 54,
        "failedTests": 0, "skippedTests": 0, "expectedFailures": 0, "testFailures": [],
        "source": "four actual current-source xcresult summaries", "sourceSha": source_sha,
        "runId": run_id, "runAttempt": attempt, "shards": list(SHARDS),
        "title": "Aggregated Test - VPN013Auto",
        "devicesAndConfigurations": [
            dict(item[1]["devicesAndConfigurations"][0], shard=shard)
            for shard, item in items
        ],
    }
    scope = {
        "iPhoneNativeSuite": 54, "renderedEvidence": "actual XCUITest attachments from four current-source shards",
        "attachmentImages": attachments, "physicalIPhoneTested": False,
        "iPadTested": False, "standaloneCapturesAccepted": False,
        "sourceSha": source_sha, "runId": run_id, "runAttempt": attempt,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("review/test-summary.json", json.dumps(merged, indent=2) + "\n")
        archive.writestr("review/iphone-only-scope.json", json.dumps(scope, indent=2) + "\n")
        for shard, item in items:
            proof, _summary, raw, images, diagnostic = item
            archive.writestr(f"review/shard-proof-{shard}.json", json.dumps(proof, indent=2) + "\n")
            archive.writestr(f"review/test-summary-{shard}.json", raw)
            if diagnostic is not None:
                archive.writestr(f"review/simulator-test-{shard}.summary.json", diagnostic)
            for name, data in images.items():
                archive.writestr(f"review/flow/{shard}/{Path(name).name}", data)
    print(f"Native UI aggregate: 54/54 passed once; source={source_sha}; run={run_id}; attachments={attachments}", flush=True)


def verify_combined(path, source_sha, run_id, attempt, review=None, require_current_git=True):
    """Recheck the same-run combined artifact before it can enter a release."""
    selectors()  # Also pins the reviewed UI methods and WireGuard fixture body.
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha) or not run_id.isdecimal() or not attempt.isdecimal():
        raise ValueError("invalid release source or run identity")
    if require_current_git:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        if head != source_sha:
            raise ValueError("release checkout differs from reviewed current-run source")
    with zipfile.ZipFile(path) as archive:
        names_in_zip = archive.namelist()
        if len(set(names_in_zip)) != len(names_in_zip):
            raise ValueError("duplicate combined artifact member")
        relative_members = {name: safe_review_member(name) for name in names_in_zip}
        if any(stat.S_ISLNK(info.external_attr >> 16) for info in archive.infolist()):
            raise ValueError("symbolic links are not allowed in combined artifact")
        members = set(names_in_zip)
        required = {"review/test-summary.json", "review/iphone-only-scope.json"}
        if not required.issubset(members):
            raise ValueError("combined artifact lacks summary or image scope")
        raw_summary = archive.read("review/test-summary.json")
        summary = json.loads(raw_summary)
        scope = json.loads(archive.read("review/iphone-only-scope.json"))
        if any(summary.get(key) != value for key, value in {
            "result": "Passed", "passedTests": 54, "totalTestCount": 54,
            "failedTests": 0, "skippedTests": 0, "expectedFailures": 0, "testFailures": [],
            "source": "four actual current-source xcresult summaries", "sourceSha": source_sha,
            "runId": run_id, "runAttempt": attempt, "shards": list(SHARDS),
        }.items()):
            raise ValueError("combined summary is stale or incomplete")
        rows = summary.get("devicesAndConfigurations")
        if not isinstance(rows, list) or len(rows) != len(SHARDS):
            raise ValueError("combined simulator rows are incomplete")
        if any(scope.get(key) != value for key, value in {
            "iPhoneNativeSuite": 54, "physicalIPhoneTested": False, "iPadTested": False,
            "standaloneCapturesAccepted": False, "sourceSha": source_sha,
            "runId": run_id, "runAttempt": attempt,
        }.items()):
            raise ValueError("combined scope is stale or inaccurate")
        seen = []
        image_count = 0
        for index, shard in enumerate(SHARDS):
            proof_name = f"review/shard-proof-{shard}.json"
            result_name = f"review/test-summary-{shard}.json"
            if proof_name not in members or result_name not in members:
                raise ValueError(f"{shard}: original evidence missing from combined artifact")
            proof = json.loads(archive.read(proof_name))
            result_bytes = archive.read(result_name)
            result = json.loads(result_bytes)
            names = expected(shard)
            if any(proof.get(key) != value for key, value in {
                "schema": 1, "shard": shard, "sourceSha": source_sha,
                "runId": run_id, "runAttempt": attempt, "jobId": "native",
                "passedSelectors": list(names), "passedTests": len(names),
                "summarySha256": hashlib.sha256(result_bytes).hexdigest(),
                "physicalIPhoneTested": False,
            }.items()):
                raise ValueError(f"{shard}: source, job, run or selector proof mismatch")
            exact_summary(result, len(names))
            if rows[index] != dict(result["devicesAndConfigurations"][0], shard=shard):
                raise ValueError(f"{shard}: merged simulator row differs from original")
            images = [name for name in members if name.startswith(f"review/flow/{shard}/") and name.endswith(".png")]
            if not images or proof.get("attachmentImages") != len(images):
                raise ValueError(f"{shard}: image count mismatch")
            if any(not archive.read(name).startswith(b"\x89PNG\r\n\x1a\n") for name in images):
                raise ValueError(f"{shard}: invalid XCUITest image")
            image_count += len(images)
            seen.extend(names)
        if image_count != scope.get("attachmentImages") or len(seen) != 54 or len(set(seen)) != 54 or set(seen) != set(selectors()):
            raise ValueError("combined attachments or selector coverage is incomplete")
        if review is not None:
            if review.is_symlink():
                raise ValueError("review destination cannot be a symlink")
            root = review.resolve()
            targets = []
            # Resolve every destination before writing any member. Existing
            # symlinked parents or files cannot redirect output outside review.
            for name, relative in relative_members.items():
                target = review.joinpath(*relative.parts)
                if not target.resolve().is_relative_to(root):
                    raise ValueError("combined artifact target escapes review directory")
                targets.append((name, target))
            review.mkdir(parents=True, exist_ok=True)
            for name, target in targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.resolve().is_relative_to(root):
                    raise ValueError("combined artifact target changed outside review directory")
                target.write_bytes(archive.read(name))
    print(f"Same-run native UI artifact verified: 54/54, source={source_sha}, run={run_id}, attempt={attempt}, images={image_count}", flush=True)
    return raw_summary


def watchdog_diagnostics(shard, seconds, group_stopped=True):
    """Best-effort diagnostics only; a timeout never creates a passing proof."""
    review = ROOT / "build/review"
    if review.is_symlink():
        raise ValueError("review destination cannot be a symlink")
    review.mkdir(parents=True, exist_ok=True)
    (review / "shard-proof.json").unlink(missing_ok=True)
    for name in ("watchdog-xcresult-summary.json", "watchdog-state.json"):
        target = review / name
        if target.is_symlink() or not target.resolve().is_relative_to(review.resolve()):
            raise ValueError("watchdog output escapes review directory")
    state = {"shard": shard, "timedOut": True, "seconds": seconds, "groupStopped": group_stopped, "proofAvailable": False,
             "summaryExported": False, "attachmentImages": 0, "attachmentBytes": 0}
    result = ROOT / "build/AutoTunnel.xcresult"
    if group_stopped and result.is_dir() and not result.is_symlink():
        with tempfile.TemporaryDirectory(prefix="vpn013-watchdog-") as temporary:
            folder = Path(temporary)
            summary = folder / "summary.json"
            try:
                with summary.open("wb") as output:
                    completed = subprocess.run(["xcrun", "xcresulttool", "get", "test-results", "summary", "--path", str(result)],
                        stdout=output, stderr=subprocess.DEVNULL, timeout=25, check=False)
                if completed.returncode == 0 and 0 < summary.stat().st_size <= 8 * 1024 * 1024:
                    raw = summary.read_bytes()
                    if isinstance(json.loads(raw), dict):
                        (review / "watchdog-xcresult-summary.json").write_bytes(raw)
                        state["summaryExported"] = True
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
            exported = folder / "flow"
            try:
                completed = subprocess.run(["xcrun", "xcresulttool", "export", "attachments", "--path", str(result), "--output-path", str(exported)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=35, check=False)
                if completed.returncode == 0 and exported.is_dir() and not exported.is_symlink():
                    flow = review / "watchdog-flow"
                    if flow.is_symlink():
                        raise ValueError("watchdog image destination cannot be a symlink")
                    for directory, dirs, files in os.walk(exported, followlinks=False):
                        dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
                        for name in sorted(files):
                            image = Path(directory) / name
                            if image.is_symlink() or not image.is_file() or image.stat().st_size > 20 * 1024 * 1024:
                                continue
                            data = image.read_bytes()
                            if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                                continue
                            if state["attachmentBytes"] + len(data) > 100 * 1024 * 1024:
                                continue
                            flow.mkdir(parents=True, exist_ok=True)
                            target = flow / f"attachment-{state['attachmentImages']:03d}.png"
                            if target.is_symlink() or not target.resolve().is_relative_to(review.resolve()):
                                raise ValueError("watchdog image escapes review directory")
                            target.write_bytes(data)
                            state["attachmentImages"] += 1
                            state["attachmentBytes"] += len(data)
                            if state["attachmentImages"] >= 200:
                                break
                        if state["attachmentImages"] >= 200:
                            break
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
    (review / "watchdog-state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def run(shard, seconds):
    if shard not in SHARDS or not 1 <= seconds <= MAX_WATCHDOG_SECONDS:
        raise ValueError("invalid native shard or watchdog bound")
    log = ROOT / "build/simulator-test.log"
    proof = ROOT / "build/review/shard-proof.json"
    if proof.is_symlink() or proof.parent.is_symlink():
        raise ValueError("review proof destination cannot be a symlink")
    proof.unlink(missing_ok=True)
    env = dict(os.environ, VPN013_UI_SHARD=shard)
    process = subprocess.Popen(["sh", "inspect-on-mac.sh"], cwd=ROOT, env=env, start_new_session=True)
    deadline = time.monotonic() + seconds
    offset = 0
    partial = ""
    def progress():
        nonlocal offset, partial
        if not log.exists():
            return
        with log.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            data = handle.read()
            offset = handle.tell()
        partial += data
        lines = partial.split("\n")
        partial = lines.pop()
        for line in lines:
            match = CASE.search(line)
            if match:
                print(f"Native UI {shard}: {match.group(1)} {match.group(2)}", flush=True)
    while process.poll() is None:
        progress()
        if time.monotonic() >= deadline:
            try: os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError): pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            # The shell may have exited while xcodebuild still owns the group.
            try: os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError): pass
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: pass
            group_stopped = False
            for _ in range(50):
                try: os.killpg(process.pid, 0)
                except ProcessLookupError:
                    group_stopped = True
                    break
                except PermissionError:
                    break
                time.sleep(0.1)
            progress()
            watchdog_diagnostics(shard, seconds, group_stopped)
            print(f"Native UI {shard}: timed out after {seconds} seconds; diagnostic artifact should still upload", flush=True)
            return 124
        time.sleep(10)
    progress()
    return process.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    choose = sub.add_parser("selectors")
    choose.add_argument("shard", choices=SHARDS + ("core49", "all54"))
    verify_cmd = sub.add_parser("verify")
    verify_cmd.add_argument("shard", choices=SHARDS + ("core49", "all54"))
    verify_cmd.add_argument("--review", type=Path, default=ROOT / "build/review")
    verify_cmd.add_argument("--log", type=Path, default=ROOT / "build/simulator-test.log")
    combine = sub.add_parser("aggregate")
    combine.add_argument("--core-a", type=Path, required=True)
    combine.add_argument("--core-b", type=Path, required=True)
    combine.add_argument("--core-c", type=Path, required=True)
    combine.add_argument("--added", type=Path, required=True)
    combine.add_argument("--output", type=Path, required=True)
    combine.add_argument("--source-sha", required=True)
    combine.add_argument("--run-id", required=True)
    combine.add_argument("--attempt", required=True)
    release = sub.add_parser("verify-combined")
    release.add_argument("--artifact", type=Path, required=True)
    release.add_argument("--source-sha", required=True)
    release.add_argument("--run-id", required=True)
    release.add_argument("--attempt", required=True)
    release.add_argument("--review", type=Path)
    drive = sub.add_parser("run")
    drive.add_argument("shard", choices=SHARDS)
    drive.add_argument("--seconds", type=int, default=MAX_WATCHDOG_SECONDS)
    args = parser.parse_args()
    try:
        if args.command == "selectors":
            print(" ".join("-only-testing:" + PREFIX + name for name in expected(args.shard)))
        elif args.command == "verify":
            verify(args.shard, args.review, args.log)
        elif args.command == "aggregate":
            aggregate(args.core_a, args.core_b, args.core_c, args.added, args.output, args.source_sha, args.run_id, args.attempt)
        elif args.command == "verify-combined":
            verify_combined(args.artifact, args.source_sha, args.run_id, args.attempt, args.review)
        else:
            return run(args.shard, args.seconds)
    except (ValueError, OSError, KeyError, json.JSONDecodeError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        print(f"Native UI evidence BLOCKED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
