"""Evidence gate tests; synthetic XCTest records are never release evidence."""

import hashlib
import contextlib
import io
import json
import signal
import stat
import subprocess
from types import SimpleNamespace
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_ui_shards as gate


SHA = "a" * 40
RUN = "41161981450"
ATTEMPT = "1"
PNG = b"\x89PNG\r\n\x1a\nsynthetic"
REAL_SELECTORS = gate.selectors
SYNTHETIC_SELECTORS = tuple(sorted([f"testCore{i:02d}" for i in range(49)] + list(gate.ADDED)))


def summary(count):
    return {
        "result": "Passed", "passedTests": count, "totalTestCount": count,
        "failedTests": 0, "skippedTests": 0, "expectedFailures": 0, "testFailures": [],
        "devicesAndConfigurations": [{
            "passedTests": count, "failedTests": 0, "skippedTests": 0,
            "expectedFailures": 0, "device": {"platform": "iOS Simulator"},
        }],
    }


def artifact(path, shard, *, source=SHA, names=None, attempt=ATTEMPT):
    names = list(names if names is not None else gate.expected(shard))
    raw = json.dumps(summary(len(names))).encode()
    proof = {
        "schema": 1, "shard": shard, "sourceSha": source, "runId": RUN,
        "runAttempt": attempt, "jobId": "native", "passedSelectors": names,
        "passedTests": len(names), "summarySha256": hashlib.sha256(raw).hexdigest(),
        "attachmentImages": 1, "physicalIPhoneTested": False,
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("review/test-summary.json", raw)
        archive.writestr("review/shard-proof.json", json.dumps(proof))
        archive.writestr("review/flow/fixture.png", PNG)


class NativeUIShardsTests(unittest.TestCase):
    def setUp(self):
        self.selectors_patch = mock.patch.object(gate, "selectors", return_value=SYNTHETIC_SELECTORS)
        self.selectors_patch.start()
        self.addCleanup(self.selectors_patch.stop)

    def test_real_source_pin_fails_closed_when_not_reviewed(self):
        raw = (gate.ROOT / "overlay/VPN013/UITests.swift").read_bytes()
        if hashlib.sha256(raw).hexdigest() != gate.UI_TEST_SOURCE_SHA256:
            with self.assertRaisesRegex(ValueError, "reviewed 54-test source changed"):
                REAL_SELECTORS()
        else:
            self.assertEqual(len(REAL_SELECTORS()), 54)

    def test_exact_partition_matches_current_source(self):
        parts = [gate.expected(shard) for shard in gate.SHARDS]
        self.assertEqual([len(part) for part in parts], [17, 16, 16, 5])
        combined = [name for part in parts for name in part]
        self.assertEqual(len(combined), len(set(combined)))
        self.assertEqual(set(combined), set(gate.expected("all54")))
        self.assertEqual(tuple(name for part in parts[:3] for name in part), gate.expected("core49"))

    def test_log_rejects_missing_duplicate_and_failed_selectors(self):
        names = gate.expected("added5")
        line = lambda name, outcome="passed": f"Test Case '-[AutoTunnelUITests.AutoTunnelUITests {name}]' {outcome} (1.0 seconds)."
        good = "\n".join(line(name) for name in names)
        gate.exact_log(good, names)
        for bad in ("\n".join(line(name) for name in names[:-1]), good + "\n" + line(names[0]), good + "\n" + line(names[0], "failed")):
            with self.assertRaises(ValueError):
                gate.exact_log(bad, names)

    def test_summary_rejects_skips_and_wrong_count(self):
        gate.exact_summary(summary(5), 5)
        for field, value in (("skippedTests", 1), ("totalTestCount", 4), ("result", "Failed")):
            invalid = summary(5)
            invalid[field] = value
            with self.assertRaises(ValueError):
                gate.exact_summary(invalid, 5)

    def test_timeout_kills_owned_group_before_diagnostic_and_never_succeeds(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            proc = mock.Mock(pid=12345)
            proc.poll.return_value = None
            proc.wait.return_value = 0
            events = []
            def kill_group(pid, sig):
                events.append((pid, sig))
                if sig == 0: raise ProcessLookupError()
            with mock.patch.object(gate, "ROOT", root), mock.patch.object(gate.subprocess, "Popen", return_value=proc), \
                 mock.patch.object(gate.time, "monotonic", side_effect=[0, 2]), \
                 mock.patch.object(gate.signal, "SIGKILL", 9, create=True), \
                 mock.patch.object(gate.os, "killpg", side_effect=kill_group, create=True), \
                 mock.patch.object(gate, "watchdog_diagnostics", side_effect=lambda shard, sec, stopped: events.append((shard, sec, stopped))), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.run("coreA", 1), 124)
            self.assertEqual(events, [(12345, signal.SIGTERM), (12345, 9), (12345, 0), ("coreA", 1, True)])

    def test_watchdog_export_is_diagnostic_only_and_unfinished_result_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            result = root / "build/AutoTunnel.xcresult"
            result.mkdir(parents=True)
            review = root / "build/review"
            review.mkdir()
            (review / "shard-proof.json").write_text("stale")
            def export(args, **kwargs):
                if "summary" in args:
                    kwargs["stdout"].write(json.dumps(summary(17)).encode())
                else:
                    target = Path(args[args.index("--output-path") + 1])
                    target.mkdir()
                    (target / "attachment").write_bytes(PNG)
                return SimpleNamespace(returncode=0)
            with mock.patch.object(gate, "ROOT", root), mock.patch.object(gate.subprocess, "run", side_effect=export):
                gate.watchdog_diagnostics("coreA", 2400)
            state = json.loads((review / "watchdog-state.json").read_text())
            self.assertTrue(state["timedOut"] and state["summaryExported"])
            self.assertFalse(state["proofAvailable"])
            self.assertEqual(state["attachmentImages"], 1)
            self.assertFalse((review / "shard-proof.json").exists())
            self.assertTrue((review / "watchdog-flow/attachment-000.png").is_file())
            (review / "shard-proof.json").write_text("stale")
            with mock.patch.object(gate, "ROOT", root), mock.patch.object(gate.subprocess, "run", side_effect=subprocess.TimeoutExpired("xcrun", 1)):
                gate.watchdog_diagnostics("coreB", 2400)
            state = json.loads((review / "watchdog-state.json").read_text())
            self.assertTrue(state["timedOut"])
            self.assertFalse(state["summaryExported"] or state["proofAvailable"])
            self.assertFalse((review / "shard-proof.json").exists())
            with mock.patch.object(gate, "ROOT", root), mock.patch.object(gate.subprocess, "run") as command:
                gate.watchdog_diagnostics("coreC", 2400, group_stopped=False)
            command.assert_not_called()
            state = json.loads((review / "watchdog-state.json").read_text())
            self.assertFalse(state["groupStopped"] or state["summaryExported"] or state["proofAvailable"])

    def test_zip_symlink_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "shard.zip"
            artifact(path, "coreA")
            link = zipfile.ZipInfo("review/flow/link.png")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr(link, PNG)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                gate.from_artifact(path, "coreA", SHA, RUN, ATTEMPT)

    def test_aggregate_accepts_only_four_same_source_actual_shards(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core_a, core_b, core_c, added, output = (root / name for name in ("a.zip", "b.zip", "c.zip", "added.zip", "combined.zip"))
            for path, shard in zip((core_a, core_b, core_c), gate.SHARDS[:3]): artifact(path, shard)
            artifact(added, "added5")
            with contextlib.redirect_stdout(io.StringIO()):
                gate.aggregate(core_a, core_b, core_c, added, output, SHA, RUN, ATTEMPT)
            with zipfile.ZipFile(output) as archive:
                merged = json.loads(archive.read("review/test-summary.json"))
                self.assertEqual(merged["passedTests"], 54)
                self.assertEqual(merged["totalTestCount"], 54)
                self.assertEqual(len([n for n in archive.namelist() if n.endswith(".png")]), 4)
            with contextlib.redirect_stdout(io.StringIO()):
                verified = gate.verify_combined(output, SHA, RUN, ATTEMPT,
                    review=root / "review", require_current_git=False)
            self.assertEqual(json.loads(verified)["passedTests"], 54)
            self.assertEqual((root / "review/test-summary.json").read_bytes(), verified)
            self.assertEqual(len(list((root / "review/flow").rglob("*.png"))), 4)
            for bad_sha, bad_run, bad_attempt in (("b" * 40, RUN, ATTEMPT), (SHA, "999", ATTEMPT), (SHA, RUN, "2")):
                with self.assertRaises(ValueError):
                    gate.verify_combined(output, bad_sha, bad_run, bad_attempt, require_current_git=False)
            for source, names, attempt in (
                ("b" * 40, None, ATTEMPT),
                (SHA, list(gate.expected("added5"))[:-1] + [gate.expected("coreA")[0]], ATTEMPT),
                (SHA, None, "2"),
            ):
                artifact(added, "added5", source=source, names=names, attempt=attempt)
                with self.assertRaises(ValueError):
                    gate.aggregate(core_a, core_b, core_c, added, output, SHA, RUN, ATTEMPT)
            artifact(added, "added5")
            with self.assertRaises((ValueError, FileNotFoundError)):
                gate.aggregate(core_a, root / "missing.zip", core_c, added, output, SHA, RUN, ATTEMPT)
            with self.assertRaises(ValueError):
                gate.aggregate(core_a, core_a, core_c, added, output, SHA, RUN, ATTEMPT)
            artifact(core_b, "coreB", attempt="2")
            with self.assertRaises(ValueError):
                gate.aggregate(core_a, core_b, core_c, added, output, SHA, RUN, ATTEMPT)

    def test_release_gate_rejects_missing_shard_proof_and_png(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core_a, core_b, core_c, added, combined = (root / name for name in ("a.zip", "b.zip", "c.zip", "added.zip", "combined.zip"))
            for path, shard in zip((core_a, core_b, core_c), gate.SHARDS[:3]): artifact(path, shard)
            artifact(added, "added5")
            with contextlib.redirect_stdout(io.StringIO()):
                gate.aggregate(core_a, core_b, core_c, added, combined, SHA, RUN, ATTEMPT)
            with zipfile.ZipFile(combined) as archive:
                values = {name: archive.read(name) for name in archive.namelist()}
            for missing in ("review/shard-proof-coreA.json", "review/shard-proof-coreB.json", "review/shard-proof-coreC.json", "review/flow/added5/fixture.png"):
                path = root / "tampered.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    for name, data in values.items():
                        if name != missing:
                            archive.writestr(name, data)
                with self.assertRaises(ValueError):
                    gate.verify_combined(path, SHA, RUN, ATTEMPT, require_current_git=False)

    def test_archive_paths_and_duplicate_members_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core_a, core_b, core_c, added, combined = (root / name for name in ("a.zip", "b.zip", "c.zip", "added.zip", "combined.zip"))
            for path, shard in zip((core_a, core_b, core_c), gate.SHARDS[:3]): artifact(path, shard)
            artifact(added, "added5")
            with contextlib.redirect_stdout(io.StringIO()):
                gate.aggregate(core_a, core_b, core_c, added, combined, SHA, RUN, ATTEMPT)
            with zipfile.ZipFile(combined) as archive:
                values = [(name, archive.read(name)) for name in archive.namelist()]

            for index, invalid_name in enumerate((
                "review//absolute/escape.json", "review/C:drive.json",
                "review/flow\\escape.png", "review/../escape.json",
            )):
                with self.subTest(path=invalid_name):
                    tampered = root / f"invalid-{index}.zip"
                    destination = root / f"extracted-{index}"
                    with zipfile.ZipFile(tampered, "w") as archive:
                        for name, data in values:
                            archive.writestr(name, data)
                        archive.writestr(invalid_name, b"escape")
                    # Windows zipfile normalizes backslashes while reading ZIP
                    # metadata. Feed that raw spelling to the guard explicitly.
                    with zipfile.ZipFile(tampered) as archive:
                        names = archive.namelist()
                    override = (mock.patch.object(zipfile.ZipFile, "namelist",
                        return_value=names[:-1] + [invalid_name])
                        if invalid_name not in names else contextlib.nullcontext())
                    with override, self.assertRaises(ValueError):
                        gate.verify_combined(tampered, SHA, RUN, ATTEMPT,
                            review=destination, require_current_git=False)
                    self.assertFalse(destination.exists(), "validation must finish before any write")
                    self.assertFalse((root / "escape.json").exists())

            duplicate = root / "duplicate-combined.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate, "w") as archive:
                    for name, data in values:
                        archive.writestr(name, data)
                    archive.writestr("review/test-summary.json", values[0][1])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                gate.verify_combined(duplicate, SHA, RUN, ATTEMPT,
                    review=root / "duplicate-extracted", require_current_git=False)
            self.assertFalse((root / "duplicate-extracted").exists())

            duplicate_shard = root / "duplicate-shard.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(core_a) as source, zipfile.ZipFile(duplicate_shard, "w") as archive:
                    for name in source.namelist():
                        archive.writestr(name, source.read(name))
                    archive.writestr("review/test-summary.json", b"duplicate")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                gate.from_artifact(duplicate_shard, "coreA", SHA, RUN, ATTEMPT)

    def test_existing_symlink_parent_cannot_redirect_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core_a, core_b, core_c, added, combined = (root / name for name in ("a.zip", "b.zip", "c.zip", "added.zip", "combined.zip"))
            for path, shard in zip((core_a, core_b, core_c), gate.SHARDS[:3]): artifact(path, shard)
            artifact(added, "added5")
            with contextlib.redirect_stdout(io.StringIO()):
                gate.aggregate(core_a, core_b, core_c, added, combined, SHA, RUN, ATTEMPT)
            destination, outside = root / "review", root / "outside"
            destination.mkdir()
            outside.mkdir()
            try:
                (destination / "flow").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            with self.assertRaisesRegex(ValueError, "escapes review directory"):
                gate.verify_combined(combined, SHA, RUN, ATTEMPT,
                    review=destination, require_current_git=False)
            self.assertEqual(list(outside.iterdir()), [])
            self.assertFalse((destination / "test-summary.json").exists(),
                "validation must finish before any write")

    def test_redirected_parent_is_rejected_without_os_symlink_privilege(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core_a, core_b, core_c, added, combined = (root / name for name in ("a.zip", "b.zip", "c.zip", "added.zip", "combined.zip"))
            for path, shard in zip((core_a, core_b, core_c, added), gate.SHARDS): artifact(path, shard)
            with contextlib.redirect_stdout(io.StringIO()):
                gate.aggregate(core_a, core_b, core_c, added, combined, SHA, RUN, ATTEMPT)
            destination, outside = root / "review", root / "outside"
            destination.mkdir(); outside.mkdir()
            original = Path.resolve
            def resolved(path, *args, **kwargs):
                try:
                    relative = path.relative_to(destination / "flow")
                except ValueError:
                    return original(path, *args, **kwargs)
                return original(outside / relative, *args, **kwargs)
            with mock.patch.object(Path, "resolve", resolved), self.assertRaisesRegex(ValueError, "escapes review directory"):
                gate.verify_combined(combined, SHA, RUN, ATTEMPT, review=destination, require_current_git=False)
            self.assertFalse((destination / "test-summary.json").exists())
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
