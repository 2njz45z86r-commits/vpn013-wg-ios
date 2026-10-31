"""Evidence gate tests; synthetic XCTest records are never release evidence."""

import hashlib
import contextlib
import io
import json
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
    def test_exact_partition_matches_current_source(self):
        core, added = gate.expected("core49"), gate.expected("added5")
        self.assertEqual((len(core), len(added)), (49, 5))
        self.assertEqual(set(core) | set(added), set(gate.expected("all54")))
        self.assertFalse(set(core) & set(added))

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

    def test_aggregate_accepts_only_two_same_source_actual_shards(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core, added, output = (root / name for name in ("core.zip", "added.zip", "combined.zip"))
            artifact(core, "core49")
            artifact(added, "added5")
            with contextlib.redirect_stdout(io.StringIO()):
                gate.aggregate(core, added, output, SHA, RUN, ATTEMPT)
            with zipfile.ZipFile(output) as archive:
                merged = json.loads(archive.read("review/test-summary.json"))
                self.assertEqual(merged["passedTests"], 54)
                self.assertEqual(merged["totalTestCount"], 54)
                self.assertEqual(len([n for n in archive.namelist() if n.endswith(".png")]), 2)
            with contextlib.redirect_stdout(io.StringIO()):
                verified = gate.verify_combined(output, SHA, RUN, ATTEMPT,
                    review=root / "review", require_current_git=False)
            self.assertEqual(json.loads(verified)["passedTests"], 54)
            self.assertEqual((root / "review/test-summary.json").read_bytes(), verified)
            self.assertEqual(len(list((root / "review/flow").rglob("*.png"))), 2)
            for bad_sha, bad_run, bad_attempt in (("b" * 40, RUN, ATTEMPT), (SHA, "999", ATTEMPT), (SHA, RUN, "2")):
                with self.assertRaises(ValueError):
                    gate.verify_combined(output, bad_sha, bad_run, bad_attempt, require_current_git=False)
            for source, names, attempt in (
                ("b" * 40, None, ATTEMPT),
                (SHA, list(gate.expected("added5"))[:-1] + [gate.expected("core49")[0]], ATTEMPT),
                (SHA, None, "2"),
            ):
                artifact(added, "added5", source=source, names=names, attempt=attempt)
                with self.assertRaises(ValueError):
                    gate.aggregate(core, added, output, SHA, RUN, ATTEMPT)

    def test_release_gate_rejects_missing_shard_proof_and_png(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core, added, combined = (root / name for name in ("core.zip", "added.zip", "combined.zip"))
            artifact(core, "core49")
            artifact(added, "added5")
            with contextlib.redirect_stdout(io.StringIO()):
                gate.aggregate(core, added, combined, SHA, RUN, ATTEMPT)
            with zipfile.ZipFile(combined) as archive:
                values = {name: archive.read(name) for name in archive.namelist()}
            for missing in ("review/shard-proof-core49.json", "review/flow/added5/fixture.png"):
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
            core, added, combined = (root / name for name in ("core.zip", "added.zip", "combined.zip"))
            artifact(core, "core49")
            artifact(added, "added5")
            with contextlib.redirect_stdout(io.StringIO()):
                gate.aggregate(core, added, combined, SHA, RUN, ATTEMPT)
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
                with zipfile.ZipFile(core) as source, zipfile.ZipFile(duplicate_shard, "w") as archive:
                    for name in source.namelist():
                        archive.writestr(name, source.read(name))
                    archive.writestr("review/test-summary.json", b"duplicate")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                gate.from_artifact(duplicate_shard, "core49", SHA, RUN, ATTEMPT)

    def test_existing_symlink_parent_cannot_redirect_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core, added, combined = (root / name for name in ("core.zip", "added.zip", "combined.zip"))
            artifact(core, "core49")
            artifact(added, "added5")
            with contextlib.redirect_stdout(io.StringIO()):
                gate.aggregate(core, added, combined, SHA, RUN, ATTEMPT)
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


if __name__ == "__main__":
    unittest.main()
