#!/usr/bin/env python3
"""Test the guarded patch against a local clone containing pinned Apple 9d5ee60.

Usage: python3 scripts/tests/test_patch_primary_resource_swift.py /path/to/apple-clone
The clone is read with git show; the test patches only temporary copies.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import patch_primary_resource_swift as patcher


PIN = "9d5ee60edefa95b933a738dd7cda671dd18021fc"


def source_tree(clone: Path, temporary: Path) -> None:
    for relative in patcher.PINNED_SHA256:
        target = temporary / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output(
            ["git", "show", f"{PIN}:{relative.as_posix()}"], cwd=clone
        ))


def expect_rejected(root: Path, reason: str) -> None:
    try:
        patcher.patch(root)
    except ValueError as error:
        assert "SHA-256 mismatch" in str(error), str(error)
    else:
        raise AssertionError(f"accepted {reason}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("supply path to a local pinned Apple git clone")
    clone = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        source_tree(clone, root)
        patcher.patch(root)
        parser = (root / patcher.PARSER).read_text(encoding="utf-8")
        editor = (root / patcher.EDITOR).read_text(encoding="utf-8")
        assert parser.count("enum VPN013PrimaryResourceBudget") == 1
        assert parser.count("VPN013PrimaryResourceBudget.valid(") == 1
        assert editor.count("VPN013PrimaryResourceBudget.valid(") == 1
        assert "interfaceHasInvalidCustomParam(junkPacketCountString)" not in parser
        expect_rejected(root, "repeat patch")
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        source_tree(clone, root)
        (root / patcher.EDITOR).write_bytes((root / patcher.EDITOR).read_bytes() + b"\n")
        expect_rejected(root, "tampered upstream source")
    print("primary Swift patch: pinned source, both preflight calls, and refusal guards passed")


if __name__ == "__main__":
    main()
