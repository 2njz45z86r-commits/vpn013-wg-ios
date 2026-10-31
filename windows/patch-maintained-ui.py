"""Apply the pinned Tailscale Walk/Win UI update to a private prepared stage.

Run after the existing VPN013 source/security patches and before source packaging.
This never runs a UI, service, installer, driver, or VPN test.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent / "ui-dependencies"
MANIFEST = json.loads((HERE / "manifest.json").read_text(encoding="utf-8-sig"))
PRIVATE_MARKER = "VPN013_UI_PRIVATE_STAGE\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    return digest(path.read_bytes())


def contained(root: Path, relative: str) -> Path:
    rel = PurePosixPath(relative)
    if rel.is_absolute() or not rel.parts or any(p in ("", ".", "..") for p in rel.parts):
        raise ValueError(f"unsafe relative path: {relative}")
    result = root.joinpath(*rel.parts)
    if not result.resolve().is_relative_to(root):
        raise ValueError(f"path escapes stage: {relative}")
    return result


def replace_once(data: bytes, before: str, after: str, label: str) -> bytes:
    old = before.encode("utf-8")
    new = after.encode("utf-8")
    if data.count(old) != 1:
        old = old.replace(b"\n", b"\r\n")
        new = new.replace(b"\n", b"\r\n")
    if data.count(old) != 1:
        raise ValueError(f"expected one exact patch anchor: {label}")
    return data.replace(old, new, 1)


BODY_EDITS: dict[str, list[tuple[str, str]]] = {
    "ui/ui.go": [
        (
            "func RunUI() {\n\truntime.LockOSThread()\n\twindows.SetProcessPriorityBoost",
            "func RunUI() {\n\truntime.LockOSThread()\n\tregisterManageTunnelsWindow()\n"
            "\tif _, err := walk.InitApp(); err != nil {\n"
            "\t\tpanic(fmt.Errorf(\"initialize UI: %w\", err))\n\t}\n"
            "\twindows.SetProcessPriorityBoost",
        ),
        (
            "\tif tray == nil {\n\t\twin.ShowWindow(mtw.Handle(), win.SW_MINIMIZE)\n\t}\n\n\tmtw.Run()",
            "\tmtw.StartHidden()\n\tif tray == nil {\n"
            "\t\twin.ShowWindow(mtw.Handle(), win.SW_MINIMIZE)\n\t}\n\n\twalk.App().Run()",
        ),
    ],
    "ui/managewindow.go": [
        (
            "func NewManageTunnelsWindow() (*ManageTunnelsWindow, error) {\n\tinitedManageTunnels.Do",
            "func registerManageTunnelsWindow() {\n\tinitedManageTunnels.Do",
        ),
        (
            "\t})\n\n\tvar err error\n\tvar disposables walk.Disposables",
            "\t})\n}\n\nfunc NewManageTunnelsWindow() (*ManageTunnelsWindow, error) {\n\n"
            "\tvar err error\n\tvar disposables walk.Disposables",
        ),
    ],
    "ui/tray.go": [
        ("walk.NewNotifyIcon(mtw)", "walk.NewNotifyIcon()"),
    ],
    "ui/r013_preview_windows.go": [
        (
            "\tEnableR013Preview()\n\twindow, err := NewManageTunnelsWindow()",
            "\tEnableR013Preview()\n\tregisterManageTunnelsWindow()\n"
            "\tif _, err := walk.InitApp(); err != nil {\n"
            "\t\tpanic(fmt.Errorf(\"initialize UI preview: %w\", err))\n\t}\n"
            "\twindow, err := NewManageTunnelsWindow()",
        ),
        ("\twindow.Run()\n\twindow.Dispose()", "\twalk.App().Run()\n\twindow.Dispose()"),
    ],
}

WALK_SHIMS: dict[str, list[tuple[str, str]]] = {
    # The compiled Walk UI never imports declarative, and this blank import
    # only initializes the archived govaluate package's internal planner.
    "vendor/github.com/tailscale/walk/expression.go": [
        (
            'import _ "gopkg.in/Knetic/govaluate.v3"\n\n',
            "",
        ),
    ],
    "vendor/github.com/tailscale/walk/form.go": [
        (
            "\tfb.SetSuspended(false)\n}\n\nfunc (fb *FormBase) Dispose()",
            "\tfb.SetSuspended(false)\n}\n\n"
            "// StartHidden initializes a form without changing visibility before App.Run.\n"
            "// VPN013 uses this to preserve its existing tray-first startup behavior.\n"
            "func (fb *FormBase) StartHidden() {\n\tfb.start()\n}\n\n"
            "func (fb *FormBase) Dispose()",
        ),
    ],
    "vendor/github.com/tailscale/walk/tableview.go": [
        (
            "\tthemeSelectedNotFocusedBGColor     Color\n\titemBGColor",
            "\tthemeSelectedNotFocusedBGColor     Color\n\tcustomPalette                      *[4]Color\n\titemBGColor",
        ),
        (
            "\t\t\t{win.PBS_NORMAL, win.TMT_TEXTCOLOR, &tv.alternatingRowTextColor},\n"
            "\t\t})\n\t}\n\n\twin.SendMessage(tv.hwndNormalLV, win.LVM_SETBKCOLOR",
            "\t\t\t{win.PBS_NORMAL, win.TMT_TEXTCOLOR, &tv.alternatingRowTextColor},\n"
            "\t\t})\n\t}\n"
            "\tif p := tv.customPalette; p != nil {\n"
            "\t\ttv.themeNormalBGColor = p[0]\n"
            "\t\ttv.themeNormalTextColor = p[1]\n"
            "\t\ttv.themeSelectedBGColor = p[2]\n"
            "\t\ttv.themeSelectedTextColor = p[3]\n"
            "\t\ttv.themeSelectedNotFocusedBGColor = p[2]\n\t}\n\n"
            "\twin.SendMessage(tv.hwndNormalLV, win.LVM_SETBKCOLOR",
        ),
        (
            "\twin.SendMessage(tv.hwndFrozenLV, win.LVM_SETBKCOLOR, 0, uintptr(tv.themeNormalBGColor))\n"
            "}\n\n// ColumnsOrderable",
            "\twin.SendMessage(tv.hwndFrozenLV, win.LVM_SETBKCOLOR, 0, uintptr(tv.themeNormalBGColor))\n"
            "\tfor _, hwnd := range []win.HWND{tv.hwndNormalLV, tv.hwndFrozenLV} {\n"
            "\t\twin.SendMessage(hwnd, win.LVM_SETTEXTCOLOR, 0, uintptr(tv.themeNormalTextColor))\n"
            "\t\twin.SendMessage(hwnd, win.LVM_SETTEXTBKCOLOR, 0, uintptr(tv.themeNormalBGColor))\n"
            "\t}\n}\n\n"
            "// SetPalette preserves the existing VPN013 table colors across system theme changes.\n"
            "func (tv *TableView) SetPalette(background, text, selection, selectedText Color) {\n"
            "\ttv.customPalette = &[4]Color{background, text, selection, selectedText}\n"
            "\ttv.ApplySysColors()\n\ttv.Invalidate()\n}\n\n// ColumnsOrderable",
        ),
    ],
}


def tree_hash(folder: Path) -> tuple[int, str]:
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError(f"missing or linked vendor directory: {folder}")
    paths = sorted(p for p in folder.rglob("*") if p.is_file())
    h = hashlib.sha256()
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"linked vendor file: {path}")
        rel = path.relative_to(folder).as_posix()
        h.update(f"{rel}\0{sha_file(path)}\n".encode("utf-8"))
    return len(paths), h.hexdigest()


def preserved_vendor_hash(stage: Path) -> str:
    vendor = stage / "vendor"
    excluded = ("vendor/modules.txt",)
    excluded_dirs = tuple(x["path"] + "/" for x in MANIFEST["obsolete_vendor"]) + tuple(
        "vendor/" + x["path"] + "/" for x in MANIFEST["modules"]
    )
    h = hashlib.sha256()
    for path in sorted(p for p in vendor.rglob("*") if p.is_file()):
        rel = path.relative_to(stage).as_posix()
        if rel in excluded or rel.startswith(excluded_dirs):
            continue
        if path.is_symlink():
            raise ValueError(f"linked vendor file: {path}")
        h.update(f"{rel}\0{sha_file(path)}\n".encode("utf-8"))
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--go", required=True, type=Path)
    args = parser.parse_args()
    private = args.private_root.resolve()
    stage = args.stage.resolve()
    if stage == private or not stage.is_relative_to(private):
        raise ValueError("stage must be inside the named private root")
    if (private / ".vpn013-ui-private-stage").read_text(encoding="ascii") != PRIVATE_MARKER:
        raise ValueError("private-stage marker missing or invalid")
    if not args.go.is_file():
        raise ValueError("named Go executable is missing")
    if not (stage / "SOURCE-MANIFEST.json").is_file():
        raise ValueError("not the expected prepared Windows source")

    replacements = MANIFEST["replacements"]
    additions = MANIFEST["additions"]
    if len(replacements) != 27 or len(additions) != 218:
        raise ValueError("unexpected patch manifest cardinality")
    all_entries = replacements + additions
    paths = [x["path"] for x in all_entries]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate output path in manifest")
    if sha_file(stage / "go.mod") != MANIFEST["source_go_mod_sha256"]:
        raise ValueError("prepared go.mod differs from pinned source")
    for entry in replacements:
        path = contained(stage, entry["path"])
        if not path.is_file() or path.is_symlink() or sha_file(path) != entry["old_sha256"]:
            raise ValueError(f"prepared source differs: {entry['path']}")
    for entry in additions:
        if contained(stage, entry["path"]).exists():
            raise ValueError(f"new dependency path already present: {entry['path']}")
    for entry in MANIFEST["obsolete_vendor"]:
        folder = contained(stage, entry["path"])
        if tree_hash(folder) != (entry["files"], entry["tree_sha256"]):
            raise ValueError(f"obsolete vendor directory differs: {entry['path']}")
    original_vendor_hash = preserved_vendor_hash(stage)

    replacement_data: dict[str, bytes] = {}
    output_by_path = {x["path"]: x for x in all_entries}
    go_paths = [x["path"] for x in replacements if x["path"].endswith(".go")]
    if len(go_paths) != 24:
        raise ValueError("expected exactly 24 first-party Go source edits")
    for relative in go_paths:
        data = contained(stage, relative).read_bytes()
        data = data.replace(b'"github.com/lxn/walk', b'"github.com/tailscale/walk')
        data = data.replace(b'"github.com/lxn/win', b'"github.com/tailscale/win')
        for index, (before, after) in enumerate(BODY_EDITS.get(relative, [])):
            data = replace_once(data, before, after, f"{relative} body edit {index}")
        if digest(data) != output_by_path[relative]["new_sha256"]:
            raise ValueError(f"source edit differs from reviewed candidate: {relative}")
        replacement_data[relative] = data
    for relative in ("go.mod", "go.sum"):
        data = (HERE / relative).read_bytes()
        if digest(data) != output_by_path[relative]["new_sha256"]:
            raise ValueError(f"pinned {relative} differs")
        replacement_data[relative] = data
    modules_data = base64.b64decode(MANIFEST["vendor_modules_b64"], validate=True)
    if digest(modules_data) != output_by_path["vendor/modules.txt"]["new_sha256"]:
        raise ValueError("vendored module list differs")
    replacement_data["vendor/modules.txt"] = modules_data

    sums = {}
    for line in replacement_data["go.sum"].decode("utf-8").splitlines():
        fields = line.split()
        if len(fields) == 3:
            sums[(fields[0], fields[1])] = fields[2]
    for module in MANIFEST["modules"]:
        key = (module["path"], module["version"])
        if sums.get(key) != module["sum"] or sums.get((key[0], key[1] + "/go.mod")) != module["go_mod_sum"]:
            raise ValueError(f"module checksum absent from pinned go.sum: {key}")

    vendor_data: dict[str, bytes] = {}
    # Go module cache files can remain locked or reappear during Windows cleanup.
    # Keep this isolated cache beside the stage until the disposable job ends.
    temporary = tempfile.mkdtemp(prefix="vpn013-ui-modules-", dir=private)
    with contextlib.nullcontext(temporary):
        temp = Path(temporary)
        if not temp.resolve().is_relative_to(private) or temp.is_relative_to(stage):
            raise ValueError("private module cache escaped the prepared workspace")
        (temp / "go.mod").write_bytes(replacement_data["go.mod"])
        (temp / "go.sum").write_bytes(replacement_data["go.sum"])
        env = dict(os.environ)
        env.update({
            "GOMODCACHE": str(temp / "modcache"),
            "GOCACHE": str(temp / "buildcache"),
            "GOWORK": "off",
            "GOTOOLCHAIN": "local",
            "GOFLAGS": "",
            "GOPROXY": "https://proxy.golang.org",
            "GOSUMDB": "sum.golang.org",
            "GONOSUMDB": "",
            "GOPRIVATE": "",
            "GOINSECURE": "",
        })
        dirs = {}
        for module in MANIFEST["modules"]:
            request = f"{module['path']}@{module['version']}"
            result = subprocess.run(
                [str(args.go), "mod", "download", "-json", request],
                cwd=temp, env=env, capture_output=True, text=True, check=True,
            )
            info = json.loads(result.stdout)
            if (info.get("Path"), info.get("Version"), info.get("Sum"), info.get("GoModSum")) != (
                module["path"], module["version"], module["sum"], module["go_mod_sum"]
            ):
                raise ValueError(f"downloaded module identity/checksum differs: {request}")
            directory = Path(info["Dir"]).resolve()
            if not directory.is_relative_to(temp / "modcache"):
                raise ValueError(f"module cache escaped private root: {request}")
            dirs[module["path"]] = directory
        if sha_file(temp / "go.sum") != digest(replacement_data["go.sum"]):
            raise ValueError("Go modified pinned go.sum during download")

        for entry in additions:
            relative = entry["path"]
            module_path = next((m for m in dirs if relative.startswith("vendor/" + m + "/")), None)
            if module_path is None:
                raise ValueError(f"unexpected vendor module: {relative}")
            suffix = relative[len("vendor/" + module_path + "/"):]
            source_file = contained(dirs[module_path], suffix)
            if not source_file.is_file() or source_file.is_symlink():
                raise ValueError(f"missing module source: {relative}")
            data = source_file.read_bytes()
            if relative in WALK_SHIMS:
                if digest(data) != MANIFEST["compat_upstream_sha256"][relative]:
                    raise ValueError(f"compatibility shim upstream changed: {relative}")
                for index, (before, after) in enumerate(WALK_SHIMS[relative]):
                    data = replace_once(data, before, after, f"{relative} shim {index}")
            if digest(data) != entry["new_sha256"]:
                raise ValueError(f"vendored module content differs: {relative}")
            vendor_data[relative] = data

    # All 245 outputs have been constructed and validated before source writes.
    for entry in all_entries:
        relative = entry["path"]
        target = contained(stage, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        data = replacement_data.get(relative, vendor_data.get(relative))
        if data is None:
            raise ValueError(f"missing output data: {relative}")
        target.write_bytes(data)
        if sha_file(target) != entry["new_sha256"]:
            raise ValueError(f"written file differs: {relative}")
    for entry in MANIFEST["obsolete_vendor"]:
        folder = contained(stage, entry["path"])
        if tree_hash(folder) != (entry["files"], entry["tree_sha256"]):
            raise ValueError(f"obsolete vendor directory changed before removal: {entry['path']}")
        shutil.rmtree(folder)
    if preserved_vendor_hash(stage) != original_vendor_hash:
        raise ValueError("unrelated vendored AWG/core source changed")
    print(f"PASS maintained UI: 24 Go sources, 3 module files, 218 pinned vendor files; old lxn vendor removed; isolated module cache retained at {temporary}")


if __name__ == "__main__":
    main()
