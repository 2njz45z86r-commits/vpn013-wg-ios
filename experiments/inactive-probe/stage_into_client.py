"""Merge an explicit source allowlist into ONE existing WireGuardKitGo archive.

Run against a disposable checkout first. Does not register provider lifecycle,
change Xcode projects, copy credentials, or produce/ship an application.
"""
from pathlib import Path
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parent
MODULE = "github.com/amnezia-vpn/amneziawg-apple"
CORE = (
    "active_guard.go", "active_guard_test.go", "controller.go", "controller_test.go",
    "dns_probe.go", "dns_probe_test.go", "identity.go", "physical_bind.go",
    "physical_bind_test.go", "probe.go", "probe_test.go", "resource_limits.go",
    "resource_limits_test.go", "scan.go", "scan_test.go",
)
BRIDGE = {"main.go": "r013_transport.go", "controller.go": "r013_controller.go", "exercise.go": "r013_exercise.go"}

def stage(destination: Path):
    destination = destination.resolve(strict=True)
    expected = json.loads((ROOT / "expected-client-source.json").read_text(encoding="utf-8"))
    for name, sha in expected["sha256_normalized_utf8"].items():
        actual = hashlib.sha256((destination / name).read_text(encoding="utf-8").replace("\r", "").encode()).hexdigest()
        assert actual == sha, "Client source/toolchain dependency snapshot changed: " + name
    module = (destination / "go.mod").read_text(encoding="utf-8")
    assert re.search(r"^module " + re.escape(MODULE) + r"$", module, re.M)
    for expected in ("github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814", "golang.org/x/net v0.57.0"):
        assert expected in module, "Unexpected client dependency set"
    originals = [p for p in destination.glob("*.go") if not p.name.endswith("_test.go")]
    assert sum(p.read_text(encoding="utf-8").count("func main()") for p in originals) == 1
    outputs = {destination / "r013probe" / name: (ROOT / name).read_text(encoding="utf-8") for name in CORE}
    for source, target in BRIDGE.items():
        text = (ROOT / "applebridge" / source).read_text(encoding="utf-8")
        if source == "main.go":
            assert text.count("func main() {}") == 1, "Unexpected bridge entry point"
            text = text.replace("func main() {}", "", 1)
        text = text.replace('"vpn013.local/awg-probe"', '"' + MODULE + '/r013probe"')
        text = text.replace('#include "bridge.h"', '#include "r013_bridge.h"')
        assert "func main()" not in text
        outputs[destination / target] = text
    outputs[destination / "r013_bridge.h"] = (ROOT / "applebridge" / "bridge.h").read_text(encoding="utf-8")
    # Validate the entire batch before writing. No implicit overwrite or deletion.
    assert not (destination / "r013probe").exists(), "Probe already staged; use a fresh disposable checkout"
    assert not any(path.exists() for path in outputs)
    original_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in originals}
    for path, text in outputs.items():
        path.parent.mkdir(exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    assert original_hashes == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in originals}
    assert sum(p.read_text(encoding="utf-8").count("func main()") for p in destination.glob("*.go")) == 1
    print(json.dumps({"staged_files": len(outputs), "archive": "existing libwg-go.a", "main_functions": 1,
                      "original_sources_preserved": True, "provider_lifecycle_integrated": False}))

if __name__ == "__main__":
    assert len(sys.argv) == 2, "Supply the existing Sources/WireGuardKitGo directory"
    stage(Path(sys.argv[1]))
