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
BRIDGE = {"main.go": "r013_transport.go", "controller.go": "r013_controller.go", "primary.go": "r013_primary.go", "exercise.go": "r013_exercise.go"}

def patch_primary_api(text):
    def one(old,new):
        nonlocal text
        assert text.count(old)==1, 'Unexpected primary API source'
        text=text.replace(old,new,1)
    one('\t"strings"','\t"strings"\n\t"sync"')
    one('var tunnelHandles = make(map[int32]tunnelHandle)','var tunnelHandlesMu sync.RWMutex\nvar tunnelHandles = make(map[int32]tunnelHandle)')
    one('''\t\tlogger.Errorf("Unable to set IPC settings: %v", err)
\t\tunix.Close(dupTunFd)
\t\treturn -1
\t}

\tdev.Up()''','''\t\tlogger.Errorf("Unable to set IPC settings")
\t\tdev.Close()
\t\treturn -1
\t}

\tif err := dev.Up(); err != nil { dev.Close(); return -1 }''')
    one('\tvar i int32','\ttunnelHandlesMu.Lock()\n\tdefer tunnelHandlesMu.Unlock()\n\tvar i int32')
    one('''\tif i == math.MaxInt32 {
\t\tunix.Close(dupTunFd)''','''\tif i == math.MaxInt32 {
\t\tdev.Close()''')
    start=text.index('func wgTurnOff(');end=text.index('//export wgSetConfig',start)
    text=text[:start]+'''func wgTurnOff(tunnelHandle int32) {
    tunnelHandlesMu.Lock()
    dev, ok := tunnelHandles[tunnelHandle]
    if ok { delete(tunnelHandles, tunnelHandle) }
    tunnelHandlesMu.Unlock()
    if ok { dev.Close() }
}

'''+text[end:]
    # Every remaining map lookup copies the entry under a read lock.
    text=text.replace('\tdev, ok := tunnelHandles[tunnelHandle]', '\ttunnelHandlesMu.RLock()\n\tdev, ok := tunnelHandles[tunnelHandle]\n\ttunnelHandlesMu.RUnlock()')
    text=text.replace('\tdevice, ok := tunnelHandles[tunnelHandle]', '\ttunnelHandlesMu.RLock()\n\tdevice, ok := tunnelHandles[tunnelHandle]\n\ttunnelHandlesMu.RUnlock()')
    return text

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
    # Explicitly scoped primary integration: serialized handle registry, complete
    # failed-device cleanup and a synchronous guarded socket-rebind entry point.
    primary=destination/'api-apple.go'
    primary.write_text(patch_primary_api(primary.read_text(encoding='utf-8')),encoding='utf-8',newline='\n')
    (destination/'r013_primary_client.go').write_text((ROOT/'applebridge'/'client_primary.go.txt').read_text(encoding='utf-8'),encoding='utf-8',newline='\n')
    header=destination/'wireguard.h'
    text=header.read_text(encoding='utf-8');assert '#include "r013_bridge.h"' not in text
    header.write_text(text.replace('#define WIREGUARD_H','#define WIREGUARD_H\n#include "r013_bridge.h"',1),encoding='utf-8',newline='\n')
    makefile=destination/'Makefile'
    if makefile.exists():
        text=makefile.read_text(encoding='utf-8')
        anchor='$(GOROOT)/.prepared go.mod'
        assert text.count(anchor)==1
        text=text.replace(anchor,anchor+' $(wildcard *.go *.h r013probe/*.go)')
        makefile.write_text(text,encoding='utf-8',newline='\n')
    assert sum(p.read_text(encoding="utf-8").count("func main()") for p in destination.glob("*.go")) == 1
    print(json.dumps({"staged_files": len(outputs), "archive": "existing libwg-go.a", "main_functions": 1,
                      "primary_cleanup_and_registry_fixed": True, "synchronous_socket_bump": True,
                      "provider_lifecycle_integrated": False}))

if __name__ == "__main__":
    assert len(sys.argv) == 2, "Supply the existing Sources/WireGuardKitGo directory"
    stage(Path(sys.argv[1]))
