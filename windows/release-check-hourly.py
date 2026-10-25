"""Require every discovered test, no skip and no partial-green report."""
from pathlib import Path
import json, subprocess, sys

out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
native = sys.argv[2] == 'windows'
packages = ['./r013probe/...','./r013tun'] + (['./r013gate', './r013winudp','./r013vault','./r013prepare','./manager','./r013','github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall','github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'] if native else [])
# Source staging retains client vendor customizations and refreshes separately
# pinned official Go dependencies. Tests must not change the staged manifests.
before = {f: Path(f).read_bytes() for f in ('go.mod', 'go.sum')}
listed = subprocess.run(['go', 'test', '-mod=vendor', '-list', '^Test', *packages], capture_output=True, text=True)
(out / 'inventory.txt').write_text(listed.stdout + listed.stderr,encoding='utf-8')
assert listed.returncode == 0, listed.stderr
expected = set(line.strip() for line in listed.stdout.splitlines() if line.startswith('Test'))
assert len(expected) == (99 if native else 45), expected
result = subprocess.run(['go', 'test', '-mod=vendor', '-race', '-p=1', '-count=1', '-timeout=5m', '-json', *packages], capture_output=True, text=True)
(out / 'tests.jsonl').write_text(result.stdout, encoding='utf-8')
(out / 'stderr.txt').write_text(result.stderr, encoding='utf-8')
events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
bad = [e for e in events if e.get('Action') in ('fail', 'skip')]
passed = {e['Test'] for e in events if e.get('Action') == 'pass' and 'Test' in e and '/' not in e['Test']}
assert result.returncode == 0 and not bad and passed == expected, {'exit': result.returncode, 'missing': sorted(expected-passed), 'bad': bad}
assert before == {f: Path(f).read_bytes() for f in before}, 'module files changed'
vet = subprocess.run(['go', 'vet', '-mod=vendor', './r013probe/...','./r013tun'] + (['./r013winudp','./r013vault','./r013prepare'] if native else []), capture_output=True, text=True)
(out / 'vet.txt').write_text(vet.stdout + vet.stderr)
assert vet.returncode == 0, vet.stderr
if native:
    # MapViewOfFile returns a native uintptr; conversion into that mapping is
    # intentional. All other vet analyzers remain enabled for the gate package.
    vet = subprocess.run(['go', 'vet', '-mod=vendor', '-unsafeptr=false', './r013gate'], capture_output=True, text=True)
    (out / 'gate-vet.txt').write_text(vet.stdout + vet.stderr)
    assert vet.returncode == 0, vet.stderr
summary = {'platform': sys.argv[2], 'top_level': len(passed), 'subtests': sum(e.get('Action')=='pass' and '/' in e.get('Test','') for e in events), 'skip': 0, 'fail': 0, 'tests': sorted(passed), 'scope': 'prototype lifecycle and isolated SYSTEM/Wintun fixtures; NOT a released hourly coordinator or owner-device proof'}
(out / 'verification.json').write_text(json.dumps(summary, indent=2))
print(json.dumps(summary))
