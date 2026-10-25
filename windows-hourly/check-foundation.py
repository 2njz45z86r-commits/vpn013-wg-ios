"""Require every discovered test, no skip and no partial-green report."""
from pathlib import Path
import json, subprocess, sys

out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
native = sys.argv[2] == 'windows'
packages = ['./r013probe/...'] + (['./r013gate', './r013winudp'] if native else [])
# Readonly module mode adds the already-pinned x/net/dns/dnsmessage package,
# omitted from the original minimal vendor tree. Versions/sums stay immutable.
before = {f: Path(f).read_bytes() for f in ('go.mod', 'go.sum')}
listed = subprocess.run(['go', 'test', '-mod=readonly', '-list', '^Test', *packages], capture_output=True, text=True)
(out / 'inventory.txt').write_text(listed.stdout + listed.stderr,encoding='utf-8')
assert listed.returncode == 0, listed.stderr
expected = set(line.strip() for line in listed.stdout.splitlines() if line.startswith('Test'))
assert len(expected) == (50 if native else 40), expected
result = subprocess.run(['go', 'test', '-mod=readonly', '-race', '-count=1', '-timeout=5m', '-json', *packages], capture_output=True, text=True)
(out / 'tests.jsonl').write_text(result.stdout, encoding='utf-8')
(out / 'stderr.txt').write_text(result.stderr, encoding='utf-8')
events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
bad = [e for e in events if e.get('Action') in ('fail', 'skip')]
passed = {e['Test'] for e in events if e.get('Action') == 'pass' and 'Test' in e and '/' not in e['Test']}
assert result.returncode == 0 and not bad and passed == expected, {'exit': result.returncode, 'missing': sorted(expected-passed), 'bad': bad}
assert before == {f: Path(f).read_bytes() for f in before}, 'module files changed'
vet = subprocess.run(['go', 'vet', '-mod=readonly', './r013probe/...'] + (['./r013winudp'] if native else []), capture_output=True, text=True)
(out / 'vet.txt').write_text(vet.stdout + vet.stderr)
assert vet.returncode == 0, vet.stderr
if native:
    # MapViewOfFile returns a native uintptr; conversion into that mapping is
    # intentional. All other vet analyzers remain enabled for the gate package.
    vet = subprocess.run(['go', 'vet', '-mod=readonly', '-unsafeptr=false', './r013gate'], capture_output=True, text=True)
    (out / 'gate-vet.txt').write_text(vet.stdout + vet.stderr)
    assert vet.returncode == 0, vet.stderr
summary = {'platform': sys.argv[2], 'top_level': len(passed), 'subtests': sum(e.get('Action')=='pass' and '/' in e.get('Test','') for e in events), 'skip': 0, 'fail': 0, 'tests': sorted(passed), 'scope': 'kernel barrier and loopback pin primitives, not Wintun integration or shipped client'}
(out / 'verification.json').write_text(json.dumps(summary, indent=2))
print(json.dumps(summary))
