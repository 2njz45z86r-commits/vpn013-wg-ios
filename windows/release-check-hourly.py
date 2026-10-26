"""Require every discovered test, no skip and no partial-green report."""
from pathlib import Path
import json, os, subprocess, sys, time

out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
native = sys.argv[2] == 'windows'
packages = ['./r013routing','./r013probe/...','./r013tun'] + (['./r013gate', './r013winudp','./r013vault','./r013prepare','./manager','./r013','./ui','github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall','github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'] if native else [])
# Source staging retains client vendor customizations and refreshes separately
# pinned official Go dependencies. Tests must not change the staged manifests.
before = {f: Path(f).read_bytes() for f in ('go.mod', 'go.sum')}
listed = subprocess.run(['go', 'test', '-mod=vendor', '-p=1', '-timeout=2m', '-list', '^Test', *packages], capture_output=True, text=True, timeout=240)
(out / 'inventory.txt').write_text(listed.stdout + listed.stderr,encoding='utf-8')
assert listed.returncode == 0, listed.stderr
expected = set(line.strip() for line in listed.stdout.splitlines() if line.startswith('Test'))
assert len(expected) == (112 if native else 47), expected
# Preserve evidence while tests run, including when a hosted job is cancelled.
# The earlier capture_output call kept every event in memory until completion.
# This watchdog diagnoses a red run; it does not turn partial results green.
assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
assert os.environ.get('GITHUB_REPOSITORY') == '2njz45z86r-commits/vpn013-wg-ios'
command = ['go', 'test', '-mod=vendor', '-race', '-p=1', '-count=1', '-timeout=5m', '-json', *packages]
timed_out = False
with (out / 'tests.jsonl').open('w', encoding='utf-8') as stdout, (out / 'stderr.txt').open('w', encoding='utf-8') as stderr:
    process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    deadline = time.monotonic() + 20 * 60
    offset = 0
    while process.poll() is None:
        with (out / 'tests.jsonl').open('rb') as progress:
            progress.seek(offset)
            for line in progress:
                if not line.endswith(b'\n'):
                    break
                offset = progress.tell()
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                name = event.get('Test', '')
                if name and '/' not in name and event.get('Action') in ('run', 'pass', 'fail', 'skip'):
                    print(json.dumps({key:event.get(key) for key in ('Action','Package','Test','Elapsed')}), flush=True)
        if time.monotonic() >= deadline:
            timed_out = True
            (out / 'deadline.json').write_text(json.dumps({'timedOut':True,'seconds':1200,'ownedPID':process.pid}))
            # This process was created above on disposable hosted CI only.
            if os.name == 'nt':
                subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,timeout=20)
            else:
                process.kill()
            process.wait(timeout=25)
            break
        time.sleep(1)
result = subprocess.CompletedProcess(command, process.returncode,
    (out / 'tests.jsonl').read_text(encoding='utf-8'), (out / 'stderr.txt').read_text(encoding='utf-8'))
assert not timed_out, 'Native inventory deadline reached; retained incomplete evidence, not acceptance'
events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
bad = [e for e in events if e.get('Action') in ('fail', 'skip')]
passed = {e['Test'] for e in events if e.get('Action') == 'pass' and 'Test' in e and '/' not in e['Test']}
if result.returncode or bad or passed != expected:
    # These are isolated synthetic fixtures, never customer configurations.
    # Retain bounded per-failing-test output so a red native run is diagnosable.
    failed = {e.get('Test') for e in bad if e.get('Test')}
    for name in sorted(failed):
        detail = ''.join(e.get('Output', '') for e in events if e.get('Test') == name)
        print(name + '\n' + detail[-12000:], flush=True)
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
