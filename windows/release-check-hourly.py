"""Require every discovered test, no skip and no partial-green report."""
from pathlib import Path
import json, os, subprocess, sys, time

out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
native = sys.argv[2] == 'windows'
catalog_traffic = len(sys.argv) == 4 and sys.argv[3] == 'catalog-traffic-122'
assert len(sys.argv) == 3 or catalog_traffic, 'Unknown native inventory mode'
assert not catalog_traffic or native, 'Catalog/traffic inventory requires Windows'
packages = ['./r013routing','./r013probe/...','./r013tun'] + (['./r013gate', './r013winudp','./r013vault','./r013prepare','./manager','./r013','./ui','github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall','github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'] if native else [])
if catalog_traffic:
    packages.append('./r013traffic')
# Source staging retains client vendor customizations and refreshes separately
# pinned official Go dependencies. Tests must not change the staged manifests.
before = {f: Path(f).read_bytes() for f in ('go.mod', 'go.sum')}
listed = subprocess.run(['go', 'test', '-mod=vendor', '-p=1', '-timeout=2m', '-list', '^Test', *packages], capture_output=True, text=True, timeout=240)
(out / 'inventory.txt').write_text(listed.stdout + listed.stderr,encoding='utf-8')
assert listed.returncode == 0, listed.stderr
expected = set(line.strip() for line in listed.stdout.splitlines() if line.startswith('Test'))
assert len(expected) == (122 if catalog_traffic else 112 if native else 47), expected
# Preserve evidence while tests run, including when a hosted job is cancelled.
# The earlier capture_output call kept every event in memory until completion.
# This watchdog diagnoses a red run; it does not turn partial results green.
assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
assert os.environ.get('GITHUB_REPOSITORY') == '2njz45z86r-commits/vpn013-wg-ios'
command = ['go', 'test', '-mod=vendor', '-race', '-p=1', '-count=1', '-timeout=5m', '-json', *packages]
if native:
    command.insert(2,'-x')  # retain compiler diagnostics, never runtime configs
environment = os.environ.copy()
watchdog = None
if native:
    # Compiler intermediates are NOT uploaded as acceptance artifacts.
    work = out.parent / (out.name+'-owned-go-work')
    work.mkdir()
    environment['GOTMPDIR'] = str(work)
    watchdog = subprocess.Popen([sys.executable,str(Path(__file__).with_name('fixture-watchdog.py')),
        str(out),str(work),os.environ['R013_CI_CLIENT_EXE']],
        stdout=(out/'fixture-watchdog.stdout').open('w'),stderr=(out/'fixture-watchdog.stderr').open('w'))
    for _ in range(100):
        if (out/'fixture-watchdog.ready').is_file():
            break
        assert watchdog.poll() is None, 'CI-only watchdog did not start'
        time.sleep(.1)
    assert (out/'fixture-watchdog.ready').is_file()
timed_out = False
with (out / 'tests.jsonl').open('w', encoding='utf-8') as stdout, (out / 'stderr.txt').open('w', encoding='utf-8') as stderr:
    process = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=environment)
    deadline = time.monotonic() + 20 * 60
    offset = 0
    last_heartbeat = 0
    while process.poll() is None:
        with (out / 'tests.jsonl').open('rb') as progress:
            progress.seek(offset)
            # Bound each read batch so a chatty test cannot starve the deadline.
            for _ in range(200):
                if time.monotonic()>=deadline:
                    break
                line = progress.readline(1024*1024)
                if not line:
                    break
                assert len(line)<1024*1024, 'Unbounded native output line'
                if not line.endswith(b'\n'):
                    break
                offset = progress.tell()
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                name = event.get('Test', '')
                if '/' not in name and event.get('Action') in ('start','run', 'pass', 'fail', 'skip'):
                    print(json.dumps({key:event.get(key) for key in ('Action','Package','Test','Elapsed')}), flush=True)
        if time.monotonic()-last_heartbeat>30:
            print(json.dumps({'stage':'native-inventory-alive','secondsRemaining':round(max(0,deadline-time.monotonic())),
                'ownedGoPID':process.pid,'evidenceBytes':(out/'tests.jsonl').stat().st_size,
                'compilerEvidenceBytes':(out/'stderr.txt').stat().st_size}),flush=True)
            last_heartbeat=time.monotonic()
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
if watchdog is not None:
    (out/'fixture-watchdog.stop').write_text('stop',encoding='ascii')
    watchdog.wait(timeout=20)
    assert watchdog.returncode==0 and not json.loads((out/'fixture-watchdog.json').read_text())['forced'], 'Leaked/hung owned fixture; evidence is not acceptance'
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
