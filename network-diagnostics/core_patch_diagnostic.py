"""Build and inspect an uninstalled runtime candidate from pinned upstream source."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

SOURCE = '0afec66085a85191e9dd2a4a6646c7c9a94688d1'
ROOT = Path.cwd()
TREE = ROOT / 'upstream'
OUT = ROOT / 'core-patch-results'
OUT.mkdir()
report = {
    'upstream_source': SOURCE, 'upstream_tag': 'v26.10.29',
    'dependency_patch': {'golang.org/x/net': {'from': 'v0.61.0', 'to': 'v0.62.0'}},
    'scope': 'Uninstalled diagnostic candidate; not release or deployment approval',
    'analysis_complete': False, 'binary_scan_clear': False, 'tests_passed': False,
}

def run(args, timeout=240, cwd=TREE):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=True)

def json_events(value):
    decoder = json.JSONDecoder()
    while value.strip():
        event, offset = decoder.raw_decode(value.lstrip())
        yield event
        value = value.lstrip()[offset:]

try:
    assert run(['git', 'rev-parse', 'HEAD']).stdout.strip() == SOURCE
    assert not run(['git', 'status', '--porcelain']).stdout.strip()
    assert run(['go', 'version']).stdout.strip().endswith('go1.27.3 linux/amd64')
    mod = TREE / 'go.mod'
    before = mod.read_bytes()
    old = b'\tgolang.org/x/net v0.61.0\n'
    new = b'\tgolang.org/x/net v0.62.0\n'
    assert before.count(old) == 1 and new not in before
    mod.write_bytes(before.replace(old, new))
    report['original_go_mod_sha256'] = hashlib.sha256(before).hexdigest()
    run(['go', 'mod', 'download', 'golang.org/x/net@v0.62.0'])
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH='amd64')
    binary = OUT / 'xray-linux-amd64'
    subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-o', str(binary), './main'],
                   cwd=TREE, env=env, capture_output=True, text=True, timeout=480, check=True)
    assert mod.read_bytes() == before.replace(old, new), 'Unexpected dependency graph change'
    buildinfo = run(['go', 'version', '-m', str(binary)]).stdout
    assert '\tgolang.org/x/net\tv0.62.0\t' in buildinfo
    assert 'go1.27.3' in buildinfo
    report.update(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  binary_bytes=binary.stat().st_size, build_information=buildinfo)
    scanner = Path(os.environ['HOME']) / 'go/bin/govulncheck'
    scan = subprocess.run([str(scanner), '-json', '-mode=binary', str(binary)],
                          capture_output=True, text=True, timeout=240)
    events = list(json_events(scan.stdout))
    findings = [e['finding'] for e in events if 'finding' in e]
    symbols = [f for f in findings if any(t.get('function') for t in f.get('trace', []))]
    report.update(analysis_complete=scan.returncode in (0, 3), scanner_exit_code=scan.returncode,
                  symbol_finding_events=len(symbols), total_finding_events=len(findings),
                  binary_scan_clear=scan.returncode == 0 and not symbols,
                  scanner_configuration=[e['config'] for e in events if 'config' in e])
    # Findings and exact function traces remain out of public artifacts/logs.
    test = subprocess.run(['go', 'test', '-mod=readonly', '-json', '-timeout=90s',
                           './proxy/wireguard', './transport/internet/reality',
                           './transport/internet/splithttp', './app/observatory/...',
                           'golang.org/x/net/html'],
                          cwd=TREE, env=env, capture_output=True, text=True, timeout=240)
    tests = [json.loads(line) for line in test.stdout.splitlines() if line.startswith('{')]
    report.update(tests_passed=test.returncode == 0, test_exit_code=test.returncode,
                  actual_test_pass_count=sum(e.get('Action') == 'pass' and bool(e.get('Test')) for e in tests),
                  actual_test_fail_count=sum(e.get('Action') == 'fail' and bool(e.get('Test')) for e in tests),
                  tested_packages=[{'package': e['Package'], 'outcome': e['Action']}
                                   for e in tests if 'Package' in e and not e.get('Test')
                                   and e.get('Action') in ('pass', 'fail', 'skip')])
    assert mod.read_bytes() == before.replace(old, new)
    assert set(run(['git', 'diff', '--name-only']).stdout.splitlines()) <= {'go.mod', 'go.sum'}
    report['only_dependency_files_changed'] = True
except Exception as error:
    report['error_type'] = type(error).__name__
finally:
    if not (report.get('binary_scan_clear') and report.get('tests_passed')):
        (OUT / 'xray-linux-amd64').unlink(missing_ok=True)
    (OUT / 'summary.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({k: report.get(k) for k in ('analysis_complete', 'binary_scan_clear',
                     'symbol_finding_events', 'tests_passed', 'actual_test_pass_count', 'error_type')}))
if not (report.get('binary_scan_clear') and report.get('tests_passed')):
    raise SystemExit(1)
