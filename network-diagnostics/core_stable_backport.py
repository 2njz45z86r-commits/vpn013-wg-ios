"""Test a security-only dependency backport onto the proven gVisor WG stack.

No production installation and no customer key/profile. The newer core's
different TCP/IP stack timed out in both external network controls; the exact
cause is unconfirmed. This preserves the older upstream implementation and
updates only its toolchain and explicitly pinned vulnerable dependencies.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

SOURCE = 'b26a91de4f3294e26a0ad0a970b81a386a41f789'
ROOT = Path.cwd()
TREE = ROOT/'upstream'
OUT = ROOT/'stable-core-results'
OUT.mkdir()
UPDATES = {'golang.org/x/net': 'v0.62.0', 'golang.org/x/crypto': 'v0.58.0',
           'github.com/andybalholm/brotli': 'v1.2.3', 'github.com/klauspost/compress': 'v1.20.0'}
report = {'scope': 'Uninstalled diagnostic security backport, not release approval',
          'source': SOURCE, 'upstream_tag': 'v26.9.30', 'dependency_updates': UPDATES,
          'analysis_complete': False, 'binary_scan_clear': False, 'tests_passed': False}


def run(args, timeout=240):
    return subprocess.run(args, cwd=TREE, capture_output=True, text=True,
                          timeout=timeout, check=True)


def events(s):
    dec = json.JSONDecoder()
    while s.strip():
        obj, end = dec.raw_decode(s.lstrip())
        yield obj
        s = s.lstrip()[end:]


try:
    report['phase'] = 'provenance'
    assert run(['git', 'rev-parse', 'HEAD']).stdout.strip() == SOURCE
    assert not run(['git', 'status', '--porcelain']).stdout.strip()
    assert run(['go', 'version']).stdout.strip().endswith('go1.27.3 linux/amd64')
    wg = TREE/'proxy/wireguard/netstack.go'
    assert '"gvisor.dev/gvisor/pkg/tcpip"' in wg.read_text()
    before = (TREE/'go.mod').read_bytes()
    source_hash = hashlib.sha256(wg.read_bytes()).hexdigest()
    report['phase'] = 'dependency-update'
    run(['go', 'get', *[name+'@'+version for name,version in UPDATES.items()]])
    run(['go', 'mod', 'verify'])
    graph = json.loads(run(['go', 'list', '-m', '-json', 'golang.org/x/net']).stdout)
    assert graph['Version'] == UPDATES['golang.org/x/net']
    # Source changes are forbidden, including accidental automatic generator edits.
    assert set(run(['git', 'diff', '--name-only']).stdout.splitlines()) <= {'go.mod', 'go.sum'}
    assert hashlib.sha256(wg.read_bytes()).hexdigest() == source_hash
    env = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0')
    binary = OUT/'xray-linux-amd64'
    report['phase'] = 'build'
    subprocess.run(['go','build','-mod=readonly','-trimpath','-o',str(binary),'./main'],
                   cwd=TREE, env=env, capture_output=True, text=True, timeout=480, check=True)
    report.update(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  binary_bytes=binary.stat().st_size,
                  build_information=run(['go','version','-m',str(binary)]).stdout,
                  wireguard_netstack_source_sha256=source_hash,
                  original_go_mod_sha256=hashlib.sha256(before).hexdigest(),
                  updated_go_mod_sha256=hashlib.sha256((TREE/'go.mod').read_bytes()).hexdigest())
    scanner = Path(os.environ['HOME'])/'go/bin/govulncheck'
    report['phase'] = 'security-analysis'
    scan = subprocess.run([str(scanner),'-mode=binary','-json',str(binary)],
                          capture_output=True, text=True, timeout=240)
    scan_events = list(events(scan.stdout))
    findings = [x['finding'] for x in scan_events if 'finding' in x]
    symbols = [x for x in findings if any(t.get('function') for t in x.get('trace',[]))]
    report.update(scanner_exit_code=scan.returncode, analysis_complete=scan.returncode in (0,3),
                  binary_scan_clear=scan.returncode==0 and not symbols,
                  symbol_finding_events=len(symbols), module_finding_events=len(findings),
                  scanner_configuration=[x['config'] for x in scan_events if 'config' in x])
    report['phase'] = 'tests'
    test = subprocess.run(['go','test','-mod=readonly','-json','-timeout=120s',
                           './proxy/wireguard','./app/proxyman/command','./app/router',
                           'golang.org/x/net/html'], cwd=TREE, env=env,
                          capture_output=True, text=True, timeout=300)
    ts = [json.loads(line) for line in test.stdout.splitlines() if line.startswith('{')]
    report.update(test_exit_code=test.returncode, tests_passed=test.returncode==0,
                  passed_test_events=sum(x.get('Action')=='pass' and bool(x.get('Test')) for x in ts),
                  failed_test_events=sum(x.get('Action')=='fail' and bool(x.get('Test')) for x in ts),
                  packages=[{'package':x['Package'],'outcome':x['Action']} for x in ts
                            if x.get('Package') and not x.get('Test') and x.get('Action') in ('pass','fail','skip')])
    assert set(run(['git','diff','--name-only']).stdout.splitlines()) <= {'go.mod','go.sum'}
    report['only_dependency_files_changed'] = True
    report['phase'] = 'complete'
except Exception as error:
    report['error_type'] = type(error).__name__
    if isinstance(error, subprocess.CalledProcessError) and report['phase'] in ('dependency-update','build'):
        print((error.stderr or '')[-1800:])
finally:
    if not (report.get('binary_scan_clear') and report.get('tests_passed')):
        (OUT/'xray-linux-amd64').unlink(missing_ok=True)
    (OUT/'summary.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({k: report.get(k) for k in ['analysis_complete','binary_scan_clear',
                     'symbol_finding_events','tests_passed','passed_test_events','error_type']}))
if not (report.get('binary_scan_clear') and report.get('tests_passed')):
    raise SystemExit(1)
