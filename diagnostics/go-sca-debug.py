"""Diagnose a staged Linux dependency check; no release approval or iOS claim."""
from pathlib import Path
import json
import os
import subprocess
import tempfile

repo = Path.cwd()
root = Path(os.environ['RUNNER_TEMP']) / 'staged/awg-core-owned'
target = os.environ.get('VPN013_SCAN_TARGET', 'linux')
assert target in ('linux', 'ios-nocgo')
goos, arch, package = ('ios', 'arm64', './device') if target == 'ios-nocgo' else ('linux', 'amd64', '.')
env = dict(os.environ, GOTOOLCHAIN='local', GOOS=goos, GOARCH=arch, CGO_ENABLED='0', GOFLAGS='-mod=readonly')
host = dict(env)
for key in ('GOOS', 'GOARCH', 'CGO_ENABLED', 'GOFLAGS', 'CC', 'CXX', 'CGO_CFLAGS', 'CGO_LDFLAGS'):
    host.pop(key, None)
details = {}
summary = {'scope': f'{goos}/{arch} {package} with CGO disabled; package dependencies only, not full iOS build or release approval', 'source': 'fbfde157ea5da6296ce33bcbbaf36833b933f9b0'}
with tempfile.TemporaryDirectory(prefix='vpn013-sca-') as tmp:
    install_env = dict(host, GOBIN=tmp)
    install = subprocess.run(['go', 'install', 'golang.org/x/vuln/cmd/govulncheck@v1.9.0'], env=install_env, capture_output=True, timeout=240)
    summary['installExit'] = install.returncode
    details['installStderr'] = install.stderr.decode('utf-8', errors='replace')[:10000]
    package_list = subprocess.run(['go', 'list', '-deps', package], cwd=root, env=env, capture_output=True, timeout=120)
    summary['packageListExit'] = package_list.returncode
    details['packageListStderr'] = package_list.stderr.decode('utf-8', errors='replace')[:10000]
    if install.returncode == 0 and package_list.returncode == 0:
        scan = subprocess.run([str(Path(tmp) / 'govulncheck'), '-db=https://vuln.go.dev', '-json', '-scan=package', package], cwd=root, env=env, capture_output=True, timeout=240)
        summary['scannerExit'] = scan.returncode
        summary['scannerStderrPresent'] = bool(scan.stderr.strip())
        details['scannerStderr'] = scan.stderr.decode('utf-8', errors='replace')[:10000]
        assert len(scan.stdout) <= 128 * 1024 * 1024
        raw = scan.stdout.decode('utf-8')
        details['scannerOutput'] = raw
        decoder = json.JSONDecoder()
        records = []
        while raw.strip():
            raw = raw.lstrip(); value, end = decoder.raw_decode(raw); records.append(value); raw = raw[end:]
        findings = [value['finding'] for value in records if 'finding' in value]
        summary['hasConfig'] = any('config' in value for value in records)
        summary['packageFindings'] = sum(any(frame.get('package') for frame in item.get('trace', [])) for item in findings)
        summary['moduleOnlyFindings'] = sum(not any(frame.get('package') for frame in item.get('trace', [])) for item in findings)
    report = repo / 'build/review/core-linux-debug.enc.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    encrypted = subprocess.run(['go', 'run', str(repo/'scripts/audit-envelope.go'), 'encrypt', str(repo/'scripts/audit-recipient.pub'), str(report)], input=json.dumps(details).encode(), env=host, capture_output=True, timeout=90)
    summary['encryptedDetailsSaved'] = encrypted.returncode == 0 and report.is_file()
    print(json.dumps(summary))
    assert summary.get('installExit') == 0 and summary.get('packageListExit') == 0
    assert summary.get('scannerExit') == 0 and summary.get('hasConfig') and not summary.get('scannerStderrPresent')
    assert summary.get('packageFindings') == 0 and summary['encryptedDetailsSaved']
