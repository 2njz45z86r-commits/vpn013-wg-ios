"""Run pinned official Go SCA without publishing detailed findings in CI logs.

This check complements the private review. Module-only matches still require
manual review; a successful scan is not approval of all 34 controls.
"""
from pathlib import Path
import argparse
import json
import os
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('root')
parser.add_argument('--level', choices=('package', 'symbol'), default='package')
parser.add_argument('--database', default='https://vuln.go.dev', help='Official live database or a separately verified local snapshot')
parser.add_argument('--encrypted-report', help='Protect detailed development evidence with the supplied public recipient')
parser.add_argument('--recipient', help='Public evidence recipient file; no private key on the runner')
args = parser.parse_args()
root = Path(args.root).resolve()
assert root.is_dir() and (root / 'go.mod').is_file()
env = dict(os.environ, GOTOOLCHAIN='local', GOSUMDB='sum.golang.org', GOPROXY='https://proxy.golang.org')
try:
    version = subprocess.check_output(['go', 'version'], env=env, text=True).strip()
    assert 'go1.26.10 ' in version
    with tempfile.TemporaryDirectory(prefix='r013-security-', dir=os.environ.get('RUNNER_TEMP')) as temporary:
        install_env = dict(env, GOBIN=temporary)
        for name in ('GOOS', 'GOARCH', 'CGO_ENABLED', 'CC', 'CXX', 'CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_LDFLAGS', 'GOFLAGS'):
            install_env.pop(name, None)
        install = subprocess.run(['go', 'install', 'golang.org/x/vuln/cmd/govulncheck@v1.9.0'],
            env=install_env, capture_output=True, timeout=240)
        assert install.returncode == 0
        scanner = Path(temporary) / ('govulncheck.exe' if os.name == 'nt' else 'govulncheck')
        scan = subprocess.run([str(scanner), '-db', args.database, '-json', '-scan', args.level, '.'],
            cwd=root, env=env, capture_output=True, timeout=240)
        assert scan.returncode == 0 and not scan.stderr.strip()
        assert len(scan.stdout) <= 128 * 1024 * 1024
        if args.encrypted_report:
            assert args.recipient
            host_env = dict(env)
            for name in ('GOOS', 'GOARCH', 'CGO_ENABLED', 'CC', 'CXX', 'CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_LDFLAGS', 'GOFLAGS'):
                host_env.pop(name, None)
            helper = Path(__file__).with_name('audit-envelope.go').resolve()
            encrypted = subprocess.run(['go', 'run', str(helper), 'encrypt', str(Path(args.recipient).resolve()), str(Path(args.encrypted_report).resolve())], input=scan.stdout, env=host_env, capture_output=True, timeout=90)
            assert encrypted.returncode == 0
        text = scan.stdout.decode('utf-8').strip()
        decoder = json.JSONDecoder()
        config_seen = False
        relevant = 0
        modules = 0
        while text:
            record, end = decoder.raw_decode(text)
            text = text[end:].lstrip()
            config_seen = config_seen or 'config' in record
            if 'finding' in record:
                trace = record['finding'].get('trace', [])
                if any(frame.get('package') for frame in trace):
                    relevant += 1
                else:
                    modules += 1
        assert config_seen
        if relevant:
            print('Go security scan: BLOCKED (private dependency review required)')
            raise SystemExit(1)
        print(json.dumps({'goSecurityScan': 'pass', 'scope': 'Go packages only',
                          'moduleOnlyRecordsForPrivateReview': modules,
                          'all34ControlsApproved': False}))
except (AssertionError, OSError, ValueError, subprocess.SubprocessError):
    print('Go security scan: BLOCKED (scanner or source verification incomplete)')
    raise SystemExit(1)
