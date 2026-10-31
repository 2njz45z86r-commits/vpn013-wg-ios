"""Build from a private, bounded AWG core without editing the Go module cache."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys


MODULE = 'github.com/amnezia-vpn/amneziawg-go/v3'
VERSION = 'v3.1.20260814'
FILES = ('device.go', 'uapi.go', 'send.go', 'noise-protocol.go')


def prepare_primary_awg(root: Path, output: Path, modfile: Path) -> dict:
    root = root.resolve(strict=True)
    output = output.resolve(strict=True)
    modfile = modfile.resolve(strict=True)
    info = json.loads(subprocess.check_output(['go', 'list', '-m', '-json', MODULE], cwd=root))
    assert info['Path'] == MODULE and info['Version'] == VERSION and not info.get('Replace')
    source = Path(info['Dir']).resolve(strict=True)
    cache = Path(subprocess.check_output(['go', 'env', 'GOMODCACHE'], cwd=root, text=True).strip()).resolve(strict=True)
    assert source.is_relative_to(cache) and not output.is_relative_to(cache)
    before = {name: hashlib.sha256((source / 'device' / name).read_bytes()).hexdigest() for name in FILES}
    local = output / 'awg-core-owned'
    assert not local.exists() and not local.is_symlink(), 'Use a fresh private primary core directory'
    shutil.copytree(source, local, copy_function=shutil.copyfile)
    # Go's cache directories are read-only on Unix. Change permissions only on
    # this fresh owned copy, so the new guarded source files can be created.
    for directory in (local, *(p for p in local.rglob('*') if p.is_dir())):
        assert not directory.is_symlink() and directory.resolve().is_relative_to(output)
        directory.chmod(0o700)
    patch = Path(__file__).with_name('patch-primary-resource-safety.py')
    assert patch.is_file() and not patch.is_symlink()
    patch_hash = hashlib.sha256(patch.read_bytes()).hexdigest()
    subprocess.run([sys.executable, str(patch), '--module-root', str(local)], check=True)
    after = {name: hashlib.sha256((local / 'device' / name).read_bytes()).hexdigest()
             for name in (*FILES, 'r013_resource_limits.go', 'r013_resource_limits_test.go')}
    assert before == {name: hashlib.sha256((source / 'device' / name).read_bytes()).hexdigest() for name in FILES}
    # Execute the copied primary implementation on the build host. Cross-compiled
    # libraries still require their platform/native acceptance tests afterwards.
    host_os = subprocess.check_output(['go', 'env', 'GOHOSTOS'], text=True).strip()
    host_arch = subprocess.check_output(['go', 'env', 'GOHOSTARCH'], text=True).strip()
    env = dict(os.environ, GOOS=host_os, GOARCH=host_arch, CGO_ENABLED='0', GOFLAGS='-mod=readonly')
    tested = subprocess.run(['go', 'test', './device', '-count=1', '-timeout=90s',
                             '-run', '^(TestPrimary|TestTwoDevicePing)', '-v'],
                            cwd=local, env=env, capture_output=True, text=True, timeout=110)
    passed = re.findall(r'^--- PASS: ([A-Za-z0-9_]+) ', tested.stdout, re.MULTILINE)
    required = {'TestTwoDevicePing', 'TestPrimaryObfuscationResourceBudget',
                'TestPrimaryUAPIStagesWholeObfuscationBeforeCommit',
                'TestPrimaryUnsafeSetDoesNotRemovePeers', 'TestPrimaryInterruptedSetDoesNotCommit',
                'TestPrimaryOrdinaryWGNoObfuscationPadding'}
    report = {'scope': 'build-host ChannelTUN and loopback UDP; not native OS VPN',
              'hostOS': host_os, 'hostArch': host_arch, 'exit': tested.returncode,
              'passedTests': passed, 'requiredTests': sorted(required),
              'failedOrSkipped': bool(re.search(r'^--- (?:FAIL|SKIP):', tested.stdout, re.MULTILINE))}
    (output / 'primary-resource-host-tests.summary.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    if tested.returncode or not required.issubset(passed) or report['failedOrSkipped']:
        # Compiler diagnostics contain source locations; never dump runtime data.
        errors = [line for line in tested.stderr.splitlines() if '.go:' in line or line.startswith('go:')]
        print('\n'.join(errors[-12:]), file=sys.stderr)
        raise RuntimeError('Primary resource or ordinary WireGuard host verification failed')
    subprocess.run(['go', 'mod', 'edit', '-modfile=' + str(modfile), '-replace=' + MODULE + '=' + str(local)], cwd=root, check=True)
    effective = json.loads(subprocess.check_output(['go', 'list', '-m', '-json', '-modfile=' + str(modfile), MODULE], cwd=root))
    assert Path(effective['Replace']['Dir']).resolve(strict=True) == local.resolve(strict=True)
    return {'module': MODULE, 'version': VERSION, 'moduleCacheUnchanged': True,
            'patchSHA256': patch_hash, 'beforeSHA256': before, 'afterSHA256': after,
            'effectiveReplacementVerified': True, 'primaryHostTests': report}
