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
FILES = ('device.go', 'uapi.go', 'send.go', 'noise-protocol.go', 'receive.go')


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
    awg31_patch = Path(__file__).with_name('patch-primary-awg31.py')
    assert awg31_patch.is_file() and not awg31_patch.is_symlink()
    subprocess.run([sys.executable, str(awg31_patch), str(local)], check=True)
    # Stage the exact Linux race-tested 1.5 prototype only on the pinned base.
    # Check every input before changing any file; no Go module cache is edited.
    legacy_dir = Path(__file__).with_name('legacy-engine').resolve(strict=True)
    manifest_file = legacy_dir / 'manifest.json'
    legacy_manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
    expected_legacy = {'device.go', 'peer.go', 'send.go', 'uapi.go',
                       'r013_resource_limits.go', 'r013_legacy15.go',
                       'r013_legacy15_test.go', 'r013_legacy_uapi_test.go', 'r013_legacy_fuzz_test.go', 'r013_stale_snapshot_test.go'}
    assert set(legacy_manifest) == expected_legacy
    staged_legacy = {}
    for name, digest in legacy_manifest.items():
        source_file = legacy_dir / (name + '.txt')
        target = local / 'device' / name
        assert source_file.is_file() and not source_file.is_symlink()
        raw = source_file.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest['afterSHA256']
        before_digest = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
        assert before_digest == digest['beforeSHA256'] and not target.is_symlink()
        staged_legacy[target] = raw
    for target, raw in staged_legacy.items():
        target.write_bytes(raw)
    after = {name: hashlib.sha256((local / 'device' / name).read_bytes()).hexdigest()
             for name in (*FILES, 'r013_resource_limits.go', 'r013_resource_limits_test.go', 'r013_s4_regression_test.go',
                          'r013_awg31_classifier.go', 'r013_awg31_testhelper_test.go',
                          'r013_vpn013_auth_classifier_test.go', 'r013_vpn013_auth_control_test.go',
                          'r013_vpn013_auth_live_test.go', 'r013_vpn013_auth_robustness_test.go',
                          'r013_vpn013_awg31_runtime_test.go', 'r013_vpn013_queued_classifier_test.go',
                          'peer.go', 'r013_legacy15.go', 'r013_legacy15_test.go', 'r013_legacy_uapi_test.go',
                          'r013_legacy_fuzz_test.go', 'r013_stale_snapshot_test.go')}
    assert before == {name: hashlib.sha256((source / 'device' / name).read_bytes()).hexdigest() for name in FILES}
    # Execute the copied primary implementation on the build host. Cross-compiled
    # libraries still require their platform/native acceptance tests afterwards.
    host_os = subprocess.check_output(['go', 'env', 'GOHOSTOS'], text=True).strip()
    host_arch = subprocess.check_output(['go', 'env', 'GOHOSTARCH'], text=True).strip()
    fixtures = Path(__file__).with_name('awg31-fixtures').resolve(strict=True)
    expected_fixtures = {'ambiguous-transport.bin':'14827386c07f42695485e4fdfa4e30e6aece4e7494691967071b50fd24237d01',
                         'redrawn-transport.bin':'ad12318a51de6ba21c95aec0e06f0a6564c87a7b24e9a6f14e76d2551cb44957',
                         'params.json':'d46737e0071c71acb9662259b31f7a20d206209889c48a5d31857633fd1b65c0'}
    assert all(hashlib.sha256((fixtures / name).read_bytes()).hexdigest() == value for name, value in expected_fixtures.items())
    env = dict(os.environ, GOOS=host_os, GOARCH=host_arch, CGO_ENABLED='0', GOFLAGS='-mod=readonly', AWG_FIXTURES=str(fixtures))
    tested = subprocess.run(['go', 'test', './device', '-count=1', '-timeout=90s',
                             '-run', '^(TestPrimary|TestTwoDevicePing|TestAWGDevicePing|TestVPN013|TestLegacy15|FuzzVPN013LegacyParse)', '-v'],
                            cwd=local, env=env, capture_output=True, text=True, timeout=110)
    passed = re.findall(r'^--- PASS: ([A-Za-z0-9_]+) ', tested.stdout, re.MULTILINE)
    required = {'TestTwoDevicePing', 'TestPrimaryObfuscationResourceBudget',
                'TestPrimaryUAPIStagesWholeObfuscationBeforeCommit',
                'TestPrimaryUnsafeSetDoesNotRemovePeers', 'TestPrimaryInterruptedSetDoesNotCommit',
                'TestPrimaryOrdinaryWGNoObfuscationPadding', 'TestVPN013S4BlockedReadReposition',
                'TestVPN013MoveTUNPayloadBounds', 'TestAWGDevicePing',
                'TestVPN013AuthenticatedTransportFallback', 'TestVPN013AuthenticatedControlFallback',
                'TestVPN013AuthenticatedFallbackLocalTraffic', 'TestVPN013ClassifierMalformedFramesDoNotPanic',
                'TestVPN013PaddingFitsPeerWindow', 'TestVPN013DisabledCookiesPermitLoadedHandshake',
                'TestVPN013QueuedCandidateRejectsForgedTraffic', 'TestLegacy15PacketSemantics',
                'TestLegacy15ControlledWaitAndOddHex', 'TestLegacy15ConfigValidation',
                'TestLegacy15MalformedAndBudgets', 'TestLegacy15Scheduling',
                'TestVPN013LegacyWaitStopsWhenDeviceGoesDown',
                'TestVPN013LegacyConcurrentUpdatesAndGeneration',
                'TestVPN013LegacyUAPIStagingAndPeerPreservation', 'TestVPN013LegacySparsePackets',
                'TestVPN013HeaderOverlapRejectedBeforePeerMutation',
                'TestVPN013InvalidPeerFieldsRejectedBeforePeerMutation',
                'TestVPN013LegacyStaleSnapshotAfterModeSwitch', 'TestVPN013LegacyRejectPreparedPacketAfterModeSwitch',
                'TestVPN013LegacySendCompletesBeforeModeCommit',
                'TestVPN013LegacyEndpointRefreshKeepsRevision', 'TestVPN013LegacyMaskingChangesAdvanceRevision',
                'FuzzVPN013LegacyParse'}
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
            'patchSHA256': patch_hash, 'awg31PatchSHA256': hashlib.sha256(awg31_patch.read_bytes()).hexdigest(),
            'legacyManifestSHA256': hashlib.sha256(manifest_file.read_bytes()).hexdigest(),
            'beforeSHA256': before, 'afterSHA256': after,
            'effectiveReplacementVerified': True, 'primaryHostTests': report}
