"""Retain complete identical native evidence after an exact-count packaging fix.

The original job must have completed device/core/SCA and native/captures;
its packaging failure is recorded, never represented as whole-job success.
Fresh device/core/SCA run again before this evidence reader is invoked.
"""
from pathlib import Path, PurePosixPath
import hashlib, io, json, os, platform, shutil, subprocess
import urllib.error, urllib.parse, urllib.request, zipfile

REPO = '2njz45z86r-commits/vpn013-wg-ios'
RUN, JOB = 40374957129, 121755426767
HEAD = '0b5bed610e74f6c7d5c50a4b7653c95458ab9ccb'
PINS = {
    'overlay': 'e1011585812b85d7b6292a6816085a18eed139d2',
    'build-on-mac.sh': '2f3fa7d1681a6a9f689201fd613a01c552d38944',
    'inspect-on-mac.sh': 'af4c04a34a83e6b6b61d1485a27fc3bb52510129',
    'tests/AutoControllerLifecycleTests.swift': 'cceaa6f76316290f759dbec758fa4721444d1cd4',
    'scripts/check_go_security.py': '282b68bd42672af5fd00f408cf554be73525e163',
    'recover-ios-routing-evidence.py': '0e2acd5322129cd275bf7377864f487ba9083556',
}
assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == REPO
for path, wanted in PINS.items():
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD:' + path], text=True).strip() == wanted, 'Native source differs'
assert platform.machine() == 'x86_64'
assert subprocess.check_output(['xcodebuild', '-version'], text=True).strip() == 'Xcode 16.4\nBuild version 16F6'
go = Path('build/toolchain/go/bin/go')
if not go.is_file():
    go = Path(shutil.which('go'))
assert subprocess.check_output([str(go.resolve()), 'version'], text=True).strip() == 'go version go1.26.10 darwin/amd64'
root = Path('build/review')
fresh = json.loads((root / 'bundle-verification.json').read_text())
assert fresh['version'] == '1.5.7' and fresh['adHocIntegrityChecked'] and fresh['requiresOwnerResigning'] and not fresh['customerKeysIncluded']

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = urllib.request.build_opener(NoRedirect())

def api(path):
    request = urllib.request.Request('https://api.github.com/repos/' + REPO + '/' + path,
        headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json'})
    return opener.open(request, timeout=45)

with api('actions/runs/' + str(RUN)) as response:
    run = json.load(response)
assert run['status'] == 'completed' and run['conclusion'] == 'failure' and run['head_sha'] == HEAD and run['run_attempt'] == 1
with api('actions/jobs/' + str(JOB)) as response:
    job = json.load(response)
assert job['run_id'] == RUN and job['status'] == 'completed' and job['conclusion'] == 'failure'
steps = {s['name']: s.get('conclusion') for s in job['steps']}
for name in ['Test core and build unsigned app', 'Check native Go dependencies without public finding details',
             'Verify native checks and appearances', 'Package credential-free inspection evidence',
             'Retain failed inspection without an installable file']:
    assert steps.get(name) == 'success', 'Native evidence incomplete'
assert steps.get('Prepare verified IPA and exact public metadata') == 'failure'
with api('actions/runs/' + str(RUN) + '/artifacts?per_page=100') as response:
    artifacts = json.load(response)
matches = [x for x in artifacts['artifacts'] if x['name'] == 'ios-diagnostics-' + str(RUN)]
assert len(matches) == 1 and not matches[0]['expired']
meta = matches[0]
assert meta['workflow_run']['id'] == RUN and meta['workflow_run']['head_sha'] == HEAD
assert meta['size_in_bytes'] <= 25_000_000 and meta['digest'].startswith('sha256:')
digest = meta['digest'][7:]
assert len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)
try:
    with api('actions/artifacts/' + str(meta['id']) + '/zip') as response:
        raw = response.read(25_000_001)
except urllib.error.HTTPError as error:
    assert error.code in (301, 302, 303, 307, 308)
    location = error.headers['Location']; error.close()
    for _ in range(4):
        url = urllib.parse.urlsplit(location)
        assert url.scheme == 'https' and not url.username and not url.password and url.port in (None, 443)
        assert url.hostname.endswith(('.blob.core.windows.net', '.githubusercontent.com'))
        try:
            # No GitHub Authorization header is sent to storage.
            with opener.open(urllib.request.Request(location), timeout=45) as response:
                raw = response.read(25_000_001)
            break
        except urllib.error.HTTPError as redirect:
            assert redirect.code in (301, 302, 303, 307, 308)
            location = urllib.parse.urljoin(location, redirect.headers['Location']); redirect.close()
    else:
        raise AssertionError('Artifact redirect limit')
assert len(raw) <= 25_000_000 and hashlib.sha256(raw).hexdigest() == digest
with zipfile.ZipFile(io.BytesIO(raw)) as outer:
    assert outer.namelist() == ['native-review.zip'] and outer.getinfo('native-review.zip').file_size <= 30_000_000
    native = outer.read('native-review.zip')
with zipfile.ZipFile(io.BytesIO(native)) as archive:
    assert len(archive.infolist()) <= 100 and sum(i.file_size for i in archive.infolist()) <= 100_000_000
    summary = json.loads(archive.read('review/test-summary.json'))
    assert summary['result'] == 'Passed' and (summary['passedTests'], summary['failedTests'], summary['skippedTests'], summary['totalTestCount']) == (31, 0, 0, 31)
    assert summary['testFailures'] == [] and json.loads(archive.read('review/bundle-verification.json')) == fresh
    previous = json.loads(archive.read('review/routing-evidence-provenance.json'))
    assert previous['sourcePins'] == {k: v for k, v in PINS.items() if k != 'recover-ios-routing-evidence.py'}
    assert previous['nativeTestsPassed'] == 31 and previous['freshSimulatorBuildAndPhoneTabletCaptures'] is True
    assert previous['nativeEvidenceRun'] == 40366130549 and previous['previousJobConclusion'] == 'cancelled'
    assert {'review/phone-large-type.png', 'review/phone-normal-launch-no-fixture.png', 'review/tablet.png'} <= set(archive.namelist())
    assert sum(i.filename.endswith('.png') for i in archive.infolist()) == 48
    for item in archive.infolist():
        if item.is_dir():
            continue
        name = PurePosixPath(item.filename)
        assert not name.is_absolute() and '..' not in name.parts and name.parts[0] == 'review'
        assert name.suffix in ('.png', '.json') and item.file_size < 15_000_000
        if name.name == 'bundle-verification.json':
            continue
        data = archive.read(item)
        if name.suffix == '.png':
            assert data.startswith(b'\x89PNG\r\n\x1a\n')
        target = Path('build').joinpath(*name.parts)
        target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
(root / 'packaging-recovery-provenance.json').write_text(json.dumps({
    'schema': 1, 'nativeEvidenceRun': RUN, 'nativeEvidenceJob': JOB, 'nativeEvidenceHead': HEAD,
    'artifactID': meta['id'], 'artifactSHA256': digest, 'previousJobConclusion': 'failure',
    'previousPackagingCondition': 'expected30_after_suite_expanded_to31',
    'nativeSourcePins': PINS, 'nativeTestsRerun': False, 'freshDeviceBuildCoreAndSCA': True,
    'physicalIPhoneTested': False}, indent=2))
print('Complete identical31-test and fresh simulator capture evidence retained; fresh device/core/SCA independently checked')
