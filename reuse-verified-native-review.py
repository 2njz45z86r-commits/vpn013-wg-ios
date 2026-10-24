"""Promote immutable native evidence only for identical client source/toolchains.

Run40117745713 passed six native tests, exported every attachment and captured
phone/iPad. A trailing CR command after those checks caused packaging exit127.
No untested source is accepted by this packaging recovery.
"""
from pathlib import Path, PurePosixPath
import hashlib, io, json, platform, subprocess, urllib.request, zipfile

RUN = '40117745713'
OVERLAY = 'adb8f91595889440912b7a2b3a29de081628b2fa'
SHA = '3d7207f79727e61d6e209b48d9b9e6aadd2f975a962360abf79725c597dac2b1'
root = Path('build/review')
assert subprocess.check_output(['git','rev-parse','HEAD:overlay'],text=True).strip() == OVERLAY
assert subprocess.check_output(['xcodebuild','-version'],text=True).strip() == 'Xcode 16.4\nBuild version 16F6'
assert platform.machine() == 'arm64'
go = Path('build/toolchain/go/bin/go')
version = subprocess.check_output([str(go.resolve()) if go.exists() else 'go','version'],text=True).strip()
assert version == 'go version go1.26.10 darwin/arm64', 'Native evidence requires this exact tested Go toolchain'
fresh = json.loads((root/'bundle-verification.json').read_text())
assert fresh['version'] == '1.4.2' and fresh['adHocIntegrityChecked'] and fresh['requiresOwnerResigning']
url = 'https://github.com/2njz45z86r-commits/vpn013-wg-ios/releases/download/inspection-'+RUN+'/native-review.zip'
with urllib.request.urlopen(url,timeout=45) as response: raw = response.read(10_000_001)
assert len(raw) <= 10_000_000 and hashlib.sha256(raw).hexdigest() == SHA
with zipfile.ZipFile(io.BytesIO(raw)) as archive:
    assert archive.testzip() is None
    summary = json.loads(archive.read('review/test-summary.json'))
    assert summary['result'] == 'Passed' and summary['passedTests'] == 6 and summary['failedTests'] == 0
    assert summary['skippedTests'] == 0 and summary['totalTestCount'] == 6
    assert json.loads(archive.read('review/bundle-verification.json')) == fresh
    manifest = json.loads(archive.read('review/flow/manifest.json'))
    expected = {'testAutoMissingRuntimeDoesNotPingSeed','testAutoPinnedFirstWithCurrentMemberAndPing',
        'testManualCurrentPingWithMissingRuntime','testManualCurrentPingWithRuntimeTimeout',
        'testManualCurrentServerPingAndInfo','testPingButtonMeasuresActualLoopbackWithoutStartingVPN'}
    assert {row['testIdentifier'].split('/')[-1].removesuffix('()') for row in manifest} == expected
    for row in manifest:
        assert row['attachments']
        for item in row['attachments']:
            assert item['isAssociatedWithFailure'] is False
            assert 'review/flow/'+item['exportedFileName'] in archive.namelist()
    assert 'review/phone-large-type.png' in archive.namelist() and 'review/tablet.png' in archive.namelist()
    for item in archive.infolist():
        if item.is_dir(): continue
        name = PurePosixPath(item.filename)
        assert not name.is_absolute() and '..' not in name.parts and name.parts[0] == 'review'
        assert name.suffix in ('.json','.png') and item.file_size < 10_000_000
        if name.name == 'bundle-verification.json': continue
        data = archive.read(item)
        if name.suffix == '.png': assert data.startswith(b'\x89PNG\r\n\x1a\n')
        target = Path('build').joinpath(*name.parts)
        target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
provenance = dict(schema=1,clientOverlaySHA=OVERLAY,nativeEvidenceRun=RUN,nativeArchiveSHA256=SHA,
    nativeTestsPassed=6,nativeTestsFailed=0,packagingOnlyRecovery=True,clientCodeChanged=False,
    previousPackagingError='trailing CR command after all native checks and captures',
    xcode='16.4 (16F6)',go=version,nativeTestsRerunInPackagingJob=False,physicalIPhoneTested=False)
(root/'native-evidence-provenance.json').write_text(json.dumps(provenance,indent=2))
print('Verified immutable native evidence: six passes, matching client tree and Xcode/Go; fresh device build independently checked')
