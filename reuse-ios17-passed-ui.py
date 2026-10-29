"""Retain 41 actual native passes only for identical executable/test sources.

The current release job still compiles the app/extension and checks current Go
dependencies. All41 iPhone UI scenarios and real XCUITest appearances come from
the exact unchanged runtime/test sources; iPad and raw simctl captures are excluded.
This exact diagnostic archive has41 complete passed UI tests; its later tablet capture failed. No partial/failed UI results are accepted. Only actual passed iPhone XCUITest attachments are accepted; optional standalone captures are excluded.
"""
from pathlib import Path, PurePosixPath
import hashlib, io, json, os, plistlib, re, subprocess, tempfile, zipfile, time

REPO = '2njz45z86r-commits/vpn013-wg-ios'
RUN = 40801078706
SOURCE = '1463aff28383284f9ffc8c49bff40c4ce8e09620'
EXPECTED = {'overlay': 'c2180d18a45cceca98f12af6d8fc369df17f0906', 'branding': 'ca6550800eda39c3cb91f10e8b269eefd2ee9f89', 'experiments': '7dcb7b683890f1c5a79d86c9856245c26f40a57c', 'tests': '962e585f711b7161cfc83a1f8ef840524c7bd564', 'scripts': 'bc60e1998fc35dd454a0a5d203f8fafac77fe3a6', 'build-on-mac.sh': 'f51c6dd02992f3d0f26673282edb71ca62af1281', 'inspect-on-mac.sh': '818bcd8b8ca437f5c57ed7133fc8e47daf4a3784', '.github/workflows/native-unified-check.yml': 'a34980db6f8f23a7bc236bf532a1f374e0bb14a2', '.github/workflows/check-inactive-probe.yml': 'e598c1dbc52be6a98fc0ddf5a9797acb69e97cde'}
def require(value, message):
    if not value: raise RuntimeError(message)
def call(*args, **kwargs):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, **kwargs)
def api(path): return json.loads(call('gh', 'api', 'repos/'+REPO+'/'+path))

def wait_for_run():
    # The release recompilation may overlap the exact-source native UI run.
    # Never promote a pending/failed run; wait at most forty-five minutes.
    cutoff = time.monotonic() + 2700
    while True:
        run = api('actions/runs/'+str(RUN))
        require(run.get('id') == RUN and run.get('head_sha') == SOURCE and run.get('path') == '.github/workflows/build-ios.yml', 'Wrong native source/run')
        if run.get('status') == 'completed': return run
        require(run.get('status') in ('queued','pending','in_progress','waiting','requested') and time.monotonic() < cutoff, 'Native validation did not finish within its bounded wait')
        time.sleep(30)

def verify(run, jobs, artifact, summary, manifest, selectors):
    require(run.get('id') == RUN and run.get('head_sha') == SOURCE and run.get('path') == '.github/workflows/build-ios.yml', 'Wrong native source/run')
    require(run.get('status') == 'completed' and run.get('conclusion') == 'failure', 'Native run incomplete or failed')
    native = [job for job in jobs if job.get('name') == 'build']
    require(len(native) == 1 and native[0].get('conclusion') == 'failure', 'Native job not successful')
    steps = {step['name']: step.get('conclusion') for step in native[0].get('steps', [])}
    for name in ('Test core and build unsigned app', 'Check native Go dependencies without public finding details'):
        require(steps.get(name) == 'success', 'Required native step missing or failed')
    require({name for name, result in steps.items() if result == 'failure'} == {'Verify native checks and appearances'}, 'Unexpected failed step')
    require(artifact.get('id') == 12868002688 and artifact.get('digest') == 'sha256:378093d7f33720930e8e8f6d9c8c6034c62ebe5cce319834d06d914bcd21f641', 'Different diagnostic evidence; no general failure exception')
    require(artifact.get('workflow_run', {}).get('id') == RUN and artifact.get('workflow_run', {}).get('head_sha') == SOURCE and artifact.get('expired') is False, 'Wrong or expired artifact')
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', artifact.get('digest', '')) is not None, 'Artifact has no SHA256')
    require(summary.get('result') == 'Passed' and (summary.get('passedTests'), summary.get('failedTests'), summary.get('skippedTests'), summary.get('totalTestCount')) == (41, 0, 0, 41) and summary.get('testFailures') == [], 'Native suite is not 41 complete passes')
    actual = {row['testIdentifier'].split('/')[-1].removesuffix('()') for row in manifest}
    require(len(selectors) == 41 and actual == selectors, 'Native selector/attachment evidence differs')
def main():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == REPO, 'Only the project CI may promote evidence')
    for path, digest in EXPECTED.items():
        require(call('git', 'rev-parse', 'HEAD:'+path).strip() == digest, 'Executable/test source changed: '+path)
    toolchain = Path('build/toolchain/go/bin').resolve()
    if toolchain.is_dir(): os.environ['PATH'] = str(toolchain)+os.pathsep+os.environ['PATH']
    require(call('go','version').strip() == 'go version go1.26.10 darwin/amd64', 'Different Go toolchain/architecture')
    os.environ['GOFLAGS'] = '-mod=readonly -modfile='+str(Path('build/proxy-fd/proxy-tun.mod').resolve())
    require(Path('build/proxy-fd/proxy-tun.mod').is_file(), 'Missing actual fd-ownership modfile')
    run = wait_for_run()
    jobs = api('actions/runs/'+str(RUN)+'/jobs?per_page=100')['jobs']
    artifacts = api('actions/runs/'+str(RUN)+'/artifacts')['artifacts']
    candidates = [a for a in artifacts if a['name'] == 'ios-diagnostics-'+str(RUN)]
    require(len(candidates) == 1, 'Ambiguous/missing native evidence')
    artifact = api('actions/artifacts/'+str(candidates[0]['id']))
    review = Path('build/review').resolve(); review.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='vpn013-native-evidence-') as folder:
        archive = Path(folder)/'evidence.zip'
        with archive.open('xb') as output:
            subprocess.run(['gh','api','repos/'+REPO+'/actions/artifacts/'+str(artifact['id'])+'/zip'], stdout=output, check=True, timeout=90)
        require(archive.stat().st_size <= 40_000_000, 'Oversized artifact')
        raw = archive.read_bytes(); require('sha256:'+hashlib.sha256(raw).hexdigest() == artifact['digest'], 'Artifact digest mismatch')
        with zipfile.ZipFile(io.BytesIO(raw)) as outer:
            require(outer.namelist() == ['native-review.zip'], 'Unexpected artifact layout')
            require(outer.infolist()[0].file_size <= 40_000_000, 'Oversized nested evidence')
            data = outer.read('native-review.zip')
        with zipfile.ZipFile(io.BytesIO(data)) as evidence:
            require(len(evidence.infolist()) <= 1000, 'Excessive evidence files')
            require(sum(i.file_size for i in evidence.infolist()) <= 100_000_000, 'Oversized evidence')
            summary = json.loads(evidence.read('review/test-summary.json'))
            manifest = json.loads(evidence.read('review/flow/manifest.json'))
            selectors = set(re.findall(r'-only-testing:AutoTunnelUITests/AutoTunnelUITests/(\w+)', Path('inspect-on-mac.sh').read_text()))
            verify(run, jobs, artifact, summary, manifest, selectors)
            names = set(evidence.namelist())
            for row in manifest:
                require(bool(row.get('attachments')), 'Missing native appearance attachment')
                for attachment in row['attachments']:
                    require(attachment.get('isAssociatedWithFailure') is False and 'review/flow/'+attachment['exportedFileName'] in names, 'Missing/failed native appearance evidence')
            seen = set()
            for entry in evidence.infolist():
                name = entry.filename; rel = PurePosixPath(name)
                require(not rel.is_absolute() and '..' not in rel.parts and '\\' not in name and (entry.external_attr >> 16) & 0o170000 != 0o120000, 'Unsafe evidence path')
                require(name.casefold() not in seen, 'Duplicate evidence path'); seen.add(name.casefold())
                if entry.is_dir() or (name != 'review/test-summary.json' and not name.startswith('review/flow/')): continue
                require(rel.suffix in ('.json','.png') and entry.file_size <= 15_000_000, 'Unexpected evidence type/size')
                target = Path('build').joinpath(*rel.parts).resolve(); require(target.is_relative_to(review), 'Evidence escapes review')
                payload = evidence.read(entry)
                if rel.suffix == '.png': require(payload.startswith(b'\x89PNG\r\n\x1a\n'), 'Invalid screenshot')
                target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(payload)
    (review/'native-test-provenance.json').write_text(json.dumps({'nativeRun': RUN, 'nativeSource': SOURCE, 'artifactSHA256': artifact['digest'], 'exactSourceObjects': EXPECTED, 'passedTests': 41, 'failedTests': 0, 'skippedTests': 0, 'capturesRerunFresh': False, 'releaseScope': 'iPhone', 'iPadTested': False, 'sourceRunConclusion': 'failure', 'sourceCaptureFailure': 'tablet simctl launch timed out twice after41 complete native passes', 'physicalIPhoneTested': False}, indent=2))
    # This release is scoped to iPhone. The immutable source contains all41
    # passed iPhone scenarios and their actual XCUITest attachments. Optional
    # standalone simctl/iPad captures are neither accepted nor required here.
    device=summary['devicesAndConfigurations'][0]['device']
    require(device.get('platform') == 'iOS Simulator' and device.get('deviceName') == 'iPhone 16 Pro', 'Different native iPhone evidence')
    require(all(row.get('attachments') for row in manifest), 'Missing actual native iPhone appearances')
    scope={'platform':'iPhone','nativeScenarios':41,'sourceRun':RUN,'sourceCommit':SOURCE,
           'actualXCUITestAttachments':True,'standaloneBlankCapturesAccepted':False,
           'iPadTested':False,'physicalIPhoneTested':False,'requiresOwnerSigning':True}
    (review/'iphone-release-scope.json').write_text(json.dumps(scope,indent=2))
    print('Exact41 passed iPhone scenarios and actual XCUITest appearances retained; current Release app/extension and Go SCA checked separately; iPad is outside this release scope')
if __name__ == '__main__': main()
