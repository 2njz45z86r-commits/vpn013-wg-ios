"""Reuse only exact successful31-case evidence; run corrected captures anew.

The original whole workflow remains failed. Its sole post-test capture-version
assertion is corrected separately; this file never marks that workflow passed.
"""
from pathlib import Path,PurePosixPath
import hashlib,io,json,os,plistlib,re,shutil,subprocess,tempfile,zipfile

REPO='2njz45z86r-commits/vpn013-wg-ios'
RUN=40461781600
SOURCE='50cbcf177ad45d90ff46026a372b8852a330e1f7'
ARTIFACT=12716546724
DIGEST='95972e551ae29a1da00a1685c86df69aee868fdbd15be3f71eb148ef75e95567'
EXPECTED={'overlay':'7831fa62836b83a3b4abe2dd3e5dd21cdfe4847d','build-on-mac.sh':'d526fbb1a457c3683747e2c23347153b747749fa','inspect-on-mac.sh':'4deaae0abd6399f249a2af4842d596eb3219533a','publish-client-release.py':'af5bd9febff562a1898585b825e8bdd386facd3b'}
def api(path):return json.loads(subprocess.check_output(['gh','api',f'repos/{REPO}/'+path]))
def call(*args,timeout=240):return subprocess.check_output(args,text=True,timeout=timeout,stderr=subprocess.STDOUT)
def main():
 assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')==REPO
 for path,digest in EXPECTED.items():assert call('git','rev-parse','HEAD:'+path).strip()==digest
 run=api(f'actions/runs/{RUN}');assert run['head_sha']==SOURCE and run['status']=='completed' and run['conclusion']=='failure'
 assert run['path']=='.github/workflows/build-ios.yml'
 jobs=api(f'actions/runs/{RUN}/jobs?per_page=100')['jobs'];build=next(j for j in jobs if j['name']=='build')
 for name in ['Test core and build unsigned app','Check native Go dependencies without public finding details']:
  assert next(s for s in build['steps'] if s['name']==name)['conclusion']=='success'
 assert next(s for s in build['steps'] if s['name']=='Verify native checks and appearances')['conclusion']=='failure'
 info=api(f'actions/artifacts/{ARTIFACT}');assert info['workflow_run']['id']==RUN and info['workflow_run']['head_sha']==SOURCE and info['digest']=='sha256:'+DIGEST and not info['expired']
 review=Path('build/review');review.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory() as folder:
  archive=Path(folder)/'diagnostics.zip'
  with archive.open('xb') as output:subprocess.run(['gh','api',f'repos/{REPO}/actions/artifacts/{ARTIFACT}/zip'],stdout=output,check=True)
  assert hashlib.sha256(archive.read_bytes()).hexdigest()==DIGEST
  with zipfile.ZipFile(archive) as outer:
   assert outer.namelist()==['native-review.zip'];data=outer.read('native-review.zip')
  with zipfile.ZipFile(io.BytesIO(data)) as z:
   summary=json.loads(z.read('review/test-summary.json'))
   assert summary['result']=='Passed' and (summary['passedTests'],summary['failedTests'],summary['skippedTests'],summary['totalTestCount'])==(31,0,0,31) and summary['testFailures']==[]
   manifest=json.loads(z.read('review/flow/manifest.json'))
   expected=set(re.findall(r'-only-testing:AutoTunnelUITests/AutoTunnelUITests/(\w+)',Path('inspect-on-mac.sh').read_text()))
   actual={t['testIdentifier'].split('/')[-1].removesuffix('()') for t in manifest}
   assert len(expected)==31 and actual==expected
   assert sum(i.file_size for i in z.infolist())<100_000_000
   seen=set()
   for entry in z.infolist():
    name=entry.filename;rel=PurePosixPath(name)
    assert not rel.is_absolute() and '..' not in rel.parts and '\\' not in name and (entry.external_attr>>16)&0o170000!=0o120000
    assert name not in seen;seen.add(name)
    # Retain fresh current build's bundle/security evidence. Only successful
    # unchanged test summary and credential-free UI evidence are reusable.
    if name!='review/test-summary.json' and not name.startswith('review/flow/'):continue
    if entry.is_dir():continue
    assert name.endswith(('.json','.png'))
    out=Path('build').joinpath(*rel.parts).resolve();assert out.is_relative_to(review.resolve())
    out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(z.read(entry))
 (review/'native-test-provenance.json').write_text(json.dumps({'testsFromRun':RUN,'testsSourceCommit':SOURCE,'testsPassed':31,'testsFailed':0,'testsSkipped':0,'priorWholeWorkflowConclusion':'failure','priorPostTestFailure':'capture script required version1.5.8 after31 passed tests on1.5.9','exactSourceObjects':EXPECTED,'currentRun':os.environ['GITHUB_RUN_ID'],'capturesRerunFresh':True},indent=2))
 command=['xcodebuild','-project','WireGuard.xcodeproj','-scheme','VPN013Auto','-configuration','Debug','-sdk','iphonesimulator','-destination','generic/platform=iOS Simulator','-derivedDataPath','../SimulatorDerivedData','CODE_SIGNING_ALLOWED=NO','DEVELOPMENT_TEAM=','build']
 with Path('build/reused-tests-simulator-build.log').open('wb') as log:subprocess.run(command,cwd='build/awg',stdout=log,stderr=subprocess.STDOUT,timeout=600,check=True)
 app=Path('build/SimulatorDerivedData/Build/Products/Debug-iphonesimulator/AmneziaWG.app').resolve();meta=plistlib.loads((app/'Info.plist').read_bytes());assert meta['CFBundleShortVersionString']=='1.5.9' and str(meta['CFBundleVersion'])=='21'
 devices=json.loads(call('xcrun','simctl','list','devices','available','-j'))
 phone=next(d for rows in devices['devices'].values() for d in rows if d['name']=='iPhone 16 Pro')
 if phone['state']!='Booted':call('xcrun','simctl','boot',phone['udid'],timeout=45)
 call('xcrun','simctl','bootstatus',phone['udid'],'-b',timeout=180)
 call('xcrun','simctl','install',phone['udid'],str(app),timeout=90)
 subprocess.run(['python3','capture-ios-simulators.py'],check=True,timeout=600)
 completed=json.loads((review/'simulator-capture-completion.json').read_text());assert completed['version']=='1.5.9' and str(completed['build'])=='21' and all(completed[k] for k in ['freshPhoneLargeType','freshPhoneOrdinaryLaunch','freshTablet','sequentialSimulators'])
 print('Exact31 passed test evidence retained; corrected phone/tablet captures freshly verified. Prior failed workflow not relabeled.')
if __name__=='__main__':main()
