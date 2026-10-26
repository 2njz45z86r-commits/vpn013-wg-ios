"""Reuse 31 completed tests from identical source; finish fresh simulator captures.

The prior job timed out AFTER its exact 31-test suite passed. Its cancelled
job is never described as successful. Fresh device/core/SCA steps still run.
"""
from pathlib import Path,PurePosixPath
import hashlib,io,json,os,platform,shutil,subprocess,urllib.error,urllib.parse,urllib.request,zipfile

REPO='2njz45z86r-commits/vpn013-wg-ios'
RUN=40366130549
JOB=121724206247
HEAD='9fac7310cd7d4e2bcf2b44c4528a28395516cfd6'
ARTIFACT=12672287253
DIGEST='f9131a2939515aa15c8be2e12f1c52aadad3025bfb1e43136d9dd5decffab377'
PINS={'overlay':'e1011585812b85d7b6292a6816085a18eed139d2',
 'build-on-mac.sh':'2f3fa7d1681a6a9f689201fd613a01c552d38944',
 'inspect-on-mac.sh':'af4c04a34a83e6b6b61d1485a27fc3bb52510129',
 'tests/AutoControllerLifecycleTests.swift':'cceaa6f76316290f759dbec758fa4721444d1cd4',
 'scripts/check_go_security.py':'282b68bd42672af5fd00f408cf554be73525e163'}
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')==REPO
for path,wanted in PINS.items():
 assert subprocess.check_output(['git','rev-parse','HEAD:'+path],text=True).strip()==wanted,'Native source changed: '+path
assert platform.machine()=='x86_64'
assert subprocess.check_output(['xcodebuild','-version'],text=True).strip()=='Xcode 16.4\nBuild version 16F6'
go=Path('build/toolchain/go/bin/go')
if not go.is_file():go=Path(shutil.which('go'))
go=go.resolve()
assert subprocess.check_output([str(go),'version'],text=True).strip()=='go version go1.26.10 darwin/amd64'
review=Path('build/review');review.mkdir(exist_ok=True)
fresh=json.loads((review/'bundle-verification.json').read_text())
assert fresh['version']=='1.5.7' and fresh['adHocIntegrityChecked'] and fresh['requiresOwnerResigning'] and not fresh['customerKeysIncluded']

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
opener=urllib.request.build_opener(NoRedirect())
def api(path):
 request=urllib.request.Request('https://api.github.com/repos/'+REPO+'/'+path,
  headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json'})
 return opener.open(request,timeout=45)
with api('actions/runs/'+str(RUN)) as response:run=json.load(response)
assert run['status']=='completed' and run['conclusion']=='cancelled' and run['head_sha']==HEAD
with api('actions/jobs/'+str(JOB)) as response:job=json.load(response)
assert job['run_id']==RUN and job['status']=='completed' and job['conclusion']=='cancelled'
steps={s['name']:s.get('conclusion') for s in job['steps']}
for name in ['Test core and build unsigned app','Check native Go dependencies without public finding details','Preserve synthetic acceptance evidence only']:
 assert steps.get(name)=='success','Prior prerequisite did not pass: '+name
assert steps.get('Verify native checks and appearances')=='cancelled'
with api('actions/artifacts/'+str(ARTIFACT)) as response:meta=json.load(response)
assert meta['workflow_run']['id']==RUN and meta['workflow_run']['head_sha']==HEAD and meta['digest']=='sha256:'+DIGEST and not meta['expired']
try:
 with api('actions/artifacts/'+str(ARTIFACT)+'/zip') as response:raw=response.read(25_000_001)
except urllib.error.HTTPError as first:
 assert first.code in (301,302,303,307,308)
 location=first.headers['Location'];first.close()
 for _ in range(4):
  url=urllib.parse.urlsplit(location)
  assert url.scheme=='https' and not url.username and not url.password and url.port in (None,443)
  assert url.hostname.endswith(('.blob.core.windows.net','.githubusercontent.com'))
  try:
   # The artifact request has no GitHub Authorization header.
   with opener.open(urllib.request.Request(location),timeout=45) as response:raw=response.read(25_000_001)
   break
  except urllib.error.HTTPError as redirect:
   assert redirect.code in (301,302,303,307,308)
   location=urllib.parse.urljoin(location,redirect.headers['Location']);redirect.close()
 else:raise AssertionError('Artifact redirect limit')
assert len(raw)<=25_000_000 and hashlib.sha256(raw).hexdigest()==DIGEST
with zipfile.ZipFile(io.BytesIO(raw)) as archive:
 assert archive.testzip() is None and len(archive.infolist())==55
 assert sum(i.file_size for i in archive.infolist())<=100_000_000
 summary=json.loads(archive.read('test-summary.json'))
 assert summary['result']=='Passed' and summary['passedTests']==31 and summary['failedTests']==0 and summary['skippedTests']==0 and summary['totalTestCount']==31
 assert summary['testFailures']==[] and summary['devicesAndConfigurations'][0]['passedTests']==31
 assert json.loads(archive.read('bundle-verification.json'))==fresh
 assert {'phone-large-type.png','phone-normal-launch-no-fixture.png'}<=set(archive.namelist())
 count=0
 for item in archive.infolist():
  if item.is_dir():continue
  name=PurePosixPath(item.filename)
  assert not name.is_absolute() and '..' not in name.parts and item.file_size<15_000_000
  assert name.suffix in ('.png','.json','.txt')
  if name.suffix!='.png' and str(name)!='test-summary.json':continue
  data=archive.read(item)
  if name.suffix=='.png':assert data.startswith(b'\x89PNG\r\n\x1a\n');count+=1
  target=review.joinpath(*name.parts);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
 assert count==47

env=os.environ.copy();env['PATH']=str(go.parent)+os.pathsep+env['PATH']
def run_command(args,timeout=180):
 return subprocess.check_output(args,env=env,text=True,timeout=timeout)
devices=json.loads(run_command(['xcrun','simctl','list','devices','available','-j']))
all_devices=[d for rows in devices['devices'].values() for d in rows]
phone=next(d['udid'] for d in all_devices if d['name']=='iPhone 16 Pro')
tablet=next(d['udid'] for d in all_devices if d['name'].startswith('iPad'))
derived=Path('build/RoutingRecoverySimulator').resolve()
log=review/'simulator-recovery-build.log'
with log.open('wb') as output:
 completed=subprocess.run(['xcodebuild','-project','WireGuard.xcodeproj','-scheme','VPN013Auto',
  '-configuration','Debug','-sdk','iphonesimulator','-destination','platform=iOS Simulator,id='+phone,
  '-derivedDataPath',str(derived),'CODE_SIGNING_ALLOWED=NO','DEVELOPMENT_TEAM=','build'],
  cwd='build/awg',env=env,stdout=output,stderr=subprocess.STDOUT,timeout=900)
if completed.returncode:
 print('\n'.join(log.read_text(errors='replace').splitlines()[-40:]))
 raise AssertionError('Fresh simulator build failed')
app=derived/'Build/Products/Debug-iphonesimulator/AmneziaWG.app'
assert app.is_dir()
for device,name,args in [(phone,'phone-normal-launch-no-fixture.png',[]),
 (tablet,'tablet.png',['--vpn013-test-count','2','--vpn013-test-current-card','--vpn013-test-start-current','--vpn013-test-ping-loopback'])]:
 # Keep the two job-owned capture simulators sequential.
 current=json.loads(run_command(['xcrun','simctl','list','devices','available','-j']))
 state=next(d['state'] for rows in current['devices'].values() for d in rows if d['udid']==device)
 if state!='Booted':run_command(['xcrun','simctl','boot',device])
 try:
  run_command(['xcrun','simctl','bootstatus',device,'-b'])
  run_command(['xcrun','simctl','ui',device,'appearance','dark'])
  run_command(['xcrun','simctl','install',device,str(app)])
  run_command(['xcrun','simctl','launch','--terminate-running-process',device,'com.vpn013.awg','-AppleLanguages','(ru)','-AppleLocale','ru_RU',*args])
  import time;time.sleep(3)
  run_command(['xcrun','simctl','io',device,'screenshot',str((review/name).resolve())])
  assert (review/name).read_bytes().startswith(b'\x89PNG\r\n\x1a\n') and (review/name).stat().st_size>10000
 finally:run_command(['xcrun','simctl','shutdown',device])
provenance={'schema':1,'sourcePins':PINS,'nativeEvidenceRun':RUN,'nativeEvidenceJob':JOB,
 'nativeEvidenceHead':HEAD,'archiveSHA256':DIGEST,'previousJobConclusion':'cancelled',
 'previousJobIsNotClaimedSuccessful':True,'nativeTestsPassed':31,'nativeTestsFailed':0,'nativeTestsSkipped':0,
 'nativeTestsRerun':False,'freshDeviceBuildCoreAndSCA':True,'freshSimulatorBuildAndPhoneTabletCaptures':True,
 'clientCodeIdenticalToTestedOverlay':True,'physicalIPhoneTested':False}
(review/'routing-evidence-provenance.json').write_text(json.dumps(provenance,indent=2))
print('Exact31 native test passes retained; fresh device/core/SCA and phone/tablet capture completion verified')
