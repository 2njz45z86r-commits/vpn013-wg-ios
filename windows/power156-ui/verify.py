"""Fresh native UI proof for unchanged production sources of verified Windows156."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,shutil,subprocess,zipfile
REPO='2njz45z86r-commits/vpn013-wg-ios';RUN=40473031734;SOURCE='7a48779c207b21d3562ba43546f80c5ab14ac005'
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='Windows' and os.environ.get('GITHUB_REPOSITORY')==REPO
workspace=Path(os.environ['GITHUB_WORKSPACE']).resolve();temp=Path(os.environ['RUNNER_TEMP']).resolve();out=temp/'power156-ui-proof';out.mkdir()
def api(path):return json.loads(subprocess.check_output(['gh','api','repos/'+REPO+'/'+path]))
def sha(data):return hashlib.sha256(data).hexdigest()
def unpack(path,folder):
 folder.mkdir();seen=set()
 with zipfile.ZipFile(path) as z:
  assert sum(x.file_size for x in z.infolist())<500000000 and len(z.infolist())<10000
  for x in z.infolist():
   rel=PurePosixPath(x.filename);assert not rel.is_absolute() and '..' not in rel.parts and '\\' not in x.filename and (x.external_attr>>16)&0o170000!=0o120000
   target=folder.joinpath(*rel.parts).resolve();assert target.is_relative_to(folder.resolve()) and str(target).casefold() not in seen;seen.add(str(target).casefold())
   if x.is_dir():target.mkdir(parents=True,exist_ok=True);continue
   target.parent.mkdir(parents=True,exist_ok=True)
   with z.open(x) as source,target.open('xb') as dest:shutil.copyfileobj(source,dest)
run=api(f'actions/runs/{RUN}');assert run['head_sha']==SOURCE and run['conclusion']=='success' and run['status']=='completed'
info=api('actions/artifacts/12720036267');assert info['workflow_run']['id']==RUN and not info['expired'] and info['digest']=='sha256:0c69334936d3945d6a70218caadd8b12ef9dd5e226b4b4d9d3c5ba19524ed29d'
archive=temp/'native156.zip'
with archive.open('xb') as f:subprocess.run(['gh','api','repos/'+REPO+'/actions/artifacts/12720036267/zip'],stdout=f,check=True)
assert sha(archive.read_bytes())==info['digest'].split(':')[1]
built=temp/'native156';unpack(archive,built)
sources=list(built.rglob('VPN013WG-1.5.6-windows-source.zip'));assert len(sources)==1 and sha(sources[0].read_bytes())=='0a08987ef52ea134a8104793ecf2693284c4ee7df71671be7580d9cf8061183d'
extracted=workspace/'power-ui-source';unpack(sources[0],extracted);root=extracted/'vpn013-wg-windows';assert root.is_dir()
pins={'ui/r013_power.go':'8ce0d024549a1b386bac04ca9a1a00ab11e041c5c93c5b8dd50858f9be4e7a87','ui/r013_current.go':'122df8003b775d46945564ce66abe8e4bcbf1c2071eccf8e17ed4bef6c0d2eb6'}
for n,h in pins.items():assert sha((root/n).read_bytes().replace(b'\r\n',b'\n'))==h
# Only the separately tagged UI harness is changed. Shipping Go files stay exact.
shutil.copyfile(workspace/'windows/power156-ui/r013_preview_windows.go',root/'ui/r013_preview_windows.go')
environment=os.environ.copy();environment['PYTHONUTF8']='1'
subprocess.run(['python','scripts/bootstrap.py'],cwd=root,env=environment,check=True)
subprocess.run(['pwsh','-NoProfile','-File','scripts/bootstrap-driver.ps1'],cwd=root,env=environment,check=True)
subprocess.run(['pwsh','-NoProfile','-File','scripts/build-r013.ps1'],cwd=root,env=environment,check=True)
environment['GOPATH']=str(root/'.deps/gopath');environment['CGO_ENABLED']='1';environment['CC']='x86_64-w64-mingw32-gcc';environment['PATH']=str(root/'.deps/go/bin')+os.pathsep+str(root/'.deps/llvm-mingw-20231128-ucrt-x86_64/bin')+os.pathsep+environment['PATH']
(out/'context.json').write_text(json.dumps({'nativeRun':RUN,'nativeSource':SOURCE,'productionPins':pins,'capture':'actual hosted desktop; native fully visible button floor64px'},indent=2)+'\n')
try:
 subprocess.run(['pwsh','-NoProfile','-File','scripts/ci-ui.ps1'],cwd=root,env=environment,check=True)
finally:
 for path in list(temp.glob('r013-ui-*.json'))+list(temp.glob('r013-power-*.png')):
  shutil.copyfile(path,out/path.name)
for n,h in pins.items():assert sha((root/n).read_bytes().replace(b'\r\n',b'\n'))==h
expected={'manual-no-stats':5,'auto':5,'auto-no-stats':3,'update-offer':6,'power':10}
for name,count in expected.items():
 p=temp/('r013-ui-'+name+'.json');r=json.loads(p.read_text(encoding='utf-8-sig'));assert r['passed'] and len(r['checks'])==count;shutil.copyfile(p,out/p.name)
for name in ('connected','disconnected','auto','minimum-window'):
 p=temp/('r013-power-'+name+'.png');assert p.stat().st_size>1000;shutil.copyfile(p,out/p.name)
proof={'passed':True,'nativeRun':RUN,'nativeSource':SOURCE,'nativeSourceArchiveSHA256':'0a08987ef52ea134a8104793ecf2693284c4ee7df71671be7580d9cf8061183d','productionFilesUnchanged':pins,'freshUIRun':int(os.environ['GITHUB_RUN_ID']),'freshUISource':os.environ['GITHUB_SHA'],'powerChecks':10,'nativeDesktopCaptures':4,'physicalOwnerPCTested':False,'installerReplacedOrRebuiltForDelivery':False}
(out/'verification.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
