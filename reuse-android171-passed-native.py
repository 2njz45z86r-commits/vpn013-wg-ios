"""Reuse only completed native acceptance for byte-identical Android sources."""
import hashlib,io,json,os,pathlib,subprocess,urllib.error,urllib.request,zipfile
SOURCE="a31258160390d41492ac892cf8a953bd1e5b337f"
RUN=40984123161
ARTIFACT=12946598588
DIGEST="7b4fa33bd1d8aefa4a2b6e06b134cac9ed39a73f97d4b3720effc84f0013a7f0"
PINS={'android-overlay': 'f5977732ac2113a69dc547ce49c0929d2044a6a1', '.github/workflows/native-android-check.yml': '4ad1e05d4025ce53c0e61862d525ddcc355f289b', 'scripts/build-previous-android-fixture.sh': 'e93f56ac6a122e0c123315b07197abf6c7631a2f', 'scripts/build-future-android-fixture.sh': '86b24eeee5c3de2aa6e3f3a006151932884a6e74', 'scripts/check_go_security.py': '25526bede0c3d524ae4188bcc02254c14e67f0fb', 'scripts/audit-envelope.go': 'a010cb69c8dcf2207fe7a6847ede977c95b50058', 'scripts/audit-recipient.pub': '97046bff2fbe54b06b6c0d86417fae6d99fa6ed7'}
COUNTS={'upgrade-before':1,'upgrade-after':1,'update-install-preflight':2,'update-install-flow':1,'native-trial-flow':5,'instrumentation':16,'proxy-runtime':2,'russian-routing':1,'network-recovery':3,'font-scale':1,'tablet':1}

def validate_review(files):
 d=json.loads(files['review/development-summary.json'])
 assert d['source']==SOURCE and d['emulatorOutcome']=='success' and d['physicalDeviceVerified'] is False and d['published'] is False
 c=json.loads(files['android-development-review.json']);assert c['source']==SOURCE and c['compile']=='success'
 for name,count in COUNTS.items():
  lines=json.loads(files['review/'+name+'.txt.summary.json'])
  assert ('OK ('+str(count)+(' test)' if count==1 else ' tests)')) in lines,name
  assert not any(any(bad in line for bad in ['FAILURES','INSTRUMENTATION_FAILED','Process crashed','AssertionError']) for line in lines),name
  assert sum(line=='INSTRUMENTATION_STATUS_CODE: 0' for line in lines)==count,name
  assert not any(line=='INSTRUMENTATION_STATUS_CODE: -2' for line in lines)
 assert 'INSTRUMENTATION_STATUS: test=multiServerSubscriptionImportsPrimaryNodesOnly' in json.loads(files['review/instrumentation.txt.summary.json'])
 for name in ['proxy-auto-cross-section','proxy-happ','proxy-incy','proxy-blacktemple','built-in-auto-paused-real-disposable-vpn','phone-main']:
  data=files['review/screenshots/'+name+'.png'];assert data.startswith(b'\x89PNG\r\n\x1a\n')
 route=json.loads(files['review/russian-route-proof.json']);assert route['foreignIPv6Captured'] is True and route['exactRussianExclusions']==10838

def read_archive(raw):
 assert hashlib.sha256(raw).hexdigest()==DIGEST
 queue=[zipfile.ZipFile(io.BytesIO(raw))];files={};total=0;count=0
 while queue:
  z=queue.pop();seen=set()
  for info in z.infolist():
   p=pathlib.PurePosixPath(info.filename);key=info.filename.casefold()
   assert not p.is_absolute() and '..' not in p.parts and '\\' not in info.filename and ':' not in info.filename
   assert key not in seen and (info.external_attr>>16)&0o170000!=0o120000;seen.add(key)
   if info.is_dir():continue
   count+=1;total+=info.file_size;assert count<1000 and total<120*1024*1024 and info.file_size<30*1024*1024
   data=z.read(info)
   if p.suffix=='.zip':
    assert len(queue)==0 and len(files)<=1;queue.append(zipfile.ZipFile(io.BytesIO(data)));continue
   assert p.suffix in ['.png','.json','.xml'] and info.filename not in files
   files[info.filename]=data
 validate_review(files);return files

def main():
 root=pathlib.Path(__file__).resolve().parent
 assert (root/"android-overlay").is_dir(), "Verifier must run from its own repository"
 for p,obj in PINS.items():assert subprocess.check_output(['git','rev-parse','HEAD:'+p],cwd=root,text=True).strip()==obj,'Native source changed; fresh acceptance required: '+p
 base='https://api.github.com/repos/2njz45z86r-commits/vpn013-wg-ios';headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'User-Agent':'VPN013-pinned-native-acceptance'}
 def get(path):
  with urllib.request.urlopen(urllib.request.Request(base+path,headers=headers),timeout=30) as r:return json.load(r)
 run=get('/actions/runs/'+str(RUN));assert run['head_sha']==SOURCE and run['status']=='completed' and run['conclusion']=='success'
 jobs=get('/actions/runs/'+str(RUN)+'/jobs')['jobs'];j=next(j for j in jobs if j['id']==123830984080)
 required={'Compile Android backend, UI and instrumented scenarios','Exercise disposable VPN, upgrades, native switch and device classes','Inspect reachable native Android dependencies'}
 assert required.issubset({s['name'] for s in j['steps']})
 assert j['conclusion']=='success' and all(s['conclusion']=='success' for s in j['steps'] if s['name'] in required)
 artifact=get('/actions/artifacts/'+str(ARTIFACT));assert artifact['digest']=='sha256:'+DIGEST and not artifact['expired'] and artifact['workflow_run']['id']==RUN and artifact['workflow_run']['head_sha']==SOURCE
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):return None
 try:response=urllib.request.build_opener(NoRedirect).open(urllib.request.Request(base+'/actions/artifacts/'+str(ARTIFACT)+'/zip',headers=headers),timeout=30)
 except urllib.error.HTTPError as error:
  assert error.code in [301,302,303,307,308];target=error.headers['Location'];assert target.startswith('https://');response=urllib.request.urlopen(target,timeout=90)
 with response:raw=response.read(30*1024*1024+1)
 assert len(raw)<=30*1024*1024
 files=read_archive(raw);output=root/'android/output'
 for name,data in files.items():
  if not name.startswith('review/'):continue
  p=output/name;p.parent.mkdir(parents=True,exist_ok=True)
  if p.exists():assert p.read_bytes()==data,'Preserve existing build evidence'
  else:p.write_bytes(data)
 proof={'nativeRun':RUN,'nativeSource':SOURCE,'sourceRunConclusion':'success','artifact':ARTIFACT,'artifactSHA256':DIGEST,'scenarioExecutions':sum(COUNTS.values()),'counts':COUNTS,'physicalAndroidTested':False,'capturesRerunFresh':False,'exactAndroidSourcesVerified':True}
 (output/'review/native-test-provenance.json').write_text(json.dumps(proof,indent=2))
 print('Accepted exact-source native Android evidence: '+str(sum(COUNTS.values()))+' executions; physical device not certified')
if __name__=='__main__':main()
