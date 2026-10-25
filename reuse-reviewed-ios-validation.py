"""Reuse completed native UI evidence only for the exact tested app/toolchains.
Fresh device compilation, core checks and live Go SCA still run in this job.
No distribution/signing/publication is performed by this evidence reader.
"""
from pathlib import Path,PurePosixPath
import hashlib,io,json,os,platform,subprocess,urllib.error,urllib.parse,urllib.request,zipfile

REPOSITORY='2njz45z86r-commits/vpn013-wg-ios'
RUN=40215533930
ARTIFACT=12607512992
HEAD='e0263201fd947aac53296d6d60fc511f60f78867'
DIGEST='c96ffa859bd0d18668358f1cb37f7230938c0f44776a20394d5b3c9f5598f107'
PINS={'overlay':'02e2f1cb8062f3293370491a3689eb6dc75de4ed',
      'build-on-mac.sh':'f618b7ed33dc9c98dac57dfe1d31cbf3ec9ce9f6',
      'inspect-on-mac.sh':'a35ee4de8dc5244e15cf62a2d7589c6f75bf64f5',
      'tests/AutoControllerLifecycleTests.swift':'cceaa6f76316290f759dbec758fa4721444d1cd4',
      'scripts/check_go_security.py':'282b68bd42672af5fd00f408cf554be73525e163'}
assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')==REPOSITORY
for path,expected in PINS.items():
    assert subprocess.check_output(['git','rev-parse','HEAD:'+path],text=True).strip()==expected,'Native source differs: '+path
assert subprocess.check_output(['xcodebuild','-version'],text=True).strip()=='Xcode 16.4\nBuild version 16F6'
assert platform.machine()=='arm64'
assert subprocess.check_output(['go','version'],text=True).strip()=='go version go1.26.10 darwin/arm64'
root=Path('build/review');fresh=json.loads((root/'bundle-verification.json').read_text())
assert fresh['version']=='1.5.1' and fresh['adHocIntegrityChecked'] and fresh['requiresOwnerResigning'] and not fresh['customerKeysIncluded']

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
opener=urllib.request.build_opener(NoRedirect())
def api(path):
    # The CI token is used ONLY at this fixed GitHub API origin. In particular
    # it is never forwarded to the artifact-storage redirect destination.
    request=urllib.request.Request('https://api.github.com/repos/'+REPOSITORY+'/'+path,
        headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json'})
    return opener.open(request,timeout=45)
with api('actions/runs/'+str(RUN)) as response:run=json.load(response)
assert run['status']=='completed' and run['conclusion']=='success' and run['head_sha']==HEAD
with api('actions/artifacts/'+str(ARTIFACT)) as response:meta=json.load(response)
assert meta['workflow_run']['id']==RUN and meta['workflow_run']['head_sha']==HEAD and meta['digest']=='sha256:'+DIGEST and not meta['expired']
try:
    with api('actions/artifacts/'+str(ARTIFACT)+'/zip') as response:raw=response.read(10_000_001)
except urllib.error.HTTPError as error:
    assert error.code in (301,302,303,307,308)
    location=error.headers['Location'];error.close()
    for _ in range(4):
        url=urllib.parse.urlsplit(location)
        assert url.scheme=='https' and not url.username and not url.password and url.port in (None,443)
        assert url.hostname.endswith(('.blob.core.windows.net','.githubusercontent.com'))
        try:
            # A separate Request has NO Authorization header.
            with opener.open(urllib.request.Request(location),timeout=45) as response:raw=response.read(10_000_001)
            break
        except urllib.error.HTTPError as redirect:
            assert redirect.code in (301,302,303,307,308)
            location=urllib.parse.urljoin(location,redirect.headers['Location']);redirect.close()
    else:raise AssertionError('Too many artifact redirects')
assert len(raw)<=10_000_000 and hashlib.sha256(raw).hexdigest()==DIGEST
with zipfile.ZipFile(io.BytesIO(raw)) as archive:
    assert archive.testzip() is None and len(archive.infolist())==10
    summary=json.loads(archive.read('test-summary.json'))
    assert summary['result']=='Passed' and summary['passedTests']==23 and summary['failedTests']==0 and summary['skippedTests']==0
    assert json.loads(archive.read('bundle-verification.json'))==fresh
    assert {'phone-large-type.png','tablet.png'}<=set(archive.namelist())
    for item in archive.infolist():
        name=PurePosixPath(item.filename)
        assert len(name.parts)==1 and not name.is_absolute() and '..' not in name.parts and name.suffix in ('.png','.json','.txt')
        assert item.file_size<10_000_000 and (item.external_attr>>16)&0o170000!=0o120000
        if name.name=='bundle-verification.json':continue
        data=archive.read(item)
        if name.suffix=='.png':assert data.startswith(b'\x89PNG\r\n\x1a\n')
        (root/name.name).write_bytes(data)
(root/'native-evidence-provenance.json').write_text(json.dumps({'schema':1,'nativeEvidenceRun':RUN,
    'nativeArtifactID':ARTIFACT,'nativeArchiveSHA256':DIGEST,'sourcePins':PINS,'nativeTestsPassed':23,
    'nativeTestsFailed':0,'nativeTestsSkipped':0,'freshDeviceBuildChecked':True,'nativeUITestsRerunInPackagingJob':False,
    'xcode':'16.4(16F6)','go':'1.26.10','physicalIPhoneTested':False},indent=2))
print('Verified23 native UI passes on identical app source/Xcode/Go; fresh device build independently checked')
