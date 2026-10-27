"""Publish the existing, reviewed build. Never rebuild or replace an asset."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile

REPO = '2njz45z86r-commits/vpn013-wg-ios'
SOURCE = 'aee39f578236abfa1551cc88ba23b5a86653d3ad'
RUN = 40456261848
TAG = 'windows-1.5.5'
PUBLIC_KEY = 'a0d080200bc93d55dcf7cee605e64e1d30381d2552cdf90696e29d52b34f26b8'
ROOT = Path('.github/release-publication/windows-1.5.5')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', 'repos/' + REPO + '/' + path]))

def unpack(path, target):
    with zipfile.ZipFile(path) as archive:
        assert sum(x.file_size for x in archive.infolist()) < 500_000_000
        seen = set()
        for entry in archive.infolist():
            rel = PurePosixPath(entry.filename)
            assert not rel.is_absolute() and '..' not in rel.parts and '\\' not in entry.filename
            assert (entry.external_attr >> 16) & 0o170000 != 0o120000
            dest = target.joinpath(*rel.parts).resolve()
            assert dest.is_relative_to(target.resolve()) and str(dest).casefold() not in seen
            seen.add(str(dest).casefold())
            if entry.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, dest.open('xb') as output:
                    shutil.copyfileobj(source, output)

def download_artifact(artifact_id, expected, temp):
    info = api(f'actions/artifacts/{artifact_id}')
    assert info['workflow_run']['id'] == RUN and info['workflow_run']['head_sha'] == SOURCE
    assert not info['expired'] and info['digest'] == 'sha256:' + expected
    dest = temp / f'{artifact_id}.zip'
    with dest.open('xb') as output:
        subprocess.run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{artifact_id}/zip'], stdout=output, check=True)
    assert sha(dest.read_bytes()) == expected
    out = temp / str(artifact_id)
    unpack(dest, out)
    return out

def main():
    record = json.loads((ROOT / 'record.json').read_text())
    assert record['source'] == SOURCE and record['run'] == RUN and record['tag'] == TAG
    run = api(f'actions/runs/{RUN}')
    assert run['status'] == 'completed' and run['conclusion'] == 'success'
    assert run['head_sha'] == SOURCE and run['path'] == '.github/workflows/build-windows.yml'
    jobs = api(f'actions/runs/{RUN}/jobs?per_page=100')['jobs']
    assert jobs and all(j['conclusion'] == 'success' for j in jobs)
    with tempfile.TemporaryDirectory() as folder:
        temp = Path(folder)
        built = download_artifact(12712837201, 'af20bf47475375bb240a3b165340a1b31327eec16c1552198e93bf078f21752d', temp)
        evidence = download_artifact(12712497562, '057f79ee8f71101ad6e488b22abcc754c838c26f28c5ff09ed5a081c1d48a4f0', temp)
        native_files = list(evidence.rglob('verification.json'))
        native = [json.loads(p.read_text()) for p in native_files if 'hourly-product-report' in str(p)]
        assert len(native) == 1
        native = native[0]
        assert (native['top_level'], native['subtests'], native['fail'], native['skip']) == (112, 176, 0, 0)
        assert 'TestOwnedRefreshPreservesKeysForeignProfilesAutoAndRollback' in native['tests']
        assets = temp / 'public'; assets.mkdir()
        names = set()
        for item in record['assets']:
            name = item['name']
            assert re.fullmatch(r'[A-Za-z0-9._-]{1,100}', name) and name not in names
            names.add(name)
            assert re.fullmatch(r'[a-f0-9]{64}', item['sha256'])
            if item['origin'] == 'native-artifact':
                found = list(built.rglob(name)); assert len(found) == 1
                data = found[0].read_bytes()
            else:
                assert item['origin'] == 'reviewed-public-metadata'
                data = (ROOT / name).read_bytes()
            assert sha(data) == item['sha256']
            (assets / name).write_bytes(data)
        assert names == {'VPN013WG-1.5.5-amd64.msi', 'VPN013WG-1.5.5-windows-source.zip', 'windows-build-provenance.json', 'client-release-windows-public.json', 'client-release-windows.json', 'SHA256SUMS-Windows.txt'}
        provenance = json.loads((assets / 'windows-build-provenance.json').read_text())
        assert provenance['commit'] == SOURCE and int(provenance['runId']) == RUN
        signed = json.loads((assets / 'client-release-windows.json').read_text())
        payload = base64.urlsafe_b64decode(signed['payload'] + '=' * (-len(signed['payload']) % 4))
        signature = base64.urlsafe_b64decode(signed['signature'] + '=' * (-len(signed['signature']) % 4))
        assert payload == (assets / 'client-release-windows-public.json').read_bytes()
        key = temp / 'key.der'; key.write_bytes(bytes.fromhex('302a300506032b6570032100' + PUBLIC_KEY))
        sig = temp / 'signature'; sig.write_bytes(signature)
        subprocess.run(['openssl','pkeyutl','-verify','-pubin','-keyform','DER','-inkey',str(key),'-rawin','-in',str(assets/'client-release-windows-public.json'),'-sigfile',str(sig)],check=True)
        public = json.loads(payload)
        assert public['version'] == '1.5.5' and public['build'] == 8
        assert public['sha256'] == sha((assets / 'VPN013WG-1.5.5-amd64.msi').read_bytes())
        assert public['downloadURL'] == f'https://github.com/{REPO}/releases/download/{TAG}/VPN013WG-1.5.5-amd64.msi'
        # The public read is unauthenticated; a 404 alone authorizes creation.
        url = f'https://api.github.com/repos/{REPO}/releases/tags/{TAG}'
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                existing = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code != 404: raise
            existing = None
        if existing is None:
            subprocess.run(['gh','release','create',TAG,'--repo',REPO,'--target',SOURCE,'--prerelease','--title','VPN013 Windows 1.5.5 — актуальные серверы подписки','--notes-file',str(ROOT/'release-notes.md'),*[str(p) for p in sorted(assets.iterdir())]],check=True)
        else:
            assert existing['target_commitish'] == SOURCE and not existing['draft']
        release = api('releases/tags/' + TAG)
        assert not release['draft'] and release['target_commitish'] == SOURCE
        assert {a['name'] for a in release['assets']} == names
        for item in record['assets']:
            asset = next(a for a in release['assets'] if a['name'] == item['name'])
            assert asset['digest'] == 'sha256:' + item['sha256']
            assert asset['size'] == (assets / item['name']).stat().st_size
        print('Published and independently verified all six exact reviewed public assets.')

if __name__ == '__main__':
    main()
