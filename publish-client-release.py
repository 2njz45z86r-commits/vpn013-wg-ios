"""Publish public, credential-free metadata only after successful native tests."""
import base64, hashlib, json, os, plistlib, subprocess, zipfile
from pathlib import Path

repository = os.environ['GITHUB_REPOSITORY']
assert repository == '2njz45z86r-commits/vpn013-wg-ios'
run = os.environ['GITHUB_RUN_ID']
verification = json.loads(Path('build/review/bundle-verification.json').read_text())
ipa = Path('build/VPN013AWG-unsigned.ipa')
summary = json.loads(Path('build/review/test-summary.json').read_text())
assert ipa.is_file() and summary.get('failedTests') == 0, 'Do not publish failed or unverified tests'
with zipfile.ZipFile(ipa) as archive:
    info=plistlib.loads(archive.read('Payload/AmneziaWG.app/Info.plist'))
assert info['CFBundleShortVersionString'] == verification['version']
value = dict(schema=1,app='vpn013-wg',platform='ios',version=verification['version'],build=int(info['CFBundleVersion']),
    downloadURL=f'https://github.com/{repository}/releases/download/unsigned-{run}/VPN013AWG-unsigned.ipa',
    sha256=hashlib.sha256(ipa.read_bytes()).hexdigest(),
    notes='РџСЂРѕРІРµСЂРєР° РЅРѕРІС‹С… РІРµСЂСЃРёР№ Рё РѕР±РЅРѕРІР»РµРЅРёРµ СЃРµСЂРІРµСЂРѕРІ РїРѕ Р·Р°СЏРІРєРµ РёР· ZIP. РџСЂРёРјРµРЅРµРЅРёРµ РїРѕСЃР»Рµ РѕС‚РєР»СЋС‡РµРЅРёСЏ VPN; СЃС‚РѕСЂРѕРЅРЅРёРµ РїСЂРѕС„РёР»Рё Рё РєР»СЋС‡Рё СЃРѕС…СЂР°РЅСЏСЋС‚СЃСЏ.')
manifest = json.dumps(value,ensure_ascii=False,indent=2)+'\n'
Path('build/client-release.json').write_text(manifest,encoding='utf-8')
path=f'repos/{repository}/contents/client-release.json'
current=subprocess.run(['gh','api',path],capture_output=True,text=True)
body={'message':f'Publish verified iOS release {value["version"]} build {value["build"]}',
      'content':base64.b64encode(manifest.encode()).decode(),'branch':'main'}
if current.returncode==0:
    previous=json.loads(current.stdout)
    if previous.get('content'):
        old=json.loads(base64.b64decode(previous['content']))
        assert old['build'] <= value['build'], 'Never downgrade public release catalog'
    body['sha']=previous['sha']
elif '404' not in current.stderr:raise RuntimeError('Cannot inspect public release manifest')
request=Path('build/release-catalog-request.json');request.write_text(json.dumps(body))
subprocess.run(['gh','api','--method','PUT',path,'--input',str(request)],check=True,capture_output=True)
subprocess.run(['gh','release','upload','unsigned-'+run,'build/client-release.json'],check=True,capture_output=True)
print('Verified release metadata published for app and bot update checks')
