"""Publish public, credential-free metadata only after successful native tests."""
import base64, hashlib, json, os, plistlib, subprocess, zipfile, sys, re
from pathlib import Path
# The release gate rejects untracked files, including Python bytecode.
sys.dont_write_bytecode = True
from scripts.native_ui_shards import verify_combined
from scripts.verify_public_ipa import verify_public_ipa

# This script is a release path even when run outside GitHub Actions.
# Check the current tracked source review before preparing or publishing.
subprocess.run([sys.executable, 'scripts/security_release_gate.py'], check=True)

def require(condition, message):
    if not condition:
        raise ValueError(message)

repository = os.environ['GITHUB_REPOSITORY']
require(repository == '2njz45z86r-commits/vpn013-wg-ios', 'Unexpected release repository')
run = os.environ['GITHUB_RUN_ID']
attempt = os.environ['GITHUB_RUN_ATTEMPT']
combined_summary = verify_combined(Path('build/native-ui-artifact/unified-native-review.zip'),
    os.environ['GITHUB_SHA'], run, attempt)
require(Path('build/review/test-summary.json').read_bytes() == combined_summary, 'Native summary differs from verified same-run artifact')
verification = json.loads(Path('build/review/bundle-verification.json').read_text())
ipa = Path('build/VPN013AWG-unsigned.ipa')
summary = json.loads(Path('build/review/test-summary.json').read_text())
require(ipa.is_file() and summary.get('result') == 'Passed' and summary.get('failedTests') == 0 and summary.get('passedTests') == 56 and summary.get('totalTestCount') == 56 and summary.get('skippedTests', 0) == 0 and summary.get('testFailures') == [], 'Do not publish failed, incomplete or unverified native tests')
require(verification.get('appID') == 'com.vpn013.awg' and verification.get('extensionID') == 'com.vpn013.awg.network-extension', 'Unexpected app or extension identity')
require(verification.get('adHocIntegrityChecked') is True and verification.get('customerKeysIncluded') is False, 'Bundle review is incomplete')
with zipfile.ZipFile(ipa) as archive:
    info=plistlib.loads(archive.read('Payload/AmneziaWG.app/Info.plist'))
    extension=plistlib.loads(archive.read('Payload/AmneziaWG.app/PlugIns/WireGuardNetworkExtension.appex/Info.plist'))
require(info['CFBundleIdentifier'] == verification['appID'] and extension['CFBundleIdentifier'] == verification['extensionID'], 'Bundle identities do not match')
require(info['CFBundleVersion'] == extension['CFBundleVersion'] and info['CFBundleShortVersionString'] == extension['CFBundleShortVersionString'], 'App and extension versions differ')
require(info['CFBundleShortVersionString'] == verification['version'], 'Reviewed version does not match bundle')
require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', verification['version']), 'Invalid public release version')
public_name = f'VPN013-{verification["version"]}.ipa'
Path('build', public_name).write_bytes(ipa.read_bytes())
value = dict(schema=1,app='vpn013-wg',platform='ios',version=verification['version'],build=int(info['CFBundleVersion']),
    downloadURL=f'https://github.com/{repository}/releases/download/unsigned-{run}/{public_name}',
    sha256=hashlib.sha256(ipa.read_bytes()).hexdigest(),
    notes='VPN013 1.7.5: выбор нескольких серверов для общих правил маршрутизации; панель подключения, статистики и пинга в Happ, INCY и BlackTemple; сокращённые единицы скорости по реальным счётчикам. Обновления доступны в настройках; лишняя кнопка в AmneziaWG убрана. Совместимость импорта INCY/XHTTP и ZIP сохранена. Существующие профили сохраняются при ошибке импорта. Для установки на iPhone требуется подпись владельца. Проверки на симуляторе не подтверждают VPN-трафик на физическом устройстве.')
manifest = json.dumps(value,ensure_ascii=False,indent=2)+'\n'
Path('build/client-release.json').write_text(manifest,encoding='utf-8')
if '--prepare-only' in sys.argv:
    print('Verified public metadata prepared; nothing published')
    raise SystemExit(0)
verify_public_ipa(value['downloadURL'], value['sha256'], ipa.stat().st_size)
path=f'repos/{repository}/contents/client-release.json'
current=subprocess.run(['gh','api',path],capture_output=True,text=True)
body={'message':f'Publish verified iOS release {value["version"]} build {value["build"]}',
      'content':base64.b64encode(manifest.encode()).decode(),'branch':'main'}
if current.returncode==0:
    previous=json.loads(current.stdout)
    if previous.get('content'):
        old=json.loads(base64.b64decode(previous['content']))
        require(old['build'] <= value['build'], 'Never downgrade public release catalog')
    body['sha']=previous['sha']
elif '404' not in current.stderr:raise RuntimeError('Cannot inspect public release manifest')
request=Path('build/release-catalog-request.json');request.write_text(json.dumps(body))
subprocess.run(['gh','api','--method','PUT',path,'--input',str(request)],check=True,capture_output=True)
subprocess.run(['gh','release','upload','unsigned-'+run,'build/client-release.json'],check=True,capture_output=True)
print('Verified release metadata published for app and bot update checks')
