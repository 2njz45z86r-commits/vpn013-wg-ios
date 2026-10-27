"""Publish public, credential-free metadata only after successful native tests."""
import base64, hashlib, json, os, plistlib, subprocess, zipfile, sys, re
from pathlib import Path

repository = os.environ['GITHUB_REPOSITORY']
assert repository == '2njz45z86r-commits/vpn013-wg-ios'
run = os.environ['GITHUB_RUN_ID']
verification = json.loads(Path('build/review/bundle-verification.json').read_text())
ipa = Path('build/VPN013AWG-unsigned.ipa')
summary = json.loads(Path('build/review/test-summary.json').read_text())
assert ipa.is_file() and summary.get('result') == 'Passed' and summary.get('failedTests') == 0 and summary.get('passedTests') == 31 and summary.get('totalTestCount') == 31 and summary.get('skippedTests', 0) == 0 and summary.get('testFailures') == [], 'Do not publish failed or unverified tests'
with zipfile.ZipFile(ipa) as archive:
    info=plistlib.loads(archive.read('Payload/AmneziaWG.app/Info.plist'))
assert info['CFBundleShortVersionString'] == verification['version']
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', verification['version']), 'Invalid public release version'
public_name = f'VPN013-{verification["version"]}.ipa'
Path('build', public_name).write_bytes(ipa.read_bytes())
value = dict(schema=1,app='vpn013-wg',platform='ios',version=verification['version'],build=int(info['CFBundleVersion']),
    downloadURL=f'https://github.com/{repository}/releases/download/unsigned-{run}/{public_name}',
    sha256=hashlib.sha256(ipa.read_bytes()).hexdigest(),
    notes='Добавлен защищённый локальный канал чтения реальной статистики расширения при недоступном системном обмене. Российские IP-сети напрямую, остальные адреса через VPN в профилях полного туннеля. Исходные профили и ключи сохраняются. Три дня теста бесплатно: полный ZIP загружается и импортируется внутри приложения. Срок доступа — 72 часа; продление прежних ключей выполняется через личную ссылку в Telegram после ручного подтверждения оплаты владельцем. Авто сравнивает другие VPN без отключения текущего при проверке: сначала через 30 секунд, затем раз в час. Для iPhone подпишите IPA в ESign и установите. Сборка и симулятор не заменяют проверку на физическом iPhone.')
manifest = json.dumps(value,ensure_ascii=False,indent=2)+'\n'
Path('build/client-release.json').write_text(manifest,encoding='utf-8')
if '--prepare-only' in sys.argv:
    print('Verified public metadata prepared; nothing published')
    raise SystemExit(0)
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
