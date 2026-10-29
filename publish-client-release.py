"""Publish public, credential-free metadata only after successful native tests."""
import base64, hashlib, json, os, plistlib, subprocess, zipfile, sys, re
from pathlib import Path

repository = os.environ['GITHUB_REPOSITORY']
assert repository == '2njz45z86r-commits/vpn013-wg-ios'
run = os.environ['GITHUB_RUN_ID']
verification = json.loads(Path('build/review/bundle-verification.json').read_text())
ipa = Path('build/VPN013AWG-unsigned.ipa')
summary = json.loads(Path('build/review/test-summary.json').read_text())
assert ipa.is_file() and summary.get('result') == 'Passed' and summary.get('failedTests') == 0 and summary.get('passedTests') == 41 and summary.get('totalTestCount') == 41 and summary.get('skippedTests', 0) == 0 and summary.get('testFailures') == [], 'Do not publish failed, incomplete or unverified native tests'
assert verification.get('appID') == 'com.vpn013.awg' and verification.get('extensionID') == 'com.vpn013.awg.network-extension'
assert verification.get('adHocIntegrityChecked') is True and verification.get('customerKeysIncluded') is False
with zipfile.ZipFile(ipa) as archive:
    info=plistlib.loads(archive.read('Payload/AmneziaWG.app/Info.plist'))
    extension=plistlib.loads(archive.read('Payload/AmneziaWG.app/PlugIns/WireGuardNetworkExtension.appex/Info.plist'))
assert info['CFBundleIdentifier'] == verification['appID'] and extension['CFBundleIdentifier'] == verification['extensionID']
assert info['CFBundleVersion'] == extension['CFBundleVersion'] and info['CFBundleShortVersionString'] == extension['CFBundleShortVersionString']
assert info['CFBundleShortVersionString'] == verification['version']
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', verification['version']), 'Invalid public release version'
public_name = f'VPN013-{verification["version"]}.ipa'
Path('build', public_name).write_bytes(ipa.read_bytes())
value = dict(schema=1,app='vpn013-wg',platform='ios',version=verification['version'],build=int(info['CFBundleVersion']),
    downloadURL=f'https://github.com/{repository}/releases/download/unsigned-{run}/{public_name}',
    sha256=hashlib.sha256(ipa.read_bytes()).hexdigest(),
    notes='VPN013 1.7.1: компактная круглая кнопка Авто на верхней панели; ссылки из бота открывают нужный раздел VPN013. Добавление ключа из буфера, QR-кода камеры или файла с явной кнопкой загрузки. Закрытие клавиатуры и возврат из другого приложения сохраняют введённый текст; замена новым ключом требует подтверждения. Поддерживаются ссылки импорта Happ, INCY и BlackTemple с HTTPS-подпиской. VPN013: четыре раздела — Happ, INCY, AmneziaWG и BlackTemple. Для совместимых подключений поддерживаются VLESS, Base64, JSON Xray и HTTPS-подписки; закрытые форматы сторонних клиентов не объявлены поддерживаемыми. Общий режим Авто включён по умолчанию и отключается вверху списка. Если текущая группа не подтверждает VPN-трафик, приложение перебирает другие загруженные конфигурации и разделы. Настройки маршрутизации каждого подключения сохраняются; при отсутствии интернета варианты не считаются исчерпанными. Следующий движок запускается только после остановки предыдущего, а экран показывает фактически выбранный раздел. Если все варианты не работают, показана ошибка без создания новых ключей или продления доступа. Расширение сравнивает серверы каждые 5 минут и проверяет работоспособность текущего соединения; показатели разных видов не смешиваются. Источники HTTPS-подписок хранятся зашифрованно: обновление восстанавливает удалённые серверы и убирает снятые провайдером, сохраняя личные профили. Для обновления списка сначала выключите VPN. У VPN013 свой идентификатор устройства: для ранее привязанной ссылки может понадобиться отдельный слот или восстановление в кабинете провайдера. Российские IP-сети идут напрямую в поддерживаемых полных профилях AmneziaWG; в VLESS доступны собственные правила по доменам и IP. Для установки на iPhone требуется подпись владельца, например в ESign. Сборка и симулятор не подтверждают VPN-трафик на физическом iPhone.')
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
