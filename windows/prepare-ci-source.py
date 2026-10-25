"""Apply public source overlays and retain the exact corresponding build source."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile

workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
root = (workspace / 'vpn013-wg-windows').resolve()
assert root.parent == workspace and root.is_dir()
overlays = workspace / 'windows/overlay'
if overlays.is_dir():
    for path in overlays.rglob('*'):
        if not path.is_file():
            continue
        assert not path.is_symlink()
        relative = path.relative_to(overlays)
        assert not any(part in ('.git', '.deps', 'output') for part in relative.parts)
        assert path.suffix in ('.ps1', '.py', '.go', '.wxs', '.c', '.h', '.txt', '.md', '.ico', '.png')
        target = root / relative
        assert target.resolve().is_relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
# Add the update offer state to the exact existing native page. The button
# does not replace the order/configuration refresh action.
tunnels_page = root / 'ui/tunnelspage.go'
page_source = tunnels_page.read_text(encoding='utf-8')
page_field = '\tupdatesBusy            int32\n'
assert page_source.count(page_field) == 1, 'Unexpected native page source'
tunnels_page.write_text(page_source.replace(page_field, page_field + '\tr013Upgrade           *r013UpgradeOffer\n'), encoding='utf-8', newline='\n')
# The base archive's build=1 predates releases1.5.x. A fixed current build must
# not keep treating the currently installed catalog entry as a new update.
install_source = root / 'r013/install_windows.go'
install_text = install_source.read_text(encoding='utf-8')
assert install_text.count('const CurrentBuild = 1') == 1
install_source.write_text(install_text.replace('const CurrentBuild = 1', ''), encoding='utf-8', newline='\n')
# An active VPN is not an installation queue. Keep the lifecycle protection,
# but tell the user the real next action instead of promising a deferred task.
update_service = root / 'manager/r013_update.go'
update_text = update_service.read_text(encoding='utf-8')
old_idle_message = 'Обновление доступно. Оно установится после отключения VPN.'
assert update_text.count(old_idle_message) == 1
update_service.write_text(update_text.replace(old_idle_message,
    'Отключите VPN и нажмите «Установить обновление» ещё раз. Профили и привязки сохранятся.'), encoding='utf-8', newline='\n')
# Keep the established executable/resource IDs and install directory. Replace
# only the branding resource AFTER the base script regenerates upstream icons.
build_r013 = root / 'scripts/build-r013.ps1'
build_r013_text = build_r013.read_text(encoding='utf-8')
icon_anchor = '$versionSource = Get-Content -LiteralPath version\\version.go -Raw'
assert build_r013_text.count(icon_anchor) == 1
build_r013.write_text(build_r013_text.replace(icon_anchor,
    "Copy-Item -LiteralPath ui/icon/vpn013.ico -Destination ui/icon/wireguard.ico -Force\n" + icon_anchor), encoding='utf-8', newline='\n')
about = root / 'ui/aboutdialog.go'
about_text = about.read_text(encoding='utf-8')
for old,new in [('About AmneziaWG','О VPN013.com WG'),('https://amnezia.org/','https://vpn013.com/'),('AmneziaWG logo image','VPN013.com WG'),('wgLbl.SetText("AmneziaWG")','wgLbl.SetText("VPN013.com WG")')]:
    assert old in about_text
    about_text=about_text.replace(old,new)
# Copyright/licensing text is retained verbatim.
wordmark_start = about_text.index('\twgLbl, err := walk.NewTextLabel(showingAboutDialog)')
wordmark_end = about_text.index('\n\tdetailsLbl, err :=',wordmark_start)
about_text = about_text[:wordmark_start] + '''\twordmark, err := walk.NewImageView(showingAboutDialog)
\tif err != nil { return err }
\tbrand, err := r013Wordmark()
\tif err != nil { return err }
\tdefer brand.Dispose()
\twordmark.SetImage(brand)
\twordmark.SetMinMaxSize(walk.Size{330,110},walk.Size{330,110})
\twordmark.Accessibility().SetName("VPN013.com WG")
''' + about_text[wordmark_end:]
about.write_text(about_text,encoding='utf-8',newline='\n')
# Keep the original protocol fixture in the same millisecond units as the
# deployed backend. Production expiry checks reject seconds-valued documents.
protocol_test = root / 'r013/protocol_test.go'
protocol_fixture = protocol_test.read_text(encoding='utf-8')
old_expiry_fixture = 'Expiry: time.Now().Add(time.Hour).Unix(),'
assert protocol_fixture.count(old_expiry_fixture) == 1, 'Unexpected base expiry fixture'
protocol_test.write_text(protocol_fixture.replace(old_expiry_fixture,
    'Expiry: time.Now().Add(time.Hour).UnixMilli(),'), encoding='utf-8', newline='\n')
os.environ['PYTHONUTF8']='1'
# bootstrap.py obtains its actual compiler from build.bat, independently of
# setup-go. Update both the URL and the official archive hash before bootstrap.
build_script = root / 'build.bat'
build_source = build_script.read_text(encoding='utf-8')
old_compiler = 'https://go.dev/dl/go1.25.14.windows-amd64.zip 119044a92b3987c341cd6aebb256676dd4780d292f7b4e72a3e9976677841697'
new_compiler = 'https://go.dev/dl/go1.26.10.windows-amd64.zip 7ecd2d7260e82c59bcbd7f1077a07cee2dea607295b858df67195a1e4e09629b'
assert build_source.count(old_compiler) == 1, 'Unexpected base compiler pin'
build_source = build_source.replace(old_compiler, new_compiler)
assert 'go1.25.14' not in build_source
build_script.write_text(build_source, encoding='utf-8', newline='\n')
subprocess.run([sys.executable,'-X','utf8',str(workspace/'windows/stage-hourly-into-existing.py'),str(workspace),str(root)],check=True)
subprocess.run([sys.executable,'-X','utf8',str(workspace/'windows/refresh-go-dependencies.py'),str(workspace),str(root)],check=True)
manifest = []
files = []
for path in sorted(root.rglob('*')):
    if not path.is_file() or path.name == 'SOURCE-MANIFEST.json':
        continue
    assert not path.is_symlink()
    assert not any(part in ('.git', '.deps', 'output') for part in path.relative_to(root).parts)
    contents = path.read_bytes()
    name = path.relative_to(root).as_posix()
    manifest.append({'path': 'vpn013-wg-windows/' + name, 'sha256': hashlib.sha256(contents).hexdigest()})
    files.append((name, contents))
(root / 'SOURCE-MANIFEST.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
archive = Path(os.environ['RUNNER_TEMP']) / 'VPN013WG-1.5.1-windows-source.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
    for name, contents in files:
        bundle.writestr('vpn013-wg-windows/' + name, contents)
    bundle.write(root / 'SOURCE-MANIFEST.json', 'vpn013-wg-windows/SOURCE-MANIFEST.json')
print('Exact corresponding build source preserved:', hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest())
