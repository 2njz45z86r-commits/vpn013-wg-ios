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
        assert path.suffix in ('.ps1', '.py', '.go', '.wxs', '.c', '.h', '.txt', '.md')
        target = root / relative
        assert target.resolve().is_relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
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
