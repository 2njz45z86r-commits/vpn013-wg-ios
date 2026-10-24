"""Apply public source overlays and retain the exact corresponding build source."""
from pathlib import Path
import hashlib
import json
import os
import shutil
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
archive = Path(os.environ['RUNNER_TEMP']) / 'VPN013WG-1.4.0-windows-source.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
    for name, contents in files:
        bundle.writestr('vpn013-wg-windows/' + name, contents)
    bundle.write(root / 'SOURCE-MANIFEST.json', 'vpn013-wg-windows/SOURCE-MANIFEST.json')
print('Exact corresponding build source preserved:', hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest())

