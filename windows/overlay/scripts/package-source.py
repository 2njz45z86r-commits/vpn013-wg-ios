"""Create the reviewed corresponding-source bundle; never include work/keys/data."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import zipfile

root = Path(__file__).resolve().parents[1]
files = {root / p for p in subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0') if p}
for directory in ('r013', 'scripts', 'vendor', '.impeccable'):
    files.update(p for p in (root / directory).rglob('*') if p.is_file())
files.update(root / p for p in ('PRODUCT.md', 'DESIGN.md', 'THIRD-PARTY-NOTICES.txt', 'release-public-key.txt', 'r013_preview.go', 'r013_preview_disabled.go', 'docs/wintun-binaries-license.txt'))
files.update((root / 'manager').glob('r013*.go'))
files.update((root / 'ui').glob('r013*.go'))
out = root / 'output' / 'release'
out.mkdir(parents=True, exist_ok=True)
version = re.search(r'Number\s*=\s*"([\d.]+)"', (root / 'version/version.go').read_text()).group(1)
target = out / f'VPN013WG-{version}-windows-source.zip'
denied = {'.git', '.deps', 'output', 'amd64', 'arm64', 'x86', 'arm', '__pycache__'}
secret = re.compile(rb'-----BEGIN (?:OPENSSH |RSA |EC |ENCRYPTED )?PRIVATE KEY-----|[0-9]{8,}:[A-Za-z0-9_-]{35}')
manifest = []
with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
    for path in sorted(files):
        relative = path.relative_to(root)
        if any(part in denied for part in relative.parts) or path.suffix.lower() in ('.exe', '.dll', '.msi', '.p12', '.pfx', '.key', '.conf', '.pyc', '.syso', '.ico'):
            continue
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in ('WORK_STATE.md', 'WINDOWS_WORK_STATE.md', '.env'):
            raise ValueError('Private state in source allowlist')
        contents = path.read_bytes()
        if secret.search(contents):
            raise ValueError('Possible credential in ' + str(relative))
        name = 'vpn013-wg-windows/' + relative.as_posix()
        bundle.writestr(name, contents)
        manifest.append({'path': name, 'sha256': hashlib.sha256(contents).hexdigest()})
    # Include the GPL tools' complete source archive, not local objects/binaries.
    with zipfile.ZipFile(root / '.deps/amneziawg-tools.zip') as upstream:
        for member in upstream.infolist():
            parts = member.filename.split('/')[1:]
            if member.is_dir() or not parts:
                continue
            relative = Path(*parts)
            if '..' in parts or relative.is_absolute():
                raise ValueError('Unsafe upstream path')
            contents = upstream.read(member)
            if relative.as_posix() == 'src/ipc-uapi-windows.h':
                contents = (root / '.deps/src/ipc-uapi-windows.h').read_bytes()
            name = 'vpn013-wg-windows/third_party/amneziawg-tools/' + relative.as_posix()
            bundle.writestr(name, contents)
            manifest.append({'path': name, 'sha256': hashlib.sha256(contents).hexdigest()})
    bundle.writestr('vpn013-wg-windows/SOURCE-MANIFEST.json', json.dumps(manifest, indent=2))
digest = hashlib.file_digest(target.open('rb'), 'sha256').hexdigest()
(out / 'source-summary.json').write_text(json.dumps({'filename': target.name, 'sha256': digest, 'files': len(manifest), 'bytes': target.stat().st_size}, indent=2))
print(json.dumps({'filename': target.name, 'sha256': digest, 'files': len(manifest), 'bytes': target.stat().st_size}))
