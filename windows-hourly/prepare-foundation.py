"""Prepare source-only disposable tests; never build or install the application."""
from pathlib import Path
import hashlib, json, shutil, subprocess, sys, zipfile

checkout = Path(sys.argv[1]).resolve()
workspace = Path(sys.argv[2]).resolve()
workspace.mkdir(parents=True, exist_ok=False)
archive = workspace / 'baseline.zip'
url = 'https://github.com/2njz45z86r-commits/vpn013-wg-ios/releases/download/windows-source-1.4.0/VPN013WG-1.4.0-windows-source.zip'
subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error', '--retry', '2', '--max-time', '180', '-o', str(archive), url], check=True)
assert hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() == 'f7c4a928eecc6e40a1d7b0bcf37bf26d7b6de1b449a2ca26f7cf1ffc2bd83e35'
with zipfile.ZipFile(archive) as z:
    for entry in z.infolist():
        dest = (workspace / entry.filename).resolve()
        assert dest.is_relative_to(workspace), 'archive traversal'
    z.extractall(workspace)
root = workspace / 'vpn013-wg-windows'
assert (root / 'go.mod').is_file()
before = {f: hashlib.sha256((root / f).read_bytes()).hexdigest() for f in ('go.mod', 'go.sum')}
overlay = checkout / 'windows-hourly' / 'overlay'
for package in ('r013probe', 'r013gate', 'r013winudp','r013vault','r013tun'):
    assert not (root / package).exists()
    shutil.copytree(overlay / package, root / package)
assert before == {f: hashlib.sha256((root / f).read_bytes()).hexdigest() for f in before}
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-device-fence.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-service-lifecycle.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-observation.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-owned-tun.py'),str(root)],check=True)
(workspace / 'source-evidence.json').write_text(json.dumps({'baseline_sha256': hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest(), 'module_files': before, 'scope': 'source-only barrier and socket primitives; NOT production lifecycle or Wintun integration'}, indent=2))
print(root)
