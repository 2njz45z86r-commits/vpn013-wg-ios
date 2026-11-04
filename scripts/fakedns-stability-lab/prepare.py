"""Diagnostic only: copy pinned Xray to owned temp and apply hashed lab files."""
from pathlib import Path
import hashlib,json,shutil,subprocess
lab=Path(__file__).resolve().parent
root=Path('overlay/Sources/WireGuardKitGo').resolve()
info=json.loads(subprocess.check_output(['go','list','-m','-json','github.com/xtls/xray-core'],cwd=root))
r=info['Replace'];assert r['Path']=='github.com/amnezia-vpn/amnezia-xray-core' and r['Version']=='v1.260728.0'
source=Path(r['Dir']);out=Path('build/fakedns-stability-owned').resolve();assert not out.exists()
man=json.loads((lab/'manifest.json').read_text());src=source/'app/dns/fakedns/fake.go'
assert hashlib.sha256(src.read_bytes()).hexdigest()==man['expectedOriginalSHA256']
shutil.copytree(source,out,copy_function=shutil.copyfile)
for name,digest in man['experimentalFiles'].items():
 data=(lab/(name+'.txt')).read_bytes();assert hashlib.sha256(data).hexdigest()==digest
 (out/'app/dns/fakedns'/name).write_bytes(data)
print('Prepared checksum-bound experimental Xray copy; module cache unchanged.')
