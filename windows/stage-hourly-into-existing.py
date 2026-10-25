"""Stage the native-verified hourly source into the exact reviewed existing client.
This script does not build, execute, install, sign or publish an application.
"""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,os
os.environ["PYTHONUTF8"]="1"
checkout=Path(sys.argv[1]).resolve()
root=Path(sys.argv[2]).resolve()
assert root.is_dir() and root.name=='vpn013-wg-windows'
before={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('go.mod','go.sum')}
assert before=={'go.mod':'0ffc3918f04162ed0dd982d6193252ecab7629209d301fd59b8aa0822f6254f7','go.sum':'4fe66e226c06924ec095e45388f229863a20617a913e765ab0f9f45cec4ef0f2'},'Unreviewed module files'
overlay = checkout / 'windows-hourly' / 'overlay'
for package in ('r013probe', 'r013gate', 'r013winudp','r013vault','r013tun','r013prepare'):
    assert not (root / package).exists(), 'Unexpected hourly package already exists'
    shutil.copytree(overlay / package, root / package)
assert before == {f: hashlib.sha256((root / f).read_bytes()).hexdigest() for f in before}
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-device-fence.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-service-lifecycle.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-observation.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-owned-tun.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-firewall-sid.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-service-dispatch.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-firewall-replace.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-numeric-uapi.py'),str(root)],check=True)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-existing-network.py'),str(root)],check=True)
for name in ('r013_existing_network.go','r013_existing_network_windows_test.go'):
    shutil.copy2(checkout/'windows-hourly'/name,root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'/name)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-backend-owner.py'),str(root)],check=True)
for name in ('r013_backend_owner.go','r013_backend_owner_windows_test.go','r013_backend_peers_windows_test.go','r013_hourly_worker.go','r013_hourly_worker_windows_test.go'):
    shutil.copy2(checkout/'windows-hourly'/name,root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'/name)
subprocess.run([sys.executable,str(checkout/'windows-hourly/patch-hourly-worker.py'),str(root)],check=True)
for name in ('r013_auto.go','r013_auto_hourly_test.go'):
    shutil.copy2(overlay/'manager'/name,root/'manager'/name)
shutil.copy2(checkout/'windows-hourly/firewall_status_windows_test.go',root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall/firewall_status_windows_test.go')

assert before=={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in before}
print('Native-verified safety/worker/manager source staged; module files unchanged; actual product acceptance still required')
