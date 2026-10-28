#!/bin/sh
set -eu
export HOMEBREW_NO_AUTO_UPDATE=1
mkdir -p build/review
python3 - <<'PY'
import hashlib,json,os,platform,tarfile,urllib.request
from pathlib import Path
if os.popen('go version 2>/dev/null').read().split()[2:3] and 'go1.26.10' in os.popen('go version').read():
 print('Go 1.26 installed')
else:
 data=json.load(urllib.request.urlopen('https://go.dev/dl/?mode=json&include=all',timeout=30))
 release=next(x for x in data if x['version']=='go1.26.10')
 arch='arm64' if platform.machine()=='arm64' else 'amd64'
 f=next(f for f in release['files'] if f['os']=='darwin' and f['arch']==arch and f['kind']=='archive')
 path=Path('build/go.tgz');urllib.request.urlretrieve('https://go.dev/dl/'+f['filename'],path)
 assert hashlib.sha256(path.read_bytes()).hexdigest()==f['sha256']
 with tarfile.open(path) as t:t.extractall('build/toolchain',filter='data')
 Path('build/go-source.json').write_text(json.dumps({'version':release['version'],'sha256':f['sha256']}))
PY
if [ -d "$PWD/build/toolchain/go/bin" ]; then export PATH="$PWD/build/toolchain/go/bin:$PATH"; fi
go version
git clone --quiet https://github.com/amnezia-vpn/amneziawg-apple.git build/awg
cd build/awg
git checkout --quiet 9d5ee60edefa95b933a738dd7cda671dd18021fc
python3 - <<'PY'
from pathlib import Path
source=Path('../../overlay')
files=[p for p in source.rglob('*') if p.is_file()]
assert len(files)==107, 'Unexpected source overlay'
for p in files:
 assert not p.is_symlink(), 'Source overlay must not contain symbolic links'
 target=Path(p.relative_to(source)); target.parent.mkdir(parents=True,exist_ok=True)
 target.write_bytes(p.read_bytes())
PY
python3 VPN013/prepare_hourly_project.py
python3 VPN013/prepare_unified_project.py
python3 VPN013/add_uitest_target.py
python3 ../../scripts/prepare_proxy_tun.py Sources/WireGuardKitGo ../proxy-fd
export GOFLAGS="-mod=readonly -modfile=$PWD/../proxy-fd/proxy-tun.mod"
mkdir -p ../../build/review
cp ../proxy-fd/proxy-tun-provenance.json ../../build/review/proxy-tun-provenance.json
swiftc VPN013/AutoFailoverPolicy.swift VPN013/tests/main.swift -o ../../build/test-auto-policy
../../build/test-auto-policy > ../../build/review/policy-tests.txt
cat ../../build/review/policy-tests.txt
swiftc -D R013_AUTO_LIFECYCLE_TESTING VPN013/AutoFailoverPolicy.swift VPN013/AutoTunnelController.swift ../../tests/AutoControllerLifecycleTests.swift -o ../../build/test-auto-controller-lifecycle
../../build/test-auto-controller-lifecycle > ../../build/review/auto-controller-lifecycle-tests.txt
cat ../../build/review/auto-controller-lifecycle-tests.txt
swiftc VPN013/PrivateTunnelStore.swift VPN013/tests/PrivateStorageTests.swift -o ../../build/test-private-storage
../../build/test-private-storage > ../../build/review/private-storage-tests.txt
cat ../../build/review/private-storage-tests.txt
swiftc VPN013/EndpointPing.swift VPN013/tests/EndpointPingTests.swift -o ../../build/test-endpoint-ping
../../build/test-endpoint-ping > ../../build/review/endpoint-ping-tests.txt
cat ../../build/review/endpoint-ping-tests.txt
swiftc VPN013/PrivateTunnelStore.swift VPN013/ClientUpdateProtocol.swift VPN013/ClientSubscriptions.swift VPN013/tests/ClientUpdateTests.swift -o ../../build/test-client-updates
../../build/test-client-updates > ../../build/review/client-update-tests.txt
cat ../../build/review/client-update-tests.txt
swiftc VPN013/ConnectionSummary.swift VPN013/tests/ConnectionSummaryTests.swift -o ../../build/test-connection-summary
../../build/test-connection-summary > ../../build/review/connection-summary-tests.txt
cat ../../build/review/connection-summary-tests.txt
swiftc VPN013/LocalStatistics.swift VPN013/tests/LocalStatisticsTests.swift -o ../../build/test-local-statistics
../../build/test-local-statistics > ../../build/review/local-statistics-tests.txt
cat ../../build/review/local-statistics-tests.txt
xcodebuild -project WireGuard.xcodeproj -target WireGuardiOS -configuration Release -sdk iphoneos -arch arm64 \
 CONFIGURATION_BUILD_DIR="$PWD/../device" CODE_SIGNING_ALLOWED=NO DEVELOPMENT_TEAM= \
 > ../device-build.log 2>&1 || { grep -n 'error:' ../device-build.log | head -80; tail -20 ../device-build.log; exit 1; }
cd ../..
test -d build/device/AmneziaWG.app/PlugIns/WireGuardNetworkExtension.appex
mkdir -p build/Payload
ditto build/device/AmneziaWG.app build/Payload/AmneziaWG.app
cp build/awg/Sources/WireGuardApp/UI/iOS/WireGuard.entitlements build/app-signing-entitlements.plist
cp build/awg/Sources/WireGuardNetworkExtension/WireGuardNetworkExtension_iOS.entitlements build/extension-signing-entitlements.plist
python3 - <<'PY'
from pathlib import Path
import subprocess
parts=['VPN013 is a modified AmneziaWG build.\n\n'+Path('build/awg/COPYING').read_text()]
root=Path('build/awg/Sources/WireGuardKitGo')
directories=set(subprocess.check_output(['go','list','-deps','-f','{{with .Module}}{{.Dir}}{{end}}'],cwd=root,text=True).splitlines())
directories.add(subprocess.check_output(['go','env','GOROOT'],text=True).strip())
for path in sorted(directories):
 if not path:continue
 for name in ('LICENSE','COPYING','LICENSE.txt','LICENSE.md'):
  p=Path(path)/name
  if p.is_file():parts.append('\n\n'+Path(path).name+' / '+name+'\n\n'+p.read_text(errors='replace'))
Path('build/Payload/AmneziaWG.app/LegalNotices.txt').write_text('\n'.join(parts))
Path('build/review/LegalNotices.txt').write_text('\n'.join(parts))
PY
python3 - <<'PY'
from pathlib import Path
for name in ('app-signing-entitlements.plist','extension-signing-entitlements.plist'):
 p=Path('build')/name;p.write_text(p.read_text().replace('$(APP_ID_IOS)','com.vpn013.awg'))
PY
# Ad-hoc declarations allow a re-signing tool to discover required rights. This is
# not an Apple distribution signature; the owner must replace it using valid profiles.
codesign --force --sign - --entitlements build/extension-signing-entitlements.plist build/Payload/AmneziaWG.app/PlugIns/WireGuardNetworkExtension.appex
codesign --force --sign - --entitlements build/app-signing-entitlements.plist build/Payload/AmneziaWG.app
codesign --verify --deep --strict build/Payload/AmneziaWG.app
python3 - <<'PY'
import plistlib,json
from pathlib import Path
app=Path('build/Payload/AmneziaWG.app');info=plistlib.loads((app/'Info.plist').read_bytes())
ext=app/'PlugIns/WireGuardNetworkExtension.appex';e=plistlib.loads((ext/'Info.plist').read_bytes())
assert info['CFBundleIdentifier']=='com.vpn013.awg'
assert e['CFBundleIdentifier']=='com.vpn013.awg.network-extension'
for root,meta in [(app,info),(ext,e)]:
 binary=(root/meta['CFBundleExecutable']).read_bytes();assert binary[:4]==bytes.fromhex('cffaedfe')
 assert b'VPN013SimulatorAutoJSON' not in binary and b'demo.wireguard.com' not in binary
Path('build/review/bundle-verification.json').write_text(json.dumps({'appID':info['CFBundleIdentifier'],'extensionID':e['CFBundleIdentifier'],'appleDistributionSigned':False,'adHocIntegrityChecked':True,'requiresOwnerResigning':True,'customerKeysIncluded':False,'physicalDeviceTested':False,'version':info['CFBundleShortVersionString']},indent=2))
PY
(cd build && zip -qr VPN013Admin-unsigned.ipa Payload)
cp build/VPN013Admin-unsigned.ipa build/VPN013AWG-unsigned.ipa
