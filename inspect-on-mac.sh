#!/bin/sh
set -eu
export HOMEBREW_NO_AUTO_UPDATE=1
export GOFLAGS="-mod=readonly -modfile=$PWD/build/proxy-fd/proxy-tun.mod"
if [ -d "$PWD/build/toolchain/go/bin" ]; then export PATH="$PWD/build/toolchain/go/bin:$PATH"; fi
device=$(xcrun simctl list devices available -j | python3 -c 'import json,sys;v=json.load(sys.stdin);print(next(x["udid"] for rows in v["devices"].values() for x in rows if x["name"]=="iPhone 16 Pro"))')
xcrun simctl boot "$device" || true
xcrun simctl bootstatus "$device" -b
cd build/awg
# Prove the compiled UI cases and native persistence fixture are the reviewed
# overlay bytes before selecting either shard.
cmp -s VPN013/UITests.swift ../../overlay/VPN013/UITests.swift
cmp -s Sources/WireGuardApp/Tunnel/TunnelsManager.swift ../../overlay/Sources/WireGuardApp/Tunnel/TunnelsManager.swift
shard=${VPN013_UI_SHARD:-all54}
case "$shard" in coreA|coreB|coreC|core49|added5|all54) ;; *) echo "Invalid native UI shard" >&2; exit 2 ;; esac
# The helper checks the exact 54 source methods and assigns every selector once.
selector_args=$(python3 ../../scripts/native_ui_shards.py selectors "$shard")
set -- $selector_args
set +e
xcodebuild -project WireGuard.xcodeproj -scheme VPN013Auto -configuration Debug -sdk iphonesimulator \
 -destination "platform=iOS Simulator,id=$device" -parallel-testing-enabled NO \
 "$@" \
 -derivedDataPath ../SimulatorDerivedData -resultBundlePath ../AutoTunnel.xcresult CODE_SIGNING_ALLOWED=NO DEVELOPMENT_TEAM= \
 test > ../simulator-test.log 2>&1
result=$?
set -e
cd ../..
python3 - <<'PY'
from pathlib import Path
import re
lines=Path('build/simulator-test.log').read_text(errors='replace').splitlines()
for line in lines:
 if re.search(r'error:|XCTAssert|Test Case .* (passed|failed)|Executed |TEST (FAILED|SUCCEEDED)',line):print(line)
PY
if [ -d build/AutoTunnel.xcresult ]; then
 xcrun xcresulttool export attachments --path build/AutoTunnel.xcresult --output-path build/review/flow
 xcrun xcresulttool get test-results summary --path build/AutoTunnel.xcresult > build/review/test-summary.json || true
fi
# Keep failure screenshots with a PNG extension; never publish UI hierarchy text.
python3 - <<'PY'
from pathlib import Path
import shutil
for path in Path('build/review/flow').glob('*'):
 if path.is_file() and not path.suffix and path.read_bytes()[:8] == b'\x89PNG\r\n\x1a\n':
  shutil.copy2(path,path.with_suffix('.png'))
PY
if [ "$result" -eq 0 ]; then
 python3 scripts/native_ui_shards.py verify "$shard"
fi
if [ "$result" -eq 0 ] && [ "$shard" = all54 ] && [ "${VPN013_IPHONE_ONLY:-0}" != 1 ]; then
 python3 capture-ios-simulators.py
elif [ "$result" -eq 0 ]; then
 export VPN013_UI_SHARD="$shard"
 python3 - <<'PY'
import json
from pathlib import Path
flow=Path('build/review/flow')
images=[p for p in flow.glob('*.png') if p.read_bytes()[:8]==b'\x89PNG\r\n\x1a\n']
assert images, 'Real XCUITest attachments are required'
Path('build/review/iphone-only-scope.json').write_text(json.dumps({'iPhoneNativeSuite':{'coreA':17,'coreB':16,'coreC':16,'core49':49,'added5':5,'all54':54}[__import__('os').environ['VPN013_UI_SHARD']],'renderedEvidence':'actual XCUITest attachments','attachmentImages':len(images),'physicalIPhoneTested':False,'iPadTested':False,'standaloneCapturesAccepted':False}))
PY
fi
test "$result" -eq 0
