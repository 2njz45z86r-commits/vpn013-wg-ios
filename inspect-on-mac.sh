#!/bin/sh
set -eu
export HOMEBREW_NO_AUTO_UPDATE=1
if [ -d "$PWD/build/toolchain/go/bin" ]; then export PATH="$PWD/build/toolchain/go/bin:$PATH"; fi
device=$(xcrun simctl list devices available -j | python3 -c 'import json,sys;v=json.load(sys.stdin);print(next(x["udid"] for rows in v["devices"].values() for x in rows if x["name"]=="iPhone 16 Pro"))')
xcrun simctl boot "$device" || true
xcrun simctl bootstatus "$device" -b
cd build/awg
set +e
xcodebuild -project WireGuard.xcodeproj -scheme VPN013Auto -configuration Debug -sdk iphonesimulator \
 -destination "platform=iOS Simulator,id=$device" -parallel-testing-enabled NO \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testTwoPersonalServers \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testThirtyPersonalServers \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testEmptyListDisablesAutomaticCreation \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testCenteredAddShowsPurchaseAndThreeDayTrial \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testNativeThreeDayTrialImportsFullZIPWithoutBrowser \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testNativeThreeDayRepeatedButtonKeepsSameProfiles \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testNativeThreeDayUnsafeZIPPreservesExistingProfiles \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testNativeThreeDayExpiredOffersPersonalRenewalWithoutImport \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testSharedZipImportsThirteenWithoutDuplicateError \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testRedesignedListKeepsNativeControls \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testAddMenuKeepsAllActions \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testDeveloperFooterAvailable \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testDarkEmptyListKeepsDeveloperFooter \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testLargeTextKeepsSwitchAndDeveloperFooter \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testUnavailableLogStopsSpinnerAndShowsExplanation \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testPingButtonMeasuresActualLoopbackWithoutStartingVPN \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testPingCancellationIsAvailable \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testUpdatesScreenAndOrderSynchronization \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testUpdateDownloadUsesDirectIPAInsteadOfTelegram \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testSettingsBrandWordmarkAndVersionUseShortName \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testAutoPinnedFirstWithCurrentMemberAndPing \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testManualCurrentServerPingAndInfo \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testManualHandshakeSummaryUsesReturnedRuntimeData \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testManualCurrentPingWithMissingRuntime \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testManualCurrentPingWithRuntimeTimeout \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testAutoMissingRuntimeDoesNotPingSeed \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testCurrentPowerButtonRemembersManualProfile \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testCurrentPowerButtonControlsAutoWithoutRuntime \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testCurrentPowerButtonEmptyAndLargeType \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testCurrentPowerButtonDisabledDuringTransition \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testNativeRussianIPRouteObjectsPreserveVPNAndPeers \
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
# A missing selector must never silently reduce the required native suite.
if [ "$result" -eq 0 ]; then
 python3 - <<'PY'
import json
from pathlib import Path
s=json.loads(Path('build/review/test-summary.json').read_text())
assert s['result']=='Passed' and s['passedTests']==31 and s['failedTests']==0 and s['skippedTests']==0,s
PY
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
 xcrun simctl ui "$device" content_size accessibility-extra-extra-extra-large
 xcrun simctl launch --terminate-running-process "$device" com.vpn013.awg -AppleLanguages '(ru)' -AppleLocale ru_RU --vpn013-test-count 2 --vpn013-test-current-card --vpn013-test-start-current --vpn013-test-ping-loopback
 sleep 3
 xcrun simctl io "$device" screenshot build/review/phone-large-type.png
 xcrun simctl ui "$device" content_size large
 # Observe the ordinary launch path too, without any synthetic app arguments.
 # A simulator launch does not validate a physical Network Extension or VPN traffic.
 xcrun simctl launch --terminate-running-process "$device" com.vpn013.awg -AppleLanguages '(ru)' -AppleLocale ru_RU
 sleep 3
 xcrun simctl io "$device" screenshot build/review/phone-normal-launch-no-fixture.png
 tablet=$(xcrun simctl list devices available -j | python3 -c 'import json,sys;v=json.load(sys.stdin);print(next(x["udid"] for rows in v["devices"].values() for x in rows if x["name"].startswith("iPad")))')
 xcrun simctl boot "$tablet" || true
 xcrun simctl bootstatus "$tablet" -b
 xcrun simctl ui "$tablet" appearance dark
 xcrun simctl install "$tablet" build/SimulatorDerivedData/Build/Products/Debug-iphonesimulator/AmneziaWG.app
 xcrun simctl launch "$tablet" com.vpn013.awg -AppleLanguages '(ru)' -AppleLocale ru_RU --vpn013-test-count 2 --vpn013-test-current-card --vpn013-test-start-current --vpn013-test-ping-loopback
 sleep 3
 xcrun simctl io "$tablet" screenshot build/review/tablet.png
fi
test "$result" -eq 0
