#!/bin/sh
set -eu
export HOMEBREW_NO_AUTO_UPDATE=1
export GOFLAGS="-mod=readonly -modfile=$PWD/build/proxy-fd/proxy-tun.mod"
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
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testSharedOwnerProxyZIPSelectsIncyAndPreviewsProfile \
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
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testUnifiedSectionsImportAndIsolation \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testInvitationReachableFromEveryProxySectionWithoutSharingProfiles \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testSettingsReachableInEveryProxySectionAndPreserveImportText \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testTrafficSummaryUsesAdaptiveUnits \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testPowerTrafficAndPingPanelPresentInEveryProxySection \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testRoutingSelectsMultipleServersAndPreservesUnselected \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testProxyRowConnectsAndOnlyRightStripOpensConfiguration \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testServiceCatalogGroupsExclusiveModesAndRememberedSelection \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testWireGuardServicesUseOwnServersAndKeepUnselectedConfiguration \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testUnifiedInvalidImportKeepsProfiles \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testUnifiedRoutingPersistsTypedPolicy \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testAutomaticModeDefaultSharedAndPersistent \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testFullJSONImportsVisibleRosterWithoutBackupDuplicates \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testProxySubscriptionRosterRestoresDeletedAndPreservesOtherSources \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testProxyMissingRuntimeNeverDisplaysAutomaticSeedAsCurrentServer \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testUnifiedRemembersSelectedSection \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testCrossProtocolRuntimeUsesActualSectionAndGlobalStop \
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
assert s['result']=='Passed' and s['passedTests']==48 and s['failedTests']==0 and s['skippedTests']==0,s
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
if [ "$result" -eq 0 ] && [ "${VPN013_IPHONE_ONLY:-0}" != 1 ]; then
 python3 capture-ios-simulators.py
elif [ "$result" -eq 0 ]; then
 python3 - <<'PY'
import json
from pathlib import Path
flow=Path('build/review/flow')
images=[p for p in flow.glob('*.png') if p.read_bytes()[:8]==b'\x89PNG\r\n\x1a\n']
assert images, 'Real XCUITest attachments are required'
Path('build/review/iphone-only-scope.json').write_text(json.dumps({'iPhoneNativeSuite':48,'renderedEvidence':'actual XCUITest attachments','attachmentImages':len(images),'physicalIPhoneTested':False,'iPadTested':False,'standaloneCapturesAccepted':False}))
PY
fi
test "$result" -eq 0
