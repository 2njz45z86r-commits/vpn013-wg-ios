#!/bin/sh
set -eu
export HOMEBREW_NO_AUTO_UPDATE=1
if [ -d "$PWD/build/toolchain/go/bin" ]; then export PATH="$PWD/build/toolchain/go/bin:$PATH"; fi
device=$(xcrun simctl list devices available -j | python3 -c 'import json,sys;v=json.load(sys.stdin);print(next(x["udid"] for rows in v["devices"].values() for x in rows if x["name"]=="iPhone 16 Pro"))')
xcrun simctl boot "$device" || true
xcrun simctl bootstatus "$device" -b
cd build/awg
xcodebuild -project WireGuard.xcodeproj -scheme VPN013Auto -configuration Debug -sdk iphonesimulator \
 -destination "platform=iOS Simulator,id=$device" -parallel-testing-enabled NO \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testTwoPersonalServers \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testThirtyPersonalServers \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testEmptyListDisablesAutomaticCreation \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testCenteredAddShowsPurchaseAndFreeHour \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testSharedZipImportsThirteenWithoutDuplicateError \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testRedesignedListKeepsNativeControls \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testAddMenuKeepsAllActions \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testDeveloperFooterAvailable \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testDarkEmptyListKeepsDeveloperFooter \
 -only-testing:AutoTunnelUITests/AutoTunnelUITests/testUnavailableLogStopsSpinnerAndShowsExplanation \
 -resultBundlePath ../AutoTunnel.xcresult CODE_SIGNING_ALLOWED=NO DEVELOPMENT_TEAM= \
 test > ../simulator-test.log 2>&1 || { tail -100 ../simulator-test.log; exit 1; }
cd ../..
xcrun xcresulttool export attachments --path build/AutoTunnel.xcresult --output-path build/review/flow
