#!/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
test "$GITHUB_ACTIONS" = true
test "$RUNNER_ENVIRONMENT" = github-hosted
test "$GITHUB_REPOSITORY" = '2njz45z86r-commits/vpn013-wg-ios'
mkdir -p output/review
df -h . > output/review/disk-before-emulator.txt
SDK="$ANDROID_HOME/cmdline-tools/latest/bin"
export ANDROID_USER_HOME="$RUNNER_TEMP/r013-android-user"
export ANDROID_EMULATOR_HOME="$ANDROID_USER_HOME"
export ANDROID_AVD_HOME="$ANDROID_USER_HOME/avd"
mkdir -p "$ANDROID_AVD_HOME"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
"$SDK/sdkmanager" 'platform-tools' 'emulator' 'system-images;android-35;google_apis;x86_64'
echo no | "$SDK/avdmanager" create avd --force -n R013CI -p "$ANDROID_AVD_HOME/R013CI.avd" -k 'system-images;android-35;google_apis;x86_64' --device pixel_7
test -s "$ANDROID_AVD_HOME/R013CI.ini"
"$ANDROID_HOME/emulator/emulator" -list-avds > output/review/avd-list.txt
grep -x R013CI output/review/avd-list.txt
sudo chmod 666 /dev/kvm
"$ANDROID_HOME/emulator/emulator" -accel-check > output/review/emulator-acceleration.txt 2>&1
"$ANDROID_HOME/emulator/emulator" -avd R013CI -no-window -no-snapshot -no-audio -gpu swiftshader_indirect -no-boot-anim -memory 3072 -cores 2 > "$RUNNER_TEMP/r013-emulator.log" 2>&1 &
emulator_pid=$!
peer_pid=""
proxy_pid=""
route_echo_pid=""
ru_alias_added=""
control_alias_added=""
finish() {
  timeout 15s adb pull /sdcard/Android/data/com.vpn013.awg.debug/files/review output/review/screenshots-partial >/dev/null 2>&1 || true
  timeout 15s adb logcat -d -t 500 -s AndroidRuntime:E > output/review/runtime-errors.txt 2>/dev/null || true
  # Only synthetic hosted CI runs here. Preserve bounded system-service crash
  # diagnostics, never app configuration dumps, when native networking fails.
  timeout 15s adb logcat -d -t 1200 -s Watchdog:E ActivityManager:E ConnectivityService:E AndroidRuntime:E > output/review/system-service-errors.txt 2>/dev/null || true
  # Native Go/JNI failures are not AndroidRuntime Java exceptions. Keep bounded
  # raw diagnostics encrypted for private review; never print crash buffers or
  # fixture material into a public summary.
  timeout 15s adb logcat -b crash -d -t 800 > "$RUNNER_TEMP/r013-native-crash.log" 2>/dev/null || true
  timeout 15s adb logcat -d -t 1600 -s libc:F DEBUG:F System.err:E Go:E GoLog:E > "$RUNNER_TEMP/r013-native-runtime.log" 2>/dev/null || true
  cp "$RUNNER_TEMP/r013-emulator.log" output/review/emulator.log 2>/dev/null || true
  cp "$RUNNER_TEMP/r013-peer.log" output/review/synthetic-peer-build.log 2>/dev/null || true
  if [ -n "$proxy_pid" ]; then kill "$proxy_pid" 2>/dev/null || true; fi
  if [ -n "$peer_pid" ]; then kill "$peer_pid" 2>/dev/null || true; fi
  if [ -n "$route_echo_pid" ]; then kill "$route_echo_pid" 2>/dev/null || true; fi
  if [ "$ru_alias_added" = yes ]; then sudo ip address del 2.56.24.1/32 dev lo 2>/dev/null || true; fi
  if [ "$control_alias_added" = yes ]; then sudo ip address del 198.18.0.1/32 dev lo 2>/dev/null || true; fi
  kill "$emulator_pid" 2>/dev/null || true
  python3 r013-ci/protect-native-diagnostics.py
}
trap finish EXIT
timeout 180s adb wait-for-device
for i in $(seq 1 90); do
  if [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; then break; fi
  sleep 2
done
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard
for setting in window_animation_scale transition_animation_scale animator_duration_scale; do adb shell settings put global "$setting" 0; done
adb shell cmd uimode night yes
if [ "${R013_FOCUS_RUNTIME:-false}" = true ]; then
  python3 r013-ci/prepare-focused-apks.py
  adb install -r -t "$RUNNER_TEMP/r013-focused-app.apk"
  adb install -r -t "$RUNNER_TEMP/r013-focused-test.apk"
  adb shell appops set com.vpn013.awg.debug ACTIVATE_VPN allow
  adb shell pm grant com.vpn013.awg.debug android.permission.POST_NOTIFICATIONS
else
# First install the historical app, seed its real encrypted vault, then replace
# it without uninstalling. Both APKs use the same ephemeral runner debug key.
python3 - <<'PY_SIZE'
from pathlib import Path
import json,os
paths=[Path('ui/build/outputs/apk/debug/ui-debug.apk'),Path(os.environ['RUNNER_TEMP'])/'VPN013WG-future-debug.apk']
proof={p.name:p.stat().st_size for p in paths}
Path('output/review/apk-sizes.json').write_text(json.dumps(proof))
assert all(0<v<=268435456 for v in proof.values())
PY_SIZE
test -s "$RUNNER_TEMP/VPN013WG-previous-debug.apk"
adb install -r -t "$RUNNER_TEMP/VPN013WG-previous-debug.apk"
adb install -r -t ui/build/outputs/apk/androidTest/debug/ui-debug-androidTest.apk
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013UpgradePreservationTest -e upgradePhase seed com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/upgrade-before.txt
grep -E '^OK \(1 test\)[[:space:]]*$' output/review/upgrade-before.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/upgrade-before.txt
adb install -r -t ui/build/outputs/apk/debug/ui-debug.apk
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013UpgradePreservationTest -e upgradePhase verify com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/upgrade-after.txt
grep -E '^OK \(1 test\)[[:space:]]*$' output/review/upgrade-after.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/upgrade-after.txt
adb push "$RUNNER_TEMP/VPN013WG-future-debug.apk" /sdcard/Android/data/com.vpn013.awg.debug/files/update-fixture.apk
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013UpdateInstallTest#changedAPKIsRejectedBeforeInstaller,org.amnezia.awg.r013.R013UpdateInstallTest#noConsentDoesNotOpenInstaller com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/update-install-preflight.txt
grep -E '^OK \(2 tests\)[[:space:]]*$' output/review/update-install-preflight.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/update-install-preflight.txt
# Establish denial outside the app UID; the production app still requests the
# normal OS permission and the test never confirms package installation.
adb shell appops set com.vpn013.awg.debug REQUEST_INSTALL_PACKAGES deny
adb shell am instrument -w -r -e initialInstallPermission denied -e class org.amnezia.awg.r013.R013UpdateInstallTest#permissionReturnResumesSameVerifiedUpdateAndCancelDoesNotLoop com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/update-install-flow.txt
grep -E '^OK \(1 test\)[[:space:]]*$' output/review/update-install-flow.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/update-install-flow.txt
adb shell appops set com.vpn013.awg.debug ACTIVATE_VPN allow
adb shell pm grant com.vpn013.awg.debug android.permission.POST_NOTIFICATIONS
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013NativeTrialTest com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/native-trial-flow.txt
grep -E '^OK \(5 tests\)[[:space:]]*$' output/review/native-trial-flow.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/native-trial-flow.txt
fi
(cd tunnel/tools/libwg-go && go run ../../../r013-ci/peer.go) > "$RUNNER_TEMP/r013-peer.log" 2>&1 &
peer_pid=$!
# The EXIT trap preserves native failure evidence before emulator teardown.
for i in $(seq 1 90); do test -s "$RUNNER_TEMP/r013-synthetic.conf" && break; sleep 2; done
test -s "$RUNNER_TEMP/r013-synthetic.conf"
test -s "$RUNNER_TEMP/r013-synthetic-candidate.conf"
start_proxy_fixture() {
(cd tunnel/tools/libwg-go && go build -o "$RUNNER_TEMP/r013-proxy-peer" ../../../r013-ci/proxy-peer.go)
timeout 30s "$RUNNER_TEMP/r013-proxy-peer" --self-test > "$RUNNER_TEMP/r013-proxy-self-test.log" 2>&1
grep -Fx 'Disposable REALITY/VLESS tcp fixture nonce exchange passed' "$RUNNER_TEMP/r013-proxy-self-test.log"
grep -Fx 'Disposable REALITY/VLESS xhttp fixture nonce exchange passed' "$RUNNER_TEMP/r013-proxy-self-test.log"
printf '%s\n' '{"hostFixtureTCPNonce":true,"hostFixtureXHTTPNonce":true,"androidTrafficVerified":false}' > output/review/proxy-host-self-test.json
"$RUNNER_TEMP/r013-proxy-peer" > "$RUNNER_TEMP/r013-proxy-peer.log" 2>&1 &
proxy_pid=$!
for i in $(seq 1 30); do test -s "$RUNNER_TEMP/r013-proxy-fixture.json" && break; sleep 1; done
test -s "$RUNNER_TEMP/r013-proxy-fixture.json"
proxy_fixture=$(base64 -w0 "$RUNNER_TEMP/r013-proxy-fixture.json")
}
fixture=$(base64 -w0 "$RUNNER_TEMP/r013-synthetic.conf")
candidate_fixture=$(base64 -w0 "$RUNNER_TEMP/r013-synthetic-candidate.conf")
if [ "${R013_FOCUS_RUNTIME:-false}" = true ]; then
  # Every timeout/crash remains a failure. Other independent diagnostic classes
  # can still run in a fresh debug process and retain their own actual evidence.
  focused_instrument() {
    local destination=$1
    shift
    if ! timeout 360s adb shell am instrument -w -r "$@" com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > "$destination"; then
      printf '%s\n' 'INSTRUMENTATION_FAILED: bounded diagnostic did not complete' >> "$destination"
    fi
    if grep -E 'Process crashed|INSTRUMENTATION_FAILED' "$destination" >/dev/null; then
      timeout 10s adb shell am force-stop com.vpn013.awg.debug >/dev/null 2>&1 || true
    fi
  }
  # Diagnostic scope is one real coordinator case, shared semantic/ZIP case,
  # both routing-surface cases and both proxy runtime cases.
  # runtime cases. It is never a complete acceptance result or release input.
  focused_instrument output/review/focused-coordinator.txt -e class org.amnezia.awg.r013.R013InstrumentedTest#jRealCoordinatorChoosesFasterPeerWithActualPolicyAndUnchangedProfiles -e syntheticConfig "$fixture" -e syntheticCandidate "$candidate_fixture"
  coordinator_ok=false
  if grep -E '^OK \(1 test\)[[:space:]]*$' output/review/focused-coordinator.txt && ! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/focused-coordinator.txt; then coordinator_ok=true; fi
  focused_instrument output/review/focused-semantic.txt -e class org.amnezia.awg.r013.R013InstrumentedTest#multiServerSubscriptionImportsPrimaryNodesOnly
  semantic_ok=false
  if grep -E '^OK \(1 test\)[[:space:]]*$' output/review/focused-semantic.txt && ! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/focused-semantic.txt; then semantic_ok=true; fi
  focused_instrument output/review/routing-surface.txt -e class org.amnezia.awg.r013.R013RoutingSurfaceTest
  surface_ok=false
  if grep -E '^OK \(2 tests\)[[:space:]]*$' output/review/routing-surface.txt && ! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/routing-surface.txt; then surface_ok=true; fi
  sudo ip address add 198.18.0.1/32 dev lo
  control_alias_added=yes
  start_proxy_fixture
  focused_instrument output/review/proxy-runtime.txt -e class org.amnezia.awg.r013.R013ProxyRuntimeTest -e proxyFixture "$proxy_fixture"
  proxy_ok=false
  if grep -E '^OK \(2 tests\)[[:space:]]*$' output/review/proxy-runtime.txt && ! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/proxy-runtime.txt; then proxy_ok=true; fi
  unset proxy_fixture fixture candidate_fixture
  printf '%s\n' '{"diagnosticOnly":true,"expectedCoordinatorCases":1,"expectedSemanticCases":1,"expectedSurfaceCases":2,"expectedProxyCases":2,"fullNativeAcceptance":false,"published":false}' > output/review/focused-scope.json
  test "$coordinator_ok" = true && test "$semantic_ok" = true && test "$surface_ok" = true && test "$proxy_ok" = true
  exit $?
fi
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013InstrumentedTest -e syntheticConfig "$fixture" -e syntheticCandidate "$candidate_fixture" com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/instrumentation.txt
grep -E '^OK \(16 tests\)[[:space:]]*$' output/review/instrumentation.txt
grep -F 'test=bSubscriptionRefreshRestoresDeletedAndReconcilesTenTwentyFifteen' output/review/instrumentation.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/instrumentation.txt
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013RoutingSurfaceTest com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/routing-surface.txt
grep -E '^OK \(2 tests\)[[:space:]]*$' output/review/routing-surface.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/routing-surface.txt
sudo ip address add 2.56.24.1/32 dev lo
ru_alias_added=yes
sudo ip address add 198.18.0.1/32 dev lo
control_alias_added=yes
python3 r013-ci/russian-route-echo.py > output/review/russian-route-echo.txt 2>&1 &
route_echo_pid=$!
adb shell rm -f /sdcard/Android/data/com.vpn013.awg.debug/files/review/russian-route-request.json /sdcard/Android/data/com.vpn013.awg.debug/files/review/russian-route-proof.json
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013RussianRoutesTest -e syntheticConfig "$fixture" com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/russian-routing.txt &
routing_test_pid=$!
python3 r013-ci/capture-russian-routes.py
wait "$routing_test_pid"
grep -E '^OK \(1 test\)[[:space:]]*$' output/review/russian-routing.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/russian-routing.txt
# Verify the real Android TUN/native Xray path with an isolated ephemeral REALITY
# server. Its only private destination is the nonce HTTP echo; public TCP443 and
# Cloudflare DNS are used solely by the application's unchanged HTTPS204 health.
start_proxy_fixture
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013ProxyRuntimeTest -e proxyFixture "$proxy_fixture" com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/proxy-runtime.txt
grep -E '^OK \(2 tests\)[[:space:]]*$' output/review/proxy-runtime.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/proxy-runtime.txt
unset proxy_fixture
unset fixture candidate_fixture
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013NetworkRecoveryTest com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/network-recovery.txt
grep -E '^OK \(3 tests\)[[:space:]]*$' output/review/network-recovery.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/network-recovery.txt
adb pull /sdcard/Android/data/com.vpn013.awg.debug/files/review output/review/screenshots
adb shell settings put system font_scale 1.3
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013InstrumentedTest#eNativeScreen -e reviewLabel phone-large-type com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/font-scale.txt
grep -E '^OK \(1 test\)' output/review/font-scale.txt
adb shell settings put system font_scale 1.0
adb shell wm size 1600x1200
adb shell wm density 160
adb shell am instrument -w -r -e class org.amnezia.awg.r013.R013InstrumentedTest#eNativeScreen -e reviewLabel tablet com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/tablet.txt
grep -E '^OK \(1 test\)' output/review/tablet.txt
adb pull /sdcard/Android/data/com.vpn013.awg.debug/files/review output/review/screenshots-final
adb shell wm size reset
adb shell wm density reset
