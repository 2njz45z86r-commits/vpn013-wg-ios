#!/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
test "$GITHUB_ACTIONS" = true
test "$RUNNER_ENVIRONMENT" = github-hosted
test "$GITHUB_REPOSITORY" = '2njz45z86r-commits/vpn013-wg-ios'
mkdir -p output/review
SDK="$ANDROID_HOME/cmdline-tools/latest/bin"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
"$SDK/sdkmanager" 'platform-tools' 'emulator' 'system-images;android-35;google_apis;x86_64'
echo no | "$SDK/avdmanager" create avd --force -n R013CI -k 'system-images;android-35;google_apis;x86_64' --device pixel_7
sudo chmod 666 /dev/kvm
"$ANDROID_HOME/emulator/emulator" -avd R013CI -no-window -no-snapshot -no-audio -gpu swiftshader_indirect -no-boot-anim -memory 3072 -cores 2 > "$RUNNER_TEMP/r013-emulator.log" 2>&1 &
emulator_pid=$!
trap 'kill "$emulator_pid" 2>/dev/null || true' EXIT
adb wait-for-device
for i in $(seq 1 90); do
  if [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; then break; fi
  sleep 2
done
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard
for setting in window_animation_scale transition_animation_scale animator_duration_scale; do adb shell settings put global "$setting" 0; done
adb shell cmd uimode night yes
adb install -r -t ui/build/outputs/apk/debug/ui-debug.apk
adb install -r -t ui/build/outputs/apk/androidTest/debug/ui-debug-androidTest.apk
adb shell appops set com.vpn013.awg.debug ACTIVATE_VPN allow
(cd tunnel/tools/libwg-go && go run ../../../r013-ci/peer.go) > "$RUNNER_TEMP/r013-peer.log" 2>&1 &
peer_pid=$!
trap 'kill "$peer_pid" "$emulator_pid" 2>/dev/null || true' EXIT
for i in $(seq 1 90); do test -s "$RUNNER_TEMP/r013-synthetic.conf" && break; sleep 2; done
test -s "$RUNNER_TEMP/r013-synthetic.conf"
fixture=$(base64 -w0 "$RUNNER_TEMP/r013-synthetic.conf")
adb shell am instrument -w -r -e syntheticConfig "$fixture" com.vpn013.awg.debug.test/androidx.test.runner.AndroidJUnitRunner > output/review/instrumentation.txt
grep -E '^OK \([0-9]+ tests?\)' output/review/instrumentation.txt
! grep -E 'FAILURES|INSTRUMENTATION_FAILED|Process crashed' output/review/instrumentation.txt
unset fixture
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
