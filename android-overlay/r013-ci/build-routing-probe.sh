#!/bin/bash
# SPDX-License-Identifier: MIT
# A standalone, debuggable, disposable CI-only APK; it is never part of the app.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ENVIRONMENT:-}" = github-hosted
work=$(mktemp -d "$RUNNER_TEMP/vpn013-routing-probe.XXXXXX")
mkdir -p "$work/classes" "$work/dex"
tools="$ANDROID_HOME/build-tools/36.0.0"
platform="$ANDROID_HOME/platforms/android-36/android.jar"
test -s "$platform"
"$tools/aapt2" link --manifest r013-ci/routing-probe/AndroidManifest.xml -I "$platform" -o "$work/unsigned.apk"
javac -encoding UTF-8 -source 8 -target 8 -bootclasspath "$platform" -d "$work/classes" r013-ci/routing-probe/RoutingProbeReceiver.java
test -s "$work/classes/com/vpn013/routingprobe/RoutingProbeReceiver.class"
test -s "$work/classes/com/vpn013/routingprobe/RoutingProbeReceiver\$1.class"
shopt -s nullglob
classes=("$work/classes/com/vpn013/routingprobe/"*.class)
test "${#classes[@]}" -ge 2 && test "${#classes[@]}" -le 16
"$tools/d8" --lib "$platform" --min-api 26 --output "$work/dex" "${classes[@]}"
(cd "$work/dex" && zip -q "$work/unsigned.apk" classes.dex)
"$tools/zipalign" -f 4 "$work/unsigned.apk" "$work/aligned.apk"
keytool -genkeypair -noprompt -keystore "$work/ephemeral.jks" -storepass android -keypass android -alias probe -keyalg RSA -keysize 2048 -validity 1 -dname 'CN=Disposable Android CI Fixture' > /dev/null 2>&1
"$tools/apksigner" sign --ks "$work/ephemeral.jks" --ks-pass pass:android --key-pass pass:android --out "$work/probe.apk" "$work/aligned.apk"
"$tools/apksigner" verify "$work/probe.apk"
adb install -r -t "$work/probe.apk"
