#!/bin/bash
# Ephemeral, non-distributed debug-signed APK solely for Android installer tests.
set -euo pipefail
test "$GITHUB_ACTIONS" = true
test "$RUNNER_ENVIRONMENT" = github-hosted
test "$GITHUB_REPOSITORY" = '2njz45z86r-commits/vpn013-wg-ios'
cd android
cp ui/build/outputs/apk/debug/ui-debug.apk "$RUNNER_TEMP/current-android-debug.apk"
cp ui/build.gradle.kts "$RUNNER_TEMP/current-android-ui.gradle.kts"
restore() {
  cp "$RUNNER_TEMP/current-android-ui.gradle.kts" ui/build.gradle.kts
  cp "$RUNNER_TEMP/current-android-debug.apk" ui/build/outputs/apk/debug/ui-debug.apk
}
trap restore EXIT
python3 - <<'PY'
from pathlib import Path
p=Path('ui/build.gradle.kts');s=p.read_text()
assert s.count('versionNameSuffix = "-debug"')==1
p.write_text(s.replace('versionNameSuffix = "-debug"','versionNameSuffix = ""'))
PY
./gradlew --no-daemon --console=plain -PamneziawgVersionCode=14 -PamneziawgVersionName=1.5.3 :ui:assembleDebug
cp ui/build/outputs/apk/debug/ui-debug.apk "$RUNNER_TEMP/VPN013WG-future-debug.apk"
