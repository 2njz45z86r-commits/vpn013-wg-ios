#!/bin/bash
# Build the previous PUBLIC client source using only an ephemeral CI debug key.
# This is not a signed production release or a distribution artifact.
set -euo pipefail
test "$GITHUB_ACTIONS" = true
test "$RUNNER_ENVIRONMENT" = github-hosted
test "$GITHUB_REPOSITORY" = '2njz45z86r-commits/vpn013-wg-ios'
old=b279094c19d45490265a7a8d88fc94838e57b038
git fetch --no-tags https://github.com/2njz45z86r-commits/vpn013-wg-ios.git "$old"
test "$(git rev-parse FETCH_HEAD)" = "$old"
git -C android worktree add --detach ../android-previous ff15093bf3856fea0947923474870b86efb682f0
git -C android-previous submodule update --init --recursive
mkdir -p "$RUNNER_TEMP/previous-android-overlay"
git archive "$old" android-overlay | tar -x -C "$RUNNER_TEMP/previous-android-overlay"
cp -a "$RUNNER_TEMP/previous-android-overlay/android-overlay/." android-previous/
grep -qx 'amneziawgVersionCode=13' android-previous/gradle.properties
grep -qx 'amneziawgVersionName=1.5.2' android-previous/gradle.properties
(cd android-previous && chmod +x gradlew && ./gradlew --no-daemon --console=plain :ui:assembleDebug)
cp android-previous/ui/build/outputs/apk/debug/ui-debug.apk "$RUNNER_TEMP/VPN013WG-previous-debug.apk"
# Do not export debug signing material or either APK as a public release.
