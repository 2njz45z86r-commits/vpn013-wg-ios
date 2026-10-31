#!/bin/sh
# Socket-free Swift models and actual host-only encryption. No VPN, credentials
# or live provider requests. Run before the longer native archive/UI checks.
set -eu
root=$(pwd)
target=$(mktemp -d "${TMPDIR:-/tmp}/vpn013-models.XXXXXXXX")
trap 'rm -rf "$target"' EXIT HUP INT TERM
xcrun swiftc -parse-as-library -swift-version 5 "$root/overlay/VPN013/ProxyProfile.swift" "$root/overlay/VPN013/ProxyRouting.swift" "$root/overlay/VPN013/ServiceRoutingCatalog.swift" "$root/tests/ProxyProfileTests.swift" -o "$target/profiles"
"$target/profiles"
xcrun swiftc -parse-as-library -swift-version 5 "$root/overlay/VPN013/ProxyProfile.swift" "$root/tests/ProxyIssuerCompatibilityTests.swift" -o "$target/issuer"
"$target/issuer"
xcrun swiftc -parse-as-library -swift-version 5 "$root/overlay/VPN013/AutomaticMode.swift" "$root/tests/AutomaticModeTests.swift" -o "$target/automatic"
"$target/automatic"
xcrun swiftc -parse-as-library -swift-version 5 "$root/overlay/VPN013/CrossProtocolSelection.swift" "$root/overlay/VPN013/CrossProtocolCoordinator.swift" "$root/tests/CrossProtocolTests.swift" -o "$target/cross-protocol"
"$target/cross-protocol"
xcrun swiftc -parse-as-library -swift-version 5 "$root/overlay/VPN013/AutomaticMode.swift" "$root/overlay/VPN013/ProxyProfile.swift" "$root/overlay/VPN013/ProxyRouting.swift" "$root/overlay/VPN013/ServiceRoutingCatalog.swift" "$root/overlay/VPN013/CrossProtocolPlan.swift" "$root/tests/CrossProtocolPlanTests.swift" -o "$target/cross-plan"
"$target/cross-plan"
xcrun swiftc -parse-as-library -swift-version 5 -D R013_PROXY_AUTO_TESTING "$root/overlay/VPN013/AutomaticMode.swift" "$root/overlay/VPN013/ProxyProfile.swift" "$root/overlay/VPN013/ProxyRouting.swift" "$root/overlay/VPN013/ServiceRoutingCatalog.swift" "$root/overlay/VPN013/ProxyAutomaticAdapter.swift" "$root/tests/ProxyAutoLifecycleTests.swift" -o "$target/lifecycle"
"$target/lifecycle"
xcrun swiftc -parse-as-library -swift-version 5 "$root/overlay/VPN013/ProxyProfile.swift" "$root/overlay/VPN013/SubscriptionRequest.swift" "$root/overlay/VPN013/ProxySubscriptionDownload.swift" "$root/tests/SubscriptionRequestTests.swift" -o "$target/requests"
"$target/requests"
xcrun swiftc -parse-as-library -swift-version 5 "$root/overlay/VPN013/ProxyProfile.swift" "$root/overlay/VPN013/PrivateTunnelStore.swift" "$root/overlay/VPN013/SubscriptionRequest.swift" "$root/overlay/VPN013/ProxySubscriptionStore.swift" "$root/tests/ProxySubscriptionStoreTests.swift" -o "$target/store"
"$target/store"
xcrun swiftc -swift-version 5 "$root/overlay/VPN013/LocalStatistics.swift" "$root/overlay/VPN013/tests/LocalStatisticsTests.swift" -o "$target/local"
"$target/local"

xcrun swiftc -parse-as-library -swift-version 5 "$root/overlay/VPN013/TrafficDisplay.swift" "$root/tests/TrafficDisplayTests.swift" -o "$target/traffic"
"$target/traffic"
