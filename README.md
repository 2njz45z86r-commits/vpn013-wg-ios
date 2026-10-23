# VPN013 WG for iPhone

Standalone VPN client project, separate from the owner administration app and Telegram bot.
Version 1.2.1 build 5 is prepared for a native build; it has not yet been validated on an iPhone.

## Source layout

The readable `overlay/` files are the VPN013 modifications to the MIT-licensed
`amnezia-vpn/amneziawg-apple` source at commit
`9d5ee60edefa95b933a738dd7cda671dd18021fc`.
The build script checks out that exact revision and applies the readable `overlay/` files.
No compressed or encrypted source payload is used.

No customer configurations, server keys, Apple certificates or provisioning profiles
are part of this project. Native Simulator fixtures are synthetic and excluded from Release.
See `LICENSE` and the legal notices generated inside the app during the build.

## Manual connection fix

Version 1.2.0 started an app-side 12-second handshake deadline for individual profiles
and stopped the system VPN when the foreground app did not observe a handshake.
This candidate follows the system Packet Tunnel lifecycle without that forced stop.
System connected status means the extension has started; it is not proof of peer traffic.
Handshake and byte counters remain in the profile detail. Auto keeps its existing
through-tunnel traffic checks and reserve switching.

The keys, private encrypted storage and imported settings are unchanged.
Auto now retries actual backend failures twice and checks traffic every 15 seconds.
Two consecutive traffic failures select the next candidate. An HTTP response delay
over 1200 ms through the tunnel also selects the next candidate; a slow origin is
checked against an independent HTTPS target. This is application response latency,
not ICMP ping. Offline and manual-stop behavior remain unchanged.
The add menu offers the public Telegram purchase link and the website free one-hour access.
Selective-route Auto changes from the cancelled draft are not included.

## Build and validation

The workflow runs only when manually dispatched. Publishing this repository does not
start a build. The public repository uses the standard `macos-15` GitHub-hosted runner, which is free
for public repositories. It does not use a paid larger runner or paid external service.

The workflow uses macOS 15 to build an unsigned arm64 IPA, run the existing core and
native Simulator tests, and publish a prerelease only if those steps succeed.
Artifacts include `VPN013AWG-unsigned.ipa`, native review evidence and checksums.

For a manual macOS build, run `sh build-on-mac.sh`, then `sh inspect-on-mac.sh`.
The iPhone build needs signing with eligible Network Extension profiles before installation.
Read `ESIGN-RU.md`. A successful build or Simulator test does not establish working
VPN traffic, locked-phone behavior or the validity of the owner's ESign signature.
