# VPN013 WG for iPhone

Standalone VPN client project, separate from the owner administration app and Telegram bot.
Version 1.3.0 build 5 is prepared for a native build; it has not yet been validated on an iPhone.

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


## Native interface update

Version 1.3.0 (7) uses the owner-selected night palette, a native server list,
a compact connection summary and Dynamic Type. The developer footer links
to https://t.me/R013_Support and identifies the VPN013 WG fork. Upstream
AmneziaWG/WireGuard attribution remains in the bundled legal notices.
Profile actions, private encrypted storage, import, manual connections and
existing Auto health checks are preserved. No demonstration latency numbers
are included in device builds.

Hourly background testing of inactive VPN peers and automatic selection of the
fastest inactive peer are NOT implemented in this release. Independent AWG
handshake probes need physical-device validation of memory use, uninterrupted
traffic and endpoint roaming. A handshake delay would not itself prove working
internet traffic. The existing Auto failover behavior remains unchanged.


## Endpoint ping in 1.3.1 (8)

The visible «Проверить пинг» action measures real ICMP echo replies from imported
profiles' endpoint addresses without activating or switching VPN profiles. Results
are in milliseconds; no reply, DNS failure, cancellation and unavailable sockets
are explicit. IPv4/IPv6 replies must match a fresh per-probe nonce. Requests cannot
be mistaken for replies. Three workers and a 45-second batch deadline bound work.
The ping uses the current OS route, including the current VPN if routed that way.
It is not an AWG handshake, UDP-port test, or proof of tunneled internet traffic.
Auto's existing in-tunnel HTTPS health measurements and failover are unchanged.
No automatic ranking or hourly inactive-VPN traffic scan is claimed by this build.
Actual loopback echo tests cover sockets and UI; physical iPhone behavior still
requires the owner-signed build. No customer configurations are included.


## Order-bound configuration updates in 1.4.0 (9)

The visible Updates screen checks a fixed HTTPS bot-backend domain, using normal
system TLS. On foreground/launch it checks at most daily after a successful check;
manual refresh is also available. iOS offers the Telegram download screen for owner
signing and installation. A closed app is not guaranteed a background daily launch.

An optional VPN013-Access.json document in the existing ZIP contains a purpose-scoped
per-order capability and an authenticated complete roster digest. The capability,
cached configurations, pending updates and profile-ID associations are encrypted
in this app's private sandbox using AES-GCM. They do not require an App Group.
Old ZIPs and third-party configurations retain the ordinary import path.

An update validates the entire roster (1-30 servers), parses every configuration,
checks the same order and preserves existing key material. A partial, empty,
unauthorized or expired response cannot remove profiles. Only explicitly bound
profile IDs can be removed. Local edits stop automatic replacement. New/changed
profiles are saved before obsolete bound profiles are removed, with durable progress
and retry. Applying waits until VPN and on-demand activation are off. Managed Auto
membership follows the refreshed sources; unrelated manual sources are retained.

After successful device compilation and native simulator tests the workflow publishes
client-release.json. The private bot consumes this public metadata, so its IPA link
and client update checks advance together. No private bot source is published here.
Android/Windows binaries and installers are not part of this iOS release.
Physical iPhone signing, traffic, and real order delivery require separate validation.
