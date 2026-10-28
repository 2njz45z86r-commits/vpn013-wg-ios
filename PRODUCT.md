# VPN013 for iPhone — unified client

The owner's 28 October request extends the existing user VPN client. Keep its name
VPN013, bundle identifiers, current avatar, night palette, existing imported AWG
profiles, private encrypted storage, subscriptions, Auto and native controls.

Add separate selectable connection sections for Happ, INCY, AmneziaWG and
BlackTemple. Happ/INCY/BlackTemple use the standard VLESS formats delivered by
the owner's current bot; AmneziaWG retains the existing WireGuard engine. This
does not claim compatibility with every proprietary key from third-party apps.
Remember the selected section and show the active connection's section when the
app returns to foreground. Each section has its own explicit import entry.

On iPhone, offer routing by domain/service and IP network. Do not claim that an
ordinary sideloaded client can enumerate arbitrary installed apps or configure
Apple's MDM-only per-app VPN. Keep routing changes explicit. Keep original-app
handoff links in the bot; a future VPN013 import URL is an additional choice.

The separate small avatar request applies to the Telegram Mini App, already
released independently as c6c5b645bd4409671d7735e3b4b354a31404c5ad. It is not
permission to redesign this native client's existing identity.

Acceptance: real native compilation and regression tests, import validation,
encrypted persistence, correct single-active-tunnel lifecycle, rendered phone
and tablet inspection, and owner signing/device acceptance. Simulator fixtures
and a successful NetworkExtension start do not prove real VPN traffic. No live
customer key may be used as a synthetic test, and no server changes are required.
