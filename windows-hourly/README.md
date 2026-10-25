# Windows hourly comparison development overlay

This isolated development workflow compiles a disposable client and runs native
Windows SYSTEM, Wintun, protected-pipe and socket fixtures. It does not publish
an installer or an application release. The shipped Windows release remains
separate.

The prototype wires a shared kernel barrier into actual primary Up, Down,
configuration changes and asynchronous Close, service startup/teardown, route
workers and bounded UAPI handling. Exact-source patch scripts preserve the
verified upstream license and existing client-specific vendor changes. The
manager's hourly coordinator, authoritative observed-runtime census and actual
one-shot measured switch remain separate unfinished integration requirements.

Native fixtures create temporary SYSTEM services and ephemeral AWG peers with
new random keys. They configure only disposable Wintun interfaces and their
test addresses/routes. A path-race fixture adds and removes an explicitly
nonpreferred default-route row after checking an existing lower-metric default;
it never replaces an existing default route. These tests require the authorized
GitHub-hosted Windows runner and are not intended for a user's installed PC.

The driver is extracted from an official hash-pinned, signature-checked MSI.
No MSI is installed by this development workflow. Runtime fixtures are distinct
from final UI/MSI acceptance and from physical-device or field validation.
Module versions and sums stay pinned. No customer profiles, bot code, signing
credentials or private server material belong in this overlay.
