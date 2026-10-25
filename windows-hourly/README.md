# Windows hourly comparison development overlay

This isolated development workflow compiles a disposable client and runs native
Windows SYSTEM, Wintun, protected-pipe and socket fixtures. It does not publish
an installer or an application release. The shipped Windows release remains
separate.

The prototype wires a shared kernel barrier into actual primary Up, Down,
configuration changes and asynchronous Close, service startup/teardown, route
workers and bounded UAPI handling. Exact-source patch scripts preserve the
verified upstream license and existing client-specific vendor changes. The
read-only observed-runtime protocol and authoritative SCM definition/PID/image
census are exercised against actual services, including refusal of multiple
running services and a stopped unsupported binary. The immutable legacy DPAPI
vault remains unchanged. A batch-one native TUN relay can retire one backend
and authenticate a fresh backend without closing its owned TUN, avoiding stale
omitted obfuscation fields. These are foundations: the manager hourly scheduler,
conditional measured switch and route/DNS/firewall rollback remain unfinished.

Native fixtures create temporary SYSTEM services and ephemeral AWG peers with
new random keys. They configure only disposable Wintun interfaces and their
test addresses/routes. A path-race fixture adds and removes an explicitly
nonpreferred default-route row after checking an existing lower-metric default;
it never replaces an existing default route. These tests require the authorized
GitHub-hosted Windows runner and are not intended for a user's installed PC.

A separate synthetic SYSTEM fixture matches the real unrestricted service SID,
establishes WFP before the unchanged privilege drop, then exercises native WFP
enable/disable after it for permissive, restrictive with DNS, and permissive
policies. Each dynamic policy is immediately closed on the disposable VM.
This API exercise is separate from proving production manager/candidate traffic
through a restrictive policy owned by another actual tunnel service. A safe
owned canonical SID copy retains the exact group attributes/service authority;
no privilege, SID restriction or ACL is relaxed for this fixture.

The driver is extracted from an official hash-pinned, signature-checked MSI.
No MSI is installed by this development workflow. Runtime fixtures are distinct
from final UI/MSI acceptance and from physical-device or field validation.
Module versions and sums stay pinned. No customer profiles, bot code, signing
credentials or private server material belong in this overlay.
