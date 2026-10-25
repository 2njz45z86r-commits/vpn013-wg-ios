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

The real service now dispatches ordinary get/set/observe through a current-device
slot. A queued set selects its device after the mutation fence, and a slow pipe
reader cannot hold the slot during a swap. A bounded SCM forwarder invalidates
stop/shutdown before a busy main loop can process a stale measured choice.
Standalone endpoint preparation excludes active client/server aliases before
resolution and keeps an immutable original domain/settings copy; only its
bounded, cancellable numeric copy is used to build the future backend UAPI.

Native fixtures create temporary SYSTEM services and ephemeral AWG peers with
new random keys. They configure only disposable Wintun interfaces and their
test addresses/routes. A path-race fixture adds and removes an explicitly
nonpreferred default-route row after checking an existing lower-metric default;
it never replaces an existing default route. These tests require the authorized
GitHub-hosted Windows runner and are not intended for a user's installed PC.

A separate synthetic SYSTEM fixture matches the real unrestricted service SID,
establishes WFP before the unchanged privilege drop, then replaces permissive,
restrictive with DNS, and permissive policies. The old dynamic session remains
until its replacement is installed and verified by a native read-only
transaction. Invalid replacement retains the previous session, failed close
retains bounded ownership, and final cleanup closes the remaining policy.
This API exercise is separate from proving production manager/candidate traffic
through a restrictive policy owned by another actual tunnel service. A safe
owned canonical SID copy retains the exact group attributes/service authority;
no privilege, SID restriction or ACL is relaxed for this fixture.

The exact-source WFP patch also propagates the documented returned DWORD status
instead of unrelated thread LastError. Native invalid-session regressions compare
the actual SDK return with the wrapper, including this runner's accepted
idempotent Close(NULL). A successful API exercise is not a proof of production
packet enforcement, a completed backend switch, or a released hourly client.

The driver is extracted from an official hash-pinned, signature-checked MSI.
No MSI is installed by this development workflow. Runtime fixtures are distinct
from final UI/MSI acceptance and from physical-device or field validation.
Module versions and sums stay pinned. No customer profiles, bot code, signing
credentials or private server material belong in this overlay.


## Existing-TUN network handover phase (not a release)

The watcher now acquires the primary barrier before its setup lock, has checked
callback retirement which preserves WFP, and explicitly configures an existing
TUN without waiting for another MibAdd event. Retirement checks each owned row
delete error (the pinned SDK address-flush method discards those errors).
Explicit apply deep-copies the source and disables foreign disconnected-interface
address cleanup; required IPv6 cannot be silently omitted. Preferred addresses,
routes, DNS servers and explicit MTU are independently read back. Search domains
are applied by the existing SDK but this phase does not claim full native search
list readback or exact OS automatic-MTU equivalence.

A disposable SYSTEM/session0 fixture checks real Wintun address/route/DNS/MTU
apply, checked retirement with old WFP retained, and changed reapply on the same
raw TUN after unchanged privilege dropping. It uses a recording bind adapter: it
is NOT an encrypted packet-admission or actual backend-choice proof. Existing
real-AWG/service regression tests remain required. Native packages are serialized
to avoid concurrent global WFP state changes. No owner PC execution or installer.


## Conditional service-main-loop backend owner (acceptance in progress)

The actual service now consumes a private bounded selection queue through the
shared backend owner. It rechecks immutable exact membership and settings, live
identity, numeric actual rollback endpoint, one-shot generation and foreign
routes before closing the old backend. It uses fresh engine leases on the same
raw TUN, retained WFP replacement, checked native reapply/readback and exact old
rollback on apply/persist failure. Public observation has optional confirmed
member digests; raw external UAPI edits invalidate membership. No hourly queue
producer or manager synchronization is enabled yet.

The new disposable native fixture invokes that SAME implementation under the
real service SID/WFP. Generated local authenticated AWG peers test selected and
rollback traffic while a prior primary stream continues during candidate Scan.
Its seed persistence dependency is in-memory; that does not establish actual
secure-file persistence, complete hourly integration, physical WAN/owner-PC or
manual-stop-during-handover acceptance. No installer or release is published.


The stronger owner fixture additionally uses the REAL existing DPAPI writer and
loader with a test-only temporary root. It injects a failure AFTER writing a new
working seed, checks decrypted rollback, and compares original source/vault
ciphertext byte-for-byte. A second real SCM stop case cancels an in-flight owner
inside persistence and must never acknowledge stale success or undo that stop.
This strengthened revision requires fresh native acceptance. The pure cadence
helper covers initial30s, one in-flight scan,3600s-after-completion and no missed-
period catchup storm; it alone is not an integrated service hourly producer.


Endpoint preparation now has an explicit2s DNS resolver over one concrete protected
physical OR through-tunnel factory, nonce/question/CNAME validation, bounded answers
and TTL<=300s, genuine Cancel acknowledgment, no OS/default/network fallback. Native
fixtures extend existing generated peers to answer a synthetic endpoint domain:
physical role before restrictive policy and through real encrypted Wintun after
restrictive policy. They require native acceptance. PreparePrimary is explicit
primary replacement preparation with no UDP; candidate Prepare and ActiveGuard
still reject every active identity alias before candidate resolution/UDP. No
service hourly/health producer or manager supervision migration is enabled yet.
