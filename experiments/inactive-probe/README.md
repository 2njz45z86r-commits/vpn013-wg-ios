# Experimental authenticated inactive-peer probe

This source is **not integrated in VPN013 WG** and does not provide a working
hourly scan or prove physical iPhone routing. It changes no OS tunnel, route,
DNS setting, profile or server. Tests create disposable loopback AWG peers with
fresh random keys; no customer credentials/configurations are present.

Pinned protocol engine: official `amnezia-vpn/amneziawg-go`,
`v3.1.20260814`. A small memory TUN measures three decrypted ICMP echoes after
an excluded handshake/warm-up echo. A supplied fresh physical-network Bind is
mandatory; there is no fallback transport. Failure to answer ICMP is not proof
that Internet traffic through that VPN fails.

`ActiveGuard` prevents a candidate from using the active client/server identity,
including X25519-clamping and endpoint aliases. All real primary-engine lifecycle
changes must call `BeginTransition`, wait for candidate engines/transports to
close, then commit the actual new state. Unknown/aborted/timed-out transitions
disable candidate work. Epochs invalidate delayed results; `BeginSwitch` makes
an epoch check atomic with stopping probes before a proposed primary switch.
The guard retains a public-identity digest, not the active private configuration.
No shipped platform lifecycle has been wired to this guard yet.

Tests exercise authenticated replies, wrong-key rejection, an independent active
engine continuing during candidate probes, identity aliases, queued membership
changes, slow transport shutdown, drain timeout, stale results, cancellation and
30 sequential probes. Resource measurements on a desktop runner are observations,
not an iOS extension memory budget. Run `go test -race -count=1 -timeout=90s -v ./...`
and `go vet ./...` with the pinned Go1.26.10. Dependencies now match the client's
AWG3.1.20260814 / x-net0.57 / x-crypto0.54 / x-sys0.47 selection.

`platform/AppleUDPAPICheck.swift` is a type-check-only SDK spike. Apple documents
`NEProvider.createUDPSession(to:from:)` with nil `from` as binding to the primary
physical interface, and `createUDPSessionThroughTunnel` as using the virtual
interface. These APIs are deprecated in favor of Network framework APIs. Type
checking is not an on-device Network Extension routing test or a completed Go
bridge. References:

- https://developer.apple.com/documentation/networkextension/neprovider/createudpsession(to:from:)
- https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/createudpsessionthroughtunnel(to:from:)
- https://developer.apple.com/documentation/networkextension/nwudpsession/writedatagram(_:completionhandler:)
- https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260814

The bounded physical transport, equal-method DNS measurement and scan policy are
implemented in this experiment. `Controller` and `applebridge/controller.go` add
bounded asynchronous scan/poll/cancel and one-shot lifecycle/choice permits.
`platform/ProbeCoordinator.swift` supplies a real3600-second timer, typed DNS
metrics, cancellation and fresh-choice checks, but it is NOT yet wired into the
released provider or all WireGuardAdapter lifecycle paths. It is not a shipped
hourly feature. Candidate fixture traffic is real disposable AWG; current/native
platform sessions remain synthetic, not physical iPhone/NEProvider proof.

`stage_into_client.py` merges an explicit client-source allowlist into the
existing WireGuardKitGo module/archive. It removes ONLY the experimental duplicate
main, preserves original client source and does not link a second Go runtime.
CI stages into the same pinned official client commit/dependencies used by the
app, runs native tests and builds one combined archive. This staged check still
does not register the Xcode sources or intercept actual provider lifecycle.

Still required before use: actual all-path lifecycle/Auto integration, UI delivery,
ongoing primary-traffic/resource checks and physical-device routing verification.
Do not compare DNS with endpoint ICMP/HTTPS or ship a guessed active identity.
