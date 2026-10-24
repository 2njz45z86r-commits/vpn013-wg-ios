# VPN013 WG 1.2.1 (manual-start fix; pending native build)

Separate iPhone app ID com.vpn013.awg, extension com.vpn013.awg.network-extension,
no shared App Group dependency. Incumbent official AmneziaWG import/list retained.
Automatic profile is made from all imported ordinary full-IPv4 single-peer profiles,
including third-party servers, regardless of country or number. Empty input is
disabled and rejected. A single server is allowed with a no-reserve explanation.
Existing Auto profiles are excluded from sources. An immutable copy of all source
configs is encrypted with AES-256-GCM in VPN preferences; a random per-profile key
is stored separately in each process's private data-protected sandbox. First app
start bootstraps the extension through VPN start options; subsequent starts use
its own persisted key. No key or expiry is
changed on any VPS; no server admin API is added to this client.

The provider resolves reserve endpoint domains during startup (bounded first-start
delay), retaining the domain originals in saved profiles. Each active candidate is
probed through NEPacketTunnelProvider.createTCPConnectionThroughTunnel with default
system TLS validation: Apple first, Cloudflare second on failure. No direct-session
URLSession can produce a false healthy result outside the tunnel. Health failure
twice triggers the next candidate; no network pauses rotation; exhausting all candidates
backs off 60s. Manual stop cancels timers/probes, increments the generation and stops
the controller. Backend switch stop/start runs inside the same system Packet Tunnel
so optional AWG fields do not carry over between countries. A path change during
backend replacement does not cancel and repeatedly restart that replacement.

Manual profiles follow the system Packet Tunnel lifecycle without a foreground
12-second handshake deadline that stops a quiet connection. A system connected
status confirms tunnel startup, not successful peer traffic. Runtime handshake and
byte counters remain available in the detail view. Auto retains its separate
through-tunnel traffic checks and reserve switching; its header reports health.
Not a claim of uninterrupted TCP sessions or a comprehensive iOS Kill Switch.

Policy tests cover counts 1...40 and every initial candidate, failures, exhaustion,
recovery, offline and manual stop. Native Simulator flow uses documentation-address
fixtures only. Signing diagnostics exercise synthetic CMS/profile/Mach-O cases;
they do not verify Apple's trust chain or revocation. Real VPN failover, locked-phone
behavior, ESign's actual profiles and radio transitions require an installed build
on a physical iPhone. These checks cannot be claimed from CI screenshots.

CI source published only on awg-auto-ios branch in existing private repository.
Main owner-admin app remains unchanged. Build uses pinned public upstream
9d5ee60edefa95b933a738dd7cda671dd18021fc and a credential-free source overlay;
Xray bridge build excluded. Go downloaded from official go.dev with SHA verification.
No Apple certificate/private key or customer config goes to CI. Output has ad-hoc
integrity signature with declared rights; it must be re-signed using eligible ESign
profiles before installing. Official sources for signing are linked in ESIGN-RU.md.
