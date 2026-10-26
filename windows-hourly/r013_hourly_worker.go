// SPDX-License-Identifier: MIT
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013prepare"
	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013vault"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

type comparisonHealthProof struct {
	guard    *probe.ActiveGuard
	action   r013.Decision
	failures int
	latency  time.Duration
	at       time.Time
}
type cachedComparisonMember struct {
	member  *r013prepare.Member
	expires time.Time
	wall    int64
}
type comparisonWorker struct {
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	owner       *comparisonBackendOwner
	image       string
	rotation    int
	policy      r013.HealthPolicy
	seen        r013gate.ConfirmedMember
	lastPath    string
	lastRx      conf.Bytes
	probeWorked bool
	goodAt      time.Time
	started     time.Time
	cache       map[string]cachedComparisonMember
}

func newComparisonWorker(parent context.Context, owner *comparisonBackendOwner) (*comparisonWorker, error) {
	if owner == nil || (*owner.configuration).Name != r013.AutoName || owner.observation.member.Load() == nil {
		return nil, nil
	}
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	image, err := r013gate.ExecutableDigest(path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	w := &comparisonWorker{ctx: ctx, cancel: cancel, done: make(chan struct{}), owner: owner, image: image, started: time.Now(), cache: make(map[string]cachedComparisonMember)}
	owner.observation.workerStarted.Store(w.started.UnixNano())
	owner.observation.healthOwned.Store(true)
	go w.run()
	return w, nil
}
func (w *comparisonWorker) Close() { w.cancel(); <-w.done }
func (w *comparisonWorker) run() {
	defer close(w.done)
	defer w.owner.observation.healthOwned.Store(false)
	schedule := probe.NewHourlySchedule(time.Now())
	defer schedule.Close()
	hourly := time.NewTimer(schedule.Delay(time.Now()))
	defer hourly.Stop()
	health := time.NewTimer(time.Second)
	defer health.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-hourly.C:
			if schedule.TryStart(time.Now()) {
				w.scan()
				schedule.Finish(time.Now())
			}
			hourly.Reset(schedule.Delay(time.Now()))
		case <-health.C:
			w.health()
			health.Reset(15 * time.Second)
		}
	}
}

// The target is explicit and identical for current and candidates. Empty DNS
// retains the existing client's declared1.1.1.1 probe target; there is NO retry
// with another resolver when a configured target does not answer.
func comparisonTarget(configuration conf.Config) (netip.AddrPort, error) {
	for _, ip := range configuration.Interface.DNS {
		if v4 := ip.To4(); v4 != nil {
			address, ok := netip.AddrFromSlice(v4)
			if ok && !address.IsUnspecified() && !address.IsMulticast() {
				return netip.AddrPortFrom(address, 53), nil
			}
		}
	}
	if len(configuration.Interface.DNS) == 0 {
		return netip.MustParseAddrPort("1.1.1.1:53"), nil
	}
	return netip.AddrPort{}, errors.New("current profile has no supported IPv4 DNS probe target")
}
func (w *comparisonWorker) inspect(ctx context.Context, token r013gate.Token) (r013gate.PrimarySnapshot, r013vault.Snapshot, conf.Config, error) {
	var noSnapshot r013vault.Snapshot
	var noConfig conf.Config
	actual, err := r013gate.InspectPrimary(ctx, token, w.image, r013.AutoName)
	if err != nil || actual.Observation.PID != uint32(os.Getpid()) || !actual.Observation.HealthOwned || actual.Observation.Member == nil || !actual.Observation.Member.Valid() {
		return actual, noSnapshot, noConfig, errBackendUnknown
	}
	snapshot, err := w.owner.load()
	if err != nil {
		return actual, noSnapshot, noConfig, errBackendUnknown
	}
	state := actual.Observation.Member
	configuration, digest, err := snapshot.Member(state.Index)
	if err != nil || state.Revision != snapshot.Revision() || state.Count != snapshot.Count() || state.Digest != digest || !r013vault.EligibleForComparison(configuration) {
		return actual, noSnapshot, noConfig, errBackendUnknown
	}
	identity, err := r013prepare.Identity(configuration)
	if err != nil || identity != actual.Observation.Identity {
		return actual, noSnapshot, noConfig, errBackendUnknown
	}
	return actual, snapshot, configuration, nil
}
func (w *comparisonWorker) resetHealth(state r013gate.ConfirmedMember) {
	w.seen = state
	w.policy = r013.HealthPolicy{}
	w.lastRx = 0
	w.probeWorked = false
	w.goodAt = time.Time{}
}
func (w *comparisonWorker) submit(request *comparisonSelection) error {
	request.created = time.Now()
	request.reply = make(chan error, 1)
	select {
	case w.owner.requests <- request:
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
	select {
	case err := <-request.reply:
		if state := w.owner.observation.member.Load(); state != nil {
			if err == nil && request.health != nil && request.health.action == r013.Retry {
				w.seen = *state
				w.lastRx = 0
			} else {
				w.resetHealth(*state)
			}
		}
		return err
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
}
func (w *comparisonWorker) prepare(ctx context.Context, snapshot r013vault.Snapshot, index int, active string, roles r013prepare.Roles, resolver *r013prepare.EndpointResolver, primary bool) (*r013prepare.Member, string, error) {
	configuration, digest, err := snapshot.Member(index)
	if err != nil {
		return nil, "", err
	}
	if !primary {
		identity, e := r013prepare.Identity(configuration)
		if e != nil {
			return nil, "", e
		}
		if identity == active {
			return nil, "", probe.ErrActiveIdentity
		}
	}
	key := snapshot.Revision() + digest
	if cached, ok := w.cache[key]; ok {
		now := time.Now()
		if now.Before(cached.expires) && now.UnixNano() < cached.wall {
			return cached.member, digest, nil
		}
		delete(w.cache, key)
	}
	var member *r013prepare.Member
	if primary {
		member, err = r013prepare.PreparePrimary(ctx, configuration, roles, resolver)
	} else {
		member, err = r013prepare.Prepare(ctx, configuration, active, roles, resolver)
	}
	if err != nil {
		return nil, "", err
	}
	ttl := resolver.TTL(configuration.Peers[0].Endpoint.Host)
	if _, e := netip.ParseAddr(configuration.Peers[0].Endpoint.Host); e == nil {
		ttl = 300 * time.Second
	}
	if ttl > 0 {
		if ttl > 300*time.Second {
			ttl = 300 * time.Second
		}
		if len(w.cache) >= 30 {
			clear(w.cache)
		}
		now := time.Now()
		w.cache[key] = cachedComparisonMember{member: member, expires: now.Add(ttl), wall: now.UnixNano() + int64(ttl)}
	}
	return member, digest, nil
}

func (w *comparisonWorker) scan() {
	stage := "enter"
	started := time.Now()
	defer func() { log.Printf("R013Routing: comparison stage=%s duration=%s", stage, time.Since(started)) }()
	ctx, cancel := context.WithTimeout(w.ctx, 90*time.Second)
	defer cancel()
	var request *comparisonSelection
	w.owner.observation.comparing.Store(true)
	defer w.owner.observation.comparing.Store(false)
	scanErr := w.owner.gate.Candidate(ctx, func(work context.Context, token r013gate.Token) error {
		stage = "inspect"
		actual, snapshot, current, err := w.inspect(work, token)
		if err != nil {
			return err
		}
		stage = "target"
		target, err := comparisonTarget(current)
		if err != nil {
			return err
		}
		stage = "foreign-path-before"
		beforePath, err := comparisonForeignPath(winipcfg.LUID(w.owner.native.LUID()))
		if err != nil {
			return err
		}
		stage = "physical-factory"
		physical, err := r013gate.NewUDPFactory(protectedudp.Physical, actual.Observation.Physical4, actual.Observation.Physical6, token)
		if err != nil {
			return err
		}
		defer physical.Close(context.Background())
		stage = "tunnel-factory"
		through, err := r013gate.NewUDPFactory(protectedudp.ThroughTunnel, actual.Observation.TunnelIndex, 0, token)
		if err != nil {
			return err
		}
		defer through.Close(context.Background())
		stage = "resolver"
		resolver, err := r013prepare.NewTunnelEndpointResolver(target, through, actual.Observation.Physical6 != 0)
		if err != nil {
			return err
		}
		guard, err := probe.NewActiveGuard(probe.ActiveState{Known: true, Configuration: actual.RuntimeConfiguration()})
		if err != nil {
			return err
		}
		type prepared struct {
			index  int
			member *r013prepare.Member
			digest string
			fresh  probe.ScanCandidate
		}
		var candidates []probe.ScanCandidate
		var members []prepared
		deadline, _ := ctx.Deadline()
		stage = "prepare"
		for offset := 0; offset < snapshot.Count(); offset++ {
			index := (w.rotation + offset) % snapshot.Count()
			if time.Until(deadline) < 24*time.Second {
				w.rotation = index
				break
			}
			member, digest, e := w.prepare(work, snapshot, index, actual.Observation.Identity, r013prepare.Roles{Physical4: actual.Observation.Physical4, Physical6: actual.Observation.Physical6}, resolver, false)
			if e != nil {
				if work.Err() != nil {
					return work.Err()
				}
				continue
			}
			binding, e := probe.NewPhysicalBind(member.Endpoint(), physical)
			if e != nil {
				return e
			}
			fresh := probe.ScanCandidate{ID: fmt.Sprintf("%d:%s", index, digest), DNSRequest: probe.DNSRequest{Request: probe.Request{Config: member.UAPI(), Source: member.Source(), Target: target.Addr(), Bind: binding, Guard: guard}, Port: target.Port()}}
			candidates = append(candidates, fresh)
			members = append(members, prepared{index, member, digest, fresh})
		}
		if len(candidates) == 0 {
			return nil
		}
		stage = "encrypted-scan"
		result, err := probe.Scan(work, probe.ScanRequest{AutoActive: true, Current: probe.CurrentDNSRequest{Target: target, Factory: through, Guard: guard}, Candidates: candidates})
		if result.NextIndex >= 0 && result.NextIndex < len(members) {
			w.rotation = members[result.NextIndex].index
		}
		if err != nil {
			return err
		}
		if err = errors.Join(physical.Close(context.Background()), through.Close(context.Background())); err != nil {
			return err
		}
		stage = "foreign-path-after"
		afterPath, err := comparisonForeignPath(winipcfg.LUID(w.owner.native.LUID()))
		if err != nil || afterPath != beforePath || !token.Valid() {
			return errBackendUnknown
		}
		stage = "vault-recheck"
		freshVault, err := w.owner.load()
		if err != nil || freshVault.Revision() != snapshot.Revision() {
			return errBackendUnknown
		}
		measured := int64(0)
		for _, row := range result.Measurements {
			if row.Status == "measured" {
				measured++
			}
		}
		w.owner.observation.lastCompared.Store(measured)
		w.owner.observation.lastComparison.Store(time.Now().UnixNano())
		stage = "choice"
		if result.Choice != nil {
			for _, member := range members {
				if member.fresh.ID == result.Choice.ID {
					request = &comparisonSelection{stamp: token.Stamp(), current: *actual.Observation.Member, revision: snapshot.Revision(), digest: member.digest, index: member.index, path: afterPath, member: member.member, choice: result.Choice, fresh: member.fresh}
					break
				}
			}
		}
		return nil
	})
	if scanErr != nil {
		log.Printf("R013Routing: comparison failed stage=%s type=%T", stage, scanErr)
	}
	if request != nil && w.ctx.Err() == nil {
		stage = "submit"
		if err := w.submit(request); err != nil {
			log.Printf("R013Routing: selection failed type=%T", err)
		}
	}
}

// Health is serialized with hourly Scan and uses the same protected current
// path. A DNS miss alone does not label a previously unmeasured VPN broken.
func (w *comparisonWorker) health() {
	ctx, cancel := context.WithTimeout(w.ctx, 12*time.Second)
	defer cancel()
	var request *comparisonSelection
	_ = w.owner.gate.Candidate(ctx, func(work context.Context, token r013gate.Token) error {
		actual, snapshot, current, err := w.inspect(work, token)
		if err != nil {
			return err
		}
		state := *actual.Observation.Member
		if state != w.seen {
			w.resetHealth(state)
		}
		target, err := comparisonTarget(current)
		if err != nil {
			return err
		}
		path, err := comparisonForeignPath(winipcfg.LUID(w.owner.native.LUID()))
		if err != nil {
			return err
		}
		if path != w.lastPath {
			w.resetHealth(state)
			w.lastPath = path
		}
		through, err := r013gate.NewUDPFactory(protectedudp.ThroughTunnel, actual.Observation.TunnelIndex, 0, token)
		if err != nil {
			return err
		}
		defer through.Close(context.Background())
		guard, err := probe.NewActiveGuard(probe.ActiveState{Known: true, Configuration: actual.RuntimeConfiguration()})
		if err != nil {
			return err
		}
		measureCtx, measureCancel := context.WithTimeout(work, 6*time.Second)
		result, probeError := probe.MeasureCurrentDNS(measureCtx, probe.CurrentDNSRequest{Target: target, Factory: through, Guard: guard})
		measureCancel()
		if work.Err() != nil {
			return work.Err()
		}
		// Re-read genuine peer traffic after the probe, never an initial saved seed.
		after, freshVault, _, err := w.inspect(work, token)
		if err != nil || *after.Observation.Member != state || freshVault.Revision() != snapshot.Revision() {
			return errBackendUnknown
		}
		runtime, err := conf.FromUAPI(strings.NewReader(after.RuntimeConfiguration()+"\n"), &current)
		if err != nil || len(runtime.Peers) != 1 {
			return errBackendUnknown
		}
		peer := runtime.Peers[0]
		progress := peer.RxBytes > w.lastRx
		w.lastRx = peer.RxBytes
		if probeError != nil && (progress || (peer.LastHandshakeTime > 0 && !w.probeWorked)) {
			if progress {
				w.policy.Failures = 0
			}
			return nil
		}
		working := probeError == nil
		if working {
			w.probeWorked = true
			w.goodAt = time.Now()
		}
		failures := 0
		if !working {
			failures = w.policy.Failures + 1
		}
		decision := w.policy.Observe(working, result.Median)
		if decision == r013.Stay {
			return nil
		}
		index := state.Index
		if decision == r013.Advance {
			index = (state.Index + 1) % snapshot.Count()
		}
		physical, err := r013gate.NewUDPFactory(protectedudp.Physical, actual.Observation.Physical4, actual.Observation.Physical6, token)
		if err != nil {
			return err
		}
		defer physical.Close(context.Background())
		resolver, err := r013prepare.NewPhysicalEndpointResolver(target, physical, actual.Observation.Physical6 != 0)
		if err != nil {
			return err
		}
		var member *r013prepare.Member
		var digest string
		roles := r013prepare.Roles{Physical4: actual.Observation.Physical4, Physical6: actual.Observation.Physical6}
		if index == state.Index {
			original, id, e := snapshot.Member(index)
			if e != nil {
				return e
			}
			ip, e := netip.ParseAddr(runtime.Peers[0].Endpoint.Host)
			if e != nil {
				return e
			}
			member, err = r013prepare.PreparePrimary(work, original, roles, runtimeEndpointResolver{ip})
			digest = id
		} else {
			member, digest, err = w.prepare(work, snapshot, index, actual.Observation.Identity, roles, resolver, true)
			if err != nil {
				original, id, e := snapshot.Member(index)
				recent := time.Since(w.started) < 60*time.Second || (!w.goodAt.IsZero() && time.Since(w.goodAt) < 60*time.Second)
				if e != nil || !recent || !strings.EqualFold(original.Peers[0].Endpoint.Host, current.Peers[0].Endpoint.Host) {
					return err
				}
				ip, e := netip.ParseAddr(runtime.Peers[0].Endpoint.Host)
				if e != nil {
					return e
				}
				member, err = r013prepare.PreparePrimary(work, original, roles, runtimeEndpointResolver{ip})
				digest = id
			}
		}
		if err != nil {
			return err
		}
		if err = errors.Join(physical.Close(context.Background()), through.Close(context.Background())); err != nil {
			return err
		}
		afterPath, err := comparisonForeignPath(winipcfg.LUID(w.owner.native.LUID()))
		if err != nil || afterPath != path || !token.Valid() {
			return errBackendUnknown
		}
		request = &comparisonSelection{stamp: token.Stamp(), current: state, revision: snapshot.Revision(), digest: digest, index: index, path: path, member: member, health: &comparisonHealthProof{guard: guard, action: decision, failures: failures, latency: result.Median, at: time.Now()}}
		return nil
	})
	if request != nil && w.ctx.Err() == nil {
		_ = w.submit(request)
	}
}

// Only a recently ACTUAL endpoint for the SAME configured hostname is supplied
// here for primary retry, never a guessed address or candidate probing fallback.
type runtimeEndpointResolver struct{ address netip.Addr }

func (r runtimeEndpointResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ctx.Err() != nil || network != "ip" || !r.address.IsValid() {
		return nil, errBackendUnknown
	}
	return []netip.Addr{r.address}, nil
}
