// SPDX-License-Identifier: MIT
package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013prepare"
	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013vault"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/sys/windows"
)

var errBackendUnknown = errors.New("actual backend is no longer confirmed")

// This private queue has one service-main-loop consumer. No public UAPI command
// can create a choice. The hourly producer must close BOTH token UDP factories
// before enqueueing an immutable one-shot measurement.
type comparisonSelection struct {
	created                time.Time
	health                 *comparisonHealthProof
	stamp                  r013gate.Stamp
	current                r013gate.ConfirmedMember
	revision, digest, path string
	index                  int
	member                 *r013prepare.Member
	choice                 *probe.Choice
	fresh                  probe.ScanCandidate
	reply                  chan error
}
type comparisonBackendOwner struct {
	generation    uint64
	ctx           context.Context
	gate          *r013gate.Gate
	slot          *r013gate.PrimaryDeviceSlot
	relay         *r013tun.Relay
	native        *tun.NativeTun
	configuration **conf.Config
	engine        **device.Device
	watcher       **interfaceWatcher
	observation   *comparisonServiceObservation
	load          func() (r013vault.Snapshot, error)
	persist       func(*conf.Config) error
	requests      chan *comparisonSelection
}

func newComparisonBackendOwner(ctx context.Context, gate *r013gate.Gate, slot *r013gate.PrimaryDeviceSlot, relay *r013tun.Relay, native *tun.NativeTun, configuration **conf.Config, engine **device.Device, watcher **interfaceWatcher, observation *comparisonServiceObservation) *comparisonBackendOwner {
	o := &comparisonBackendOwner{ctx: ctx, gate: gate, slot: slot, relay: relay, native: native, configuration: configuration, engine: engine, watcher: watcher, observation: observation, load: r013vault.Load, persist: func(c *conf.Config) error { return c.Save(true) }, requests: make(chan *comparisonSelection, 1)}
	o.confirmInitial()
	return o
}
func (o *comparisonBackendOwner) confirmInitial() {
	o.observation.member.Store(nil)
	if *o.configuration == nil || (*o.configuration).Name != r013.AutoName {
		return
	}
	snapshot, err := o.load()
	if err != nil {
		return
	}
	index, digest, err := snapshot.WorkingMember(**o.configuration)
	if err != nil {
		return
	}
	o.generation++
	state := &r013gate.ConfirmedMember{Generation: o.generation, Index: index, Count: snapshot.Count(), Revision: snapshot.Revision(), Digest: digest}
	if state.Valid() {
		o.observation.member.Store(state)
	}
}

// A raw external write invalidates membership BEFORE waiting for the primary
// barrier; matching client/server keys cannot preserve different old settings.
type comparisonDeviceAccess struct {
	slot        *r013gate.PrimaryDeviceSlot
	observation *comparisonServiceObservation
}

func (a *comparisonDeviceAccess) IpcGetOperation(w io.Writer) error { return a.slot.IpcGetOperation(w) }
func (a *comparisonDeviceAccess) IpcSet(body string) error {
	a.observation.member.Store(nil)
	return a.slot.IpcSet(body)
}

func (o *comparisonBackendOwner) apply(request *comparisonSelection) error {
	stage := "received"
	step := func(value string) { stage = value; log.Printf("R013Routing: backend stage=%s", stage) }
	defer func() { log.Printf("R013Routing: backend returned stage=%s", stage) }()
	step("received")
	if request == nil || request.member == nil || !request.current.Valid() || o.ctx.Err() != nil || !comparisonRequestFresh(request.created) {
		return errBackendUnknown
	}
	if request.health == nil && (request.choice == nil || request.fresh.Config != request.member.UAPI() || request.fresh.Source != request.member.Source()) {
		return errBackendUnknown
	}
	selected, err := request.member.Original()
	if err != nil {
		return errBackendUnknown
	}
	selected.Name = r013.AutoName
	// Capture an ACTUAL numeric rollback endpoint before acquiring the fence.
	old, err := r013vault.CopyConfig(**o.configuration)
	if err != nil || !r013vault.EligibleForComparison(old) {
		return errBackendUnknown
	}
	step("runtime-before")
	raw, err := (*o.engine).IpcGet()
	if err != nil {
		return errBackendUnknown
	}
	actual, err := conf.FromUAPI(strings.NewReader(raw+"\n"), &old)
	if err != nil || len(actual.Peers) != 1 {
		return errBackendUnknown
	}
	numeric, err := netip.ParseAddr(actual.Peers[0].Endpoint.Host)
	if err != nil || actual.Peers[0].Endpoint.Port == 0 {
		return errBackendUnknown
	}
	rollback, err := r013vault.CopyConfig(old)
	if err != nil || len(rollback.Peers) != 1 {
		return errBackendUnknown
	}
	rollback.Peers[0].Endpoint = conf.Endpoint{Host: numeric.String(), Port: actual.Peers[0].Endpoint.Port}
	rollbackUAPI, err := rollback.ToUAPI()
	if err != nil {
		return errBackendUnknown
	}
	identity, err := probe.PublicIdentityDigest(raw)
	if err != nil {
		return errBackendUnknown
	}
	var transition *probe.ActiveTransition
	step("choice-transition")
	if request.health != nil {
		if request.choice != nil || !request.health.valid(request.index, request.current) {
			return errBackendUnknown
		}
		transition, err = request.health.guard.BeginTransition(o.ctx)
	} else {
		transition, err = request.choice.BeginSwitch(o.ctx, request.fresh)
	}
	if err != nil {
		return err
	}
	defer transition.Abort()
	step("slot-swap")
	return o.slot.Swap(request.stamp, func(current r013gate.PrimaryUAPIDevice) (r013gate.PrimaryUAPIDevice, error) {
		step("slot-owned")
		if current != *o.engine || o.ctx.Err() != nil || !comparisonRequestFresh(request.created) || (request.health != nil && !request.health.valid(request.index, request.current)) {
			return current, errBackendUnknown
		}
		known := o.observation.member.Load()
		if known == nil || *known != request.current {
			return current, errBackendUnknown
		}
		snapshot, e := o.load()
		if e != nil || snapshot.Revision() != request.revision {
			return current, errBackendUnknown
		}
		exact, digest, e := snapshot.Member(request.index)
		if e != nil || digest != request.digest {
			return current, errBackendUnknown
		}
		original, e := request.member.Original()
		if e != nil {
			return current, errBackendUnknown
		}
		left, e := json.Marshal(exact)
		if e != nil {
			return current, errBackendUnknown
		}
		right, e := json.Marshal(original)
		if e != nil || string(left) != string(right) {
			return current, errBackendUnknown
		}
		currentIndex, currentDigest, e := snapshot.WorkingMember(old)
		if e != nil || currentIndex != known.Index || currentDigest != known.Digest || known.Revision != snapshot.Revision() {
			return current, errBackendUnknown
		}
		step("runtime-fenced")
		now, e := (*o.engine).IpcGet()
		if e != nil {
			return current, errBackendUnknown
		}
		nowIdentity, e := probe.PublicIdentityDigest(now)
		if e != nil || nowIdentity != identity {
			return current, errBackendUnknown
		}
		nowActual, e := conf.FromUAPI(strings.NewReader(now+"\n"), &old)
		if e != nil || len(nowActual.Peers) != 1 || nowActual.Peers[0].Endpoint != rollback.Peers[0].Endpoint {
			return current, errBackendUnknown
		}
		step("path-fenced")
		path, e := comparisonForeignPath(winipcfg.LUID(o.native.LUID()))
		if e != nil || path != request.path {
			return current, errBackendUnknown
		}
		o.observation.ready.Store(false)
		o.observation.member.Store(nil)
		// From here every failure must restore exact old state or stop unavailable.
		step("retire-watcher")
		applyError := (*o.watcher).RetireForBackend(o.ctx)
		if applyError == nil {
			step("close-engine")
			(*o.engine).Close()
			<-(*o.engine).Wait()
			*o.engine = nil
		}
		if applyError == nil {
			step("install-engine")
			applyError = o.install(&selected, request.member.UAPI())
		}
		if applyError == nil {
			path, e = comparisonForeignPath(winipcfg.LUID(o.native.LUID()))
			if e != nil || path != request.path {
				applyError = errBackendUnknown
			}
		}
		if applyError == nil {
			step("persist-working")
			applyError = o.persist(&selected)
		}
		if applyError == nil && o.ctx.Err() == nil {
			runtime, e := (*o.engine).IpcGet()
			if e == nil {
				var id string
				id, e = probe.PublicIdentityDigest(runtime)
				if id != request.member.Identity() {
					e = errBackendUnknown
				}
			}
			if e == nil {
				fresh, loadError := o.load()
				if loadError != nil || fresh.Revision() != request.revision {
					e = errBackendUnknown
				}
			}
			if e == nil {
				e = transition.Commit(probe.ActiveState{Known: true, Configuration: runtime})
			}
			applyError = e
			if applyError == nil {
				o.generation++
				state := &r013gate.ConfirmedMember{Generation: o.generation, Index: request.index, Count: snapshot.Count(), Revision: snapshot.Revision(), Digest: request.digest}
				o.observation.member.Store(state)
				o.observation.ready.Store(true)
				return *o.engine, nil
			}
		}
		if o.ctx.Err() != nil {
			return nil, errors.Join(applyError, o.ctx.Err())
		}
		// A new native engine may be partially installed. All callbacks/IO must be
		// genuinely retired before trying the old exact settings on another lease.
		if *o.watcher != nil {
			if e = (*o.watcher).RetireForBackend(o.ctx); e != nil {
				return nil, errors.Join(applyError, e)
			}
		}
		if *o.engine != nil {
			(*o.engine).Close()
			<-(*o.engine).Wait()
			*o.engine = nil
		}
		if e = o.install(&old, rollbackUAPI); e != nil {
			return nil, errors.Join(applyError, e)
		}
		if e = o.persist(&old); e != nil {
			return nil, errors.Join(applyError, e)
		}
		path, e = comparisonForeignPath(winipcfg.LUID(o.native.LUID()))
		if e != nil || path != request.path {
			return nil, errors.Join(applyError, errBackendUnknown)
		}
		runtime, e := (*o.engine).IpcGet()
		if e == nil {
			e = transition.Commit(probe.ActiveState{Known: true, Configuration: runtime})
		}
		if e != nil {
			return nil, errors.Join(applyError, e)
		}
		// Confirm only if the unchanged vault still contains that exact old member.
		snapshot, e = o.load()
		if e != nil || snapshot.Revision() != known.Revision {
			return nil, errors.Join(applyError, errBackendUnknown)
		}
		index, digest, e := snapshot.WorkingMember(old)
		if e != nil || index != known.Index || digest != known.Digest {
			return nil, errors.Join(applyError, errBackendUnknown)
		}
		o.generation++
		restored := *known
		restored.Generation = o.generation
		o.observation.member.Store(&restored)
		o.observation.ready.Store(true)
		return *o.engine, applyError
	})
}

func (o *comparisonBackendOwner) install(configuration *conf.Config, uapi string) error {
	if o.ctx.Err() != nil {
		return o.ctx.Err()
	}
	if err := firewall.ReplaceFirewall(o.native.LUID(), !comparisonRestricts(configuration), configuration.Interface.DNS); err != nil {
		return err
	}
	watcher, err := watchInterface(o.gate, o.ctx)
	if err != nil {
		return err
	}
	*o.watcher = watcher
	binding := conn.NewDefaultBind()
	lease, err := o.relay.Open()
	if err != nil {
		return err
	}
	engine := device.NewDevice(lease, binding, device.NewLogger(device.LogLevelSilent, ""))
	*o.engine = engine
	if !engine.SetPrimaryMutationFence(func(work func() error) error {
		return o.gate.Primary(context.Background(), r013gate.Stamp{}, func(context.Context) error { return work() })
	}) {
		return errBackendUnknown
	}
	if err = engine.IpcSet(uapi); err != nil {
		return err
	}
	if err = engine.Up(); err != nil {
		return err
	}
	if err = watcher.ConfigureExisting(o.ctx, binding.(conn.BindSocketToInterface), configuration, o.native); err != nil {
		return err
	}
	copy, err := r013vault.CopyConfig(*configuration)
	if err != nil {
		return err
	}
	*o.configuration = &copy
	o.observation.config.Store(&copy)
	o.observation.watcher.Store(watcher)
	return nil
}
func comparisonRestricts(configuration *conf.Config) bool {
	if len(configuration.Peers) != 1 || configuration.Interface.TableOff {
		return false
	}
	for _, prefix := range configuration.Peers[0].AllowedIPs {
		if prefix.Cidr != 0 {
			continue
		}
		zero := true
		for _, b := range prefix.IP {
			if b != 0 {
				zero = false
			}
		}
		if zero {
			return true
		}
	}
	return false
}

// Only public native routing/interface facts are hashed, never configs/keys.
// Exclude only our TUN so internal handover events cannot hide foreign changes.
func comparisonForeignPath(own winipcfg.LUID) (string, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil || len(routes) > 8192 {
		return "", errBackendUnknown
	}
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil || len(addresses) > 8192 {
		return "", errBackendUnknown
	}
	var parts []string
	interfaces := make(map[winipcfg.LUID]bool)
	for _, row := range routes {
		if row.InterfaceLUID == own {
			continue
		}
		interfaces[row.InterfaceLUID] = true
		parts = append(parts, fmt.Sprintf("r:%d:%d:%s:%d:%s:%d", row.InterfaceLUID, row.InterfaceIndex, row.DestinationPrefix.Prefix.IP(), row.DestinationPrefix.PrefixLength, row.NextHop.IP(), row.Metric))
	}
	for _, row := range addresses {
		if row.InterfaceLUID == own {
			continue
		}
		interfaces[row.InterfaceLUID] = true
		parts = append(parts, fmt.Sprintf("a:%d:%s:%d:%d", row.InterfaceLUID, row.Address.IP(), row.OnLinkPrefixLength, row.DadState))
	}
	if len(interfaces) > 256 {
		return "", errBackendUnknown
	}
	for luid := range interfaces {
		row, err := luid.Interface()
		if err != nil {
			return "", errBackendUnknown
		}
		parts = append(parts, fmt.Sprintf("i:%d:%d:%d:%d", luid, row.InterfaceIndex, row.OperStatus, row.MTU))
		for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			network, err := luid.IPInterface(family)
			if err != nil {
				if errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
					parts = append(parts, fmt.Sprintf("missing:%d:%d", luid, family))
					continue
				}
				return "", errBackendUnknown
			}
			parts = append(parts, fmt.Sprintf("metric:%d:%d:%d:%d:%v", luid, family, network.Metric, network.NLMTU, network.UseAutomaticMetric))
		}
	}
	sort.Strings(parts)
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(digest[:]), nil
}

func comparisonRequestFresh(at time.Time) bool {
	age := time.Since(at)
	return !at.IsZero() && age >= 0 && age <= 15*time.Second
}
func (p *comparisonHealthProof) valid(index int, current r013gate.ConfirmedMember) bool {
	if p == nil || p.guard == nil || !comparisonRequestFresh(p.at) || !current.Valid() {
		return false
	}
	switch p.action {
	case r013.Retry:
		return index == current.Index && p.failures == 1 && p.latency == 0
	case r013.Advance:
		return index == (current.Index+1)%current.Count && ((p.failures == 2 && p.latency == 0) || (p.failures == 0 && p.latency > 1200*time.Millisecond))
	default:
		return false
	}
}
