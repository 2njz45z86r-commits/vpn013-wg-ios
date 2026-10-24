// SPDX-License-Identifier: MIT
package awgprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
)

var ErrControllerBusy = errors.New("probe controller is changing or already measuring")
var ErrControllerClosed = errors.New("probe controller is closed")
var ErrInvalidHandle = errors.New("invalid controller operation or transition")

const MaxScanJSON = 4 * 1024 * 1024

// Snapshot is a memory-only, already-resolved UAPI snapshot. Its Config MUST
// NOT be logged, returned in results, or persisted by this subsystem.
type Snapshot struct {
	ID     string `json:"id"`
	Config string `json:"config"`
	Source string `json:"source"`
}
type ScanInput struct {
	AutoActive bool       `json:"auto_active"`
	Resolver   string     `json:"resolver"`
	StartIndex int        `json:"start_index"`
	Candidates []Snapshot `json:"candidates"`
}

func DecodeScanInput(wire []byte) (ScanInput, error) {
	var in ScanInput
	if len(wire) == 0 || len(wire) > MaxScanJSON {
		return in, ErrInvalidScan
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		return ScanInput{}, ErrInvalidScan
	}
	if validateInput(in) != nil {
		return ScanInput{}, ErrInvalidScan
	}
	return in, nil
}

func validateInput(in ScanInput) error {
	if !in.AutoActive {
		return ErrAutoInactive
	}
	resolver, err := netip.ParseAddrPort(in.Resolver)
	if err != nil || !resolver.Addr().Is4() || resolver.Addr().IsUnspecified() || resolver.Port() == 0 ||
		len(in.Candidates) < 1 || len(in.Candidates) > 30 || in.StartIndex < 0 || in.StartIndex >= len(in.Candidates) {
		return ErrInvalidScan
	}
	ids := make(map[string]bool)
	for _, s := range in.Candidates {
		if s.ID == "" || len(s.ID) > 256 || strings.ContainsAny(s.ID, "\x00\r\n") || ids[s.ID] || len(s.Config) == 0 || len(s.Config) > 64*1024 {
			return ErrInvalidScan
		}
		ids[s.ID] = true
		if _, err := snapshotEndpoint(s); err != nil {
			return err
		}
	}
	return nil
}

// No resolver, endpoint rewriting, or default socket is hidden in the bridge.
func snapshotEndpoint(s Snapshot) (netip.AddrPort, error) {
	var endpoint netip.AddrPort
	source, err := netip.ParseAddr(s.Source)
	if err != nil || !source.Is4() || source.IsUnspecified() {
		return endpoint, ErrInvalidScan
	}
	for _, line := range strings.Split(s.Config, "\n") {
		if strings.HasPrefix(line, "endpoint=") {
			if endpoint.IsValid() {
				return netip.AddrPort{}, ErrInvalidScan
			}
			endpoint, err = netip.ParseAddrPort(strings.TrimPrefix(line, "endpoint="))
			if err != nil || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().Zone() != "" {
				return netip.AddrPort{}, ErrInvalidScan
			}
		}
	}
	if !endpoint.IsValid() {
		return endpoint, ErrInvalidScan
	}
	return endpoint, nil
}

type Metric struct {
	Milliseconds float64 `json:"milliseconds"`
	Samples      int     `json:"samples"`
	Epoch        uint64  `json:"epoch"`
	Method       string  `json:"method"`
	Target       string  `json:"target"`
}
type ScanRow struct {
	ID     string  `json:"id"`
	Status string  `json:"status"`
	Metric *Metric `json:"metric,omitempty"`
}
type ScanStatus struct {
	Status     string    `json:"status"`
	Before     *Metric   `json:"before,omitempty"`
	After      *Metric   `json:"after,omitempty"`
	Rows       []ScanRow `json:"rows,omitempty"`
	ChoiceID   string    `json:"choice_id,omitempty"`
	Incomplete bool      `json:"incomplete"`
	NextIndex  int       `json:"next_index"`
}

func metric(r Result) *Metric {
	if r.Samples != 3 || r.Method == "" {
		return nil
	}
	return &Metric{float64(r.Median) / 1e6, r.Samples, r.Epoch, r.Method, r.Target.String()}
}

type controllerOperation struct {
	id     uint64
	cancel context.CancelFunc
	done   chan struct{}
	ready  bool
	status ScanStatus
	choice *Choice
}

// Controller owns ONE guard, ONE bounded scan and at most ONE transition. It
// starts unknown. Lifecycle changes must begin/drain BEFORE touching the real
// adapter and commit only the actual applied identity afterward. A drain error
// is never permission to mutate the primary engine. All calls are thread-safe.
type Controller struct {
	mu       sync.Mutex
	guard    *ActiveGuard
	physical PhysicalUDPFactory
	current  TunnelUDPFactory
	next     uint64
	closed   bool
	changing bool
	changeID uint64
	change   *ActiveTransition
	op       *controllerOperation
}

func NewController(physical PhysicalUDPFactory, current TunnelUDPFactory) (*Controller, error) {
	guard, _ := NewActiveGuard(ActiveState{})
	return NewControllerWithGuard(physical, current, guard)
}

// Native controllers in one extension share the process primary guard. A new
// provider/controller cannot forget the identity or live probes of its predecessor.
func NewControllerWithGuard(physical PhysicalUDPFactory, current TunnelUDPFactory, guard *ActiveGuard) (*Controller, error) {
	if physical == nil || current == nil || guard == nil {
		return nil, ErrPhysicalTransport
	}
	return &Controller{guard: guard, physical: physical, current: current}, nil
}

// TransferChange moves a drained choice permit into the native primary gate.
// The old controller token becomes unusable immediately. Close/new scans remain
// blocked until the returned one-shot completion commits actual state.
func (c *Controller) TransferChange(id uint64) (func(ActiveState) error, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.change == nil || id == 0 || id != c.changeID {
		return nil, ErrInvalidHandle
	}
	tr := c.change
	c.change, c.changeID = nil, 0
	var once sync.Once
	return func(actual ActiveState) error {
		err := ErrClosedTransition
		once.Do(func() {
			err = tr.Commit(actual)
			c.mu.Lock()
			c.changing = false
			c.mu.Unlock()
		})
		return err
	}, nil
}

func (c *Controller) BeginChange(ctx context.Context) (uint64, error) {
	return c.begin(ctx, nil, Snapshot{}, "")
}

func (c *Controller) begin(ctx context.Context, choice *Choice, fresh Snapshot, resolver string) (uint64, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ErrControllerClosed
	}
	if c.changing {
		c.mu.Unlock()
		return 0, ErrControllerBusy
	}
	c.changing = true
	if c.op != nil {
		c.op.cancel()
		c.op.choice = nil
	}
	c.mu.Unlock()
	var tr *ActiveTransition
	var err error
	if choice == nil {
		tr, err = c.guard.BeginTransition(ctx)
	} else {
		var candidate ScanCandidate
		candidate, err = c.candidate(fresh, resolver)
		if err == nil {
			tr, err = choice.BeginSwitch(ctx, candidate)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.changing = false
		return 0, err
	}
	c.next++
	c.changeID, c.change = c.next, tr
	return c.changeID, nil
}

func (c *Controller) CommitChange(id uint64, state ActiveState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.change == nil || id == 0 || id != c.changeID {
		return ErrInvalidHandle
	}
	// Parse failure leaves unknown; it NEVER restores the pre-change snapshot.
	err := c.change.Commit(state)
	c.change, c.changeID, c.changing = nil, 0, false
	return err
}

func (c *Controller) candidate(s Snapshot, resolver string) (ScanCandidate, error) {
	endpoint, err := snapshotEndpoint(s)
	if err != nil {
		return ScanCandidate{}, err
	}
	target, err := netip.ParseAddrPort(resolver)
	if err != nil || !target.Addr().Is4() || target.Port() == 0 {
		return ScanCandidate{}, ErrInvalidScan
	}
	bind, err := NewPhysicalBind(endpoint, c.physical)
	if err != nil {
		return ScanCandidate{}, err
	}
	return ScanCandidate{ID: s.ID, DNSRequest: DNSRequest{Request: Request{
		Config: s.Config, Source: netip.MustParseAddr(s.Source), Target: target.Addr(), Bind: bind, Guard: c.guard,
	}, Port: target.Port()}}, nil
}

func (c *Controller) StartScan(in ScanInput) (uint64, error) {
	if err := validateInput(in); err != nil {
		return 0, err
	}
	request := ScanRequest{AutoActive: in.AutoActive, StartIndex: in.StartIndex,
		Current: CurrentDNSRequest{Target: netip.MustParseAddrPort(in.Resolver), Factory: c.current, Guard: c.guard}}
	for _, s := range in.Candidates {
		candidate, err := c.candidate(s, in.Resolver)
		if err != nil {
			return 0, err
		}
		request.Candidates = append(request.Candidates, candidate)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, ErrControllerClosed
	}
	if c.changing || c.op != nil && !c.op.ready {
		return 0, ErrControllerBusy
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.next++
	op := &controllerOperation{id: c.next, cancel: cancel, done: make(chan struct{}), status: ScanStatus{Status: "pending"}}
	c.op = op
	go func() {
		out, err := Scan(ctx, request)
		// Drop raw configuration references as soon as this bounded run ends.
		request.Candidates = nil
		c.mu.Lock()
		defer c.mu.Unlock()
		op.ready = true
		switch {
		case ctx.Err() != nil:
			op.status = ScanStatus{Status: "cancelled"}
		case err != nil || !c.guard.Accept(out.Before) || !c.guard.Accept(out.After):
			op.status = ScanStatus{Status: "unavailable"}
		default:
			op.status = ScanStatus{Status: "complete", Before: metric(out.Before), After: metric(out.After), Incomplete: out.Incomplete, NextIndex: out.NextIndex}
			for _, row := range out.Measurements {
				op.status.Rows = append(op.status.Rows, ScanRow{row.ID, row.Status, metric(row.Result)})
			}
			op.choice = out.Choice
			if op.choice != nil {
				op.status.ChoiceID = op.choice.ID
			}
		}
		cancel()
		close(op.done)
	}()
	return op.id, nil
}

func (c *Controller) PollScan(id uint64) (ScanStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.op == nil || id != c.op.id {
		return ScanStatus{}, ErrInvalidHandle
	}
	status := c.op.status
	if status.Status == "complete" && (c.changing || status.Before == nil || !c.guard.Accept(Result{Epoch: status.Before.Epoch, Samples: status.Before.Samples})) {
		return ScanStatus{Status: "stale"}, nil
	}
	// No caller can mutate the retained result through an exported slice/pointer.
	wire, _ := json.Marshal(status)
	var owned ScanStatus
	_ = json.Unmarshal(wire, &owned)
	return owned, nil
}

func (c *Controller) CancelScan(ctx context.Context, id uint64) error {
	c.mu.Lock()
	if c.op == nil || c.op.id != id {
		c.mu.Unlock()
		return ErrInvalidHandle
	}
	op := c.op
	op.cancel()
	op.choice = nil
	if op.ready {
		op.status = ScanStatus{Status: "cancelled"}
	}
	c.mu.Unlock()
	select {
	case <-op.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Controller) BeginChoice(ctx context.Context, id uint64, fresh Snapshot, resolver string) (uint64, error) {
	c.mu.Lock()
	if c.op == nil || id != c.op.id || !c.op.ready || c.op.choice == nil {
		c.mu.Unlock()
		return 0, ErrInvalidHandle
	}
	choice := c.op.choice
	c.op.choice = nil // One-shot even on an edited or stale snapshot.
	c.mu.Unlock()
	return c.begin(ctx, choice, fresh, resolver)
}

// Close disables this controller only after a real drain. Failure is retryable
// and retains ownership; it never reports success or forgets a live UDP socket.
func (c *Controller) Close(ctx context.Context) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil
	}
	id, err := c.BeginChange(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if id != c.changeID {
		return ErrInvalidHandle
	}
	if err := c.change.Abort(); err != nil {
		return err
	}
	c.change, c.changeID, c.changing = nil, 0, false
	c.closed = true
	if c.op != nil {
		c.op.choice = nil
	}
	return nil
}
