// SPDX-License-Identifier: MIT
package r013gate

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc/namedpipe"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

const ObservationVersion = 2
const maxObservationBytes = 8192

type Observation struct {
	HealthOwned            bool             `json:"health_owned"`
	Comparing              bool             `json:"comparing"`
	LastComparisonUnixNano int64            `json:"last_comparison_unix_nano"`
	ComparedCount          int64            `json:"compared_count"`
	WorkerStartedUnixNano  int64            `json:"worker_started_unix_nano"`
	Version                uint32           `json:"version"`
	PID                    uint32           `json:"pid"`
	Name                   string           `json:"name"`
	Stamp                  Stamp            `json:"stamp"`
	Ready                  bool             `json:"ready"`
	Dirty                  bool             `json:"dirty"`
	Scripts                bool             `json:"scripts"`
	TunnelIndex            uint32           `json:"tunnel_index"`
	Physical4              uint32           `json:"physical4"`
	Physical6              uint32           `json:"physical6"`
	Identity               string           `json:"identity"`
	Member                 *ConfirmedMember `json:"member,omitempty"`
}

// ConfirmedMember exposes only the exact immutable vault/member digests. It
// carries no key or seed configuration; nil is explicitly unknown membership.
type ConfirmedMember struct {
	Generation uint64 `json:"generation"`
	Index      int    `json:"index"`
	Count      int    `json:"count"`
	Revision   string `json:"revision"`
	Digest     string `json:"digest"`
}

func (m ConfirmedMember) Valid() bool {
	if m.Generation == 0 || m.Count < 1 || m.Count > 30 || m.Index < 0 || m.Index >= m.Count {
		return false
	}
	for _, value := range []string{m.Revision, m.Digest} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 || strings.ToLower(value) != value {
			return false
		}
	}
	return true
}

func (o Observation) Validate(token Token, name string, pid uint32) error {
	if !token.Valid() || o.Version != ObservationVersion || o.Name != name || o.PID == 0 || o.PID != pid || o.Stamp != token.Stamp() || !o.Ready || o.Dirty || o.Scripts || o.TunnelIndex == 0 || o.Physical4 == 0 || o.TunnelIndex == o.Physical4 || o.TunnelIndex == o.Physical6 {
		return ErrUnavailable
	}
	digest, err := hex.DecodeString(o.Identity)
	if err != nil || len(digest) != 32 || strings.ToLower(o.Identity) != o.Identity {
		return ErrUnavailable
	}
	return nil
}

// PathObservationState is public path metadata, never a config. Notifications
// increment revision BEFORE epoch invalidation. Successful native work commits
// the captured revision; a notification racing that work remains dirty. A zero
// interface is an allowed primary reset but never a usable probe route.
type PathObservationState struct {
	revision  atomic.Uint64
	applied   atomic.Uint64
	index     atomic.Uint32
	committed atomic.Bool
	failed    atomic.Bool
}

func (s *PathObservationState) Changed() uint64  { return s.revision.Add(1) }
func (s *PathObservationState) Revision() uint64 { return s.revision.Load() }
func (s *PathObservationState) Commit(revision uint64, index uint32, err error) {
	if err != nil {
		s.failed.Store(true)
		s.committed.Store(false)
		s.index.Store(0)
		return
	}
	s.index.Store(index)
	s.applied.Store(revision)
	s.failed.Store(false)
	s.committed.Store(true)
}
func (s *PathObservationState) Snapshot() (index uint32, aligned bool) {
	before := s.revision.Load()
	index = s.index.Load()
	aligned = s.committed.Load() && !s.failed.Load() && s.applied.Load() == before && s.revision.Load() == before
	return
}

// ReadObservation is a read-only protected local pipe operation. The metadata
// is advisory outside a held Candidate lease; consumers must call Validate and
// recheck actual SCM membership/runtime while that concrete token remains live.
func ReadObservation(ctx context.Context, name string) (Observation, error) {
	var zero Observation
	if ctx == nil || ctx.Err() != nil || !conf.TunnelNameIsValid(name) {
		return zero, ErrUnavailable
	}
	bound, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	connection, err := namedpipe.DialContext(bound, `\\.\pipe\ProtectedPrefix\Administrators\VPN013WG\`+name)
	if err != nil {
		return zero, ErrUnavailable
	}
	defer connection.Close()
	deadline, _ := bound.Deadline()
	connection.SetDeadline(deadline)
	stop := context.AfterFunc(bound, func() { connection.Close() })
	defer stop()
	if _, err = connection.Write([]byte("r013_observe=1\n\n")); err != nil {
		return zero, ErrUnavailable
	}
	reader := bufio.NewReader(connection)
	line, err := boundedUAPILine(reader, maxObservationBytes)
	if err != nil || !strings.HasPrefix(line, "observation=") {
		return zero, ErrUnavailable
	}
	wire := strings.TrimSuffix(strings.TrimPrefix(line, "observation="), "\n")
	decoder := json.NewDecoder(strings.NewReader(wire))
	decoder.DisallowUnknownFields()
	var out Observation
	if decoder.Decode(&out) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return zero, ErrUnavailable
	}
	status, err := boundedUAPILine(reader, 64)
	if err != nil || status != "errno=0\n" {
		return zero, ErrUnavailable
	}
	end, err := boundedUAPILine(reader, 2)
	if err != nil || end != "\n" {
		return zero, ErrUnavailable
	}
	if out.Version != ObservationVersion {
		return zero, ErrUnavailable
	}
	return out, nil
}
