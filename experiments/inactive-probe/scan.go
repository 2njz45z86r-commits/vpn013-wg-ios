// SPDX-License-Identifier: MIT
package awgprobe

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

var ErrAutoInactive = errors.New("automatic selection is not active")
var ErrInvalidScan = errors.New("scan requires one through-tunnel resolver and 1-30 immutable candidate snapshots")
var ErrCandidateChanged = errors.New("selected candidate changed after measurement")

type ScanCandidate struct {
	ID string
	DNSRequest
}
type ScanRequest struct {
	AutoActive bool
	Current    CurrentDNSRequest
	Candidates []ScanCandidate
	StartIndex int
}
type CandidateMeasurement struct {
	ID     string
	Status string
	Result Result
}
type ScanResult struct {
	Before, After Result
	Measurements  []CandidateMeasurement
	Choice        *Choice
	Incomplete    bool
	NextIndex     int
}

// Choice retains only identifiers, timing and a local digest, not profile keys.
// It grants no switch permission until fresh profile data and epoch are checked.
type Choice struct {
	ID          string
	Measurement Result
	guard       *ActiveGuard
	fingerprint [32]byte
}

func candidateFingerprint(c ScanCandidate) [32]byte {
	return sha256.Sum256([]byte(c.Config + "\x00" + c.Source.String() + "\x00" + c.Target.String() + "\x00" + string([]byte{byte(c.Port >> 8), byte(c.Port)})))
}
func (c *Choice) BeginSwitch(ctx context.Context, fresh ScanCandidate) (*ActiveTransition, error) {
	if c == nil || c.guard == nil || fresh.Guard != c.guard || fresh.ID != c.ID || candidateFingerprint(fresh) != c.fingerprint {
		return nil, ErrCandidateChanged
	}
	if !c.guard.Accept(c.Measurement) {
		return nil, ErrStaleEpoch
	}
	return c.guard.BeginSwitch(ctx, c.Measurement.Epoch)
}

// Scan measures serially with one bounded candidate engine. The current VPN is
// never stopped here. It reserves time for a fresh current-path baseline AFTER
// testing candidates and only chooses a result faster than BOTH baselines.
// Total deadline90s, candidate deadline6s, at most30 candidates. If the budget
// ends early, NextIndex lets the platform rotate its next hourly starting point;
// missing measurements are not labeled dead servers. No timer or OS integration
// is claimed by this pure policy; the platform still owns an actual hourly run.
func Scan(parent context.Context, r ScanRequest) (ScanResult, error) {
	var out ScanResult
	if !r.AutoActive {
		return out, ErrAutoInactive
	}
	if len(r.Candidates) < 1 || len(r.Candidates) > 30 || r.StartIndex < 0 || r.StartIndex >= len(r.Candidates) || r.Current.Guard == nil {
		return out, ErrInvalidScan
	}
	seenIDs := make(map[string]bool)
	candidates := append([]ScanCandidate(nil), r.Candidates...)
	for _, c := range candidates {
		if c.ID == "" || len(c.ID) > 256 || strings.ContainsAny(c.ID, "\x00\r\n") || seenIDs[c.ID] || c.Guard != r.Current.Guard ||
			c.Target != r.Current.Target.Addr() || c.Port != r.Current.Target.Port() {
			return out, ErrInvalidScan
		}
		seenIDs[c.ID] = true
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	before, err := MeasureCurrentDNS(ctx, r.Current)
	if err != nil {
		return out, err
	}
	out.Before = before
	deadline, _ := ctx.Deadline()
	candidateDeadline := deadline.Add(-12 * time.Second)
	seenProbes := make(map[[32]byte]bool)
	var best *Choice
	for offset := 0; offset < len(candidates); offset++ {
		index := (r.StartIndex + offset) % len(candidates)
		out.NextIndex = index
		if !r.Current.Guard.Accept(before) {
			return out, ErrStaleEpoch
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if !time.Now().Before(candidateDeadline) {
			out.Incomplete = true
			break
		}
		out.NextIndex = (index + 1) % len(candidates)
		c := candidates[index]
		row := CandidateMeasurement{ID: c.ID}
		if validateProbeResources(c.Config) != nil {
			row.Status = "invalid_or_over_budget"
			out.Measurements = append(out.Measurements, row)
			continue
		}
		_, err := peerIdentity(c.Config)
		if err != nil {
			row.Status = "invalid_candidate"
			out.Measurements = append(out.Measurements, row)
			continue
		}
		fingerprint := candidateFingerprint(c)
		if seenProbes[fingerprint] {
			row.Status = "duplicate_snapshot_skipped"
			out.Measurements = append(out.Measurements, row)
			continue
		}
		// Distinct settings/endpoints for one INACTIVE identity remain separate
		// serial attempts. The guard still rejects every ACTIVE identity alias.
		seenProbes[fingerprint] = true
		candidateCtx, candidateCancel := context.WithDeadline(ctx, candidateDeadline)
		bounded, boundedCancel := context.WithTimeout(candidateCtx, 6*time.Second)
		value, err := MeasureDNS(bounded, c.DNSRequest)
		boundedCancel()
		candidateCancel()
		if !r.Current.Guard.Accept(before) {
			return out, ErrStaleEpoch
		}
		switch {
		case errors.Is(err, ErrActiveIdentity):
			row.Status = "active_identity_skipped"
		case err != nil:
			row.Status = "measurement_unavailable"
		case !Comparable(before, value):
			return out, ErrStaleEpoch
		default:
			row.Status = "measured"
			row.Result = value
			if value.Median < before.Median && (best == nil || value.Median < best.Measurement.Median) {
				best = &Choice{ID: c.ID, Measurement: value, guard: r.Current.Guard, fingerprint: candidateFingerprint(c)}
			}
		}
		out.Measurements = append(out.Measurements, row)
		out.NextIndex = (index + 1) % len(candidates)
	}
	after, err := MeasureCurrentDNS(ctx, r.Current)
	if err != nil {
		return out, err
	}
	out.After = after
	if !Comparable(before, after) || !r.Current.Guard.Accept(before) {
		return out, ErrStaleEpoch
	}
	if best != nil && Comparable(after, best.Measurement) && best.Measurement.Median < after.Median {
		out.Choice = best
	}
	return out, nil
}
