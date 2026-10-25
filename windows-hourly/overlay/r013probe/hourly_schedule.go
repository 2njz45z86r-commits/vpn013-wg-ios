// SPDX-License-Identifier: MIT
package awgprobe

import (
	"sync"
	"time"
)

// HourlySchedule owns only cadence, never a socket or primary connection.
// time.Time values from time.Now retain Go's monotonic clock. A late wakeup
// starts ONE scan; completion schedules the next hour from that completion,
// rather than replaying every missed period after sleep or a long scan.
type HourlySchedule struct {
	mu           sync.Mutex
	due          time.Time
	busy, closed bool
}

func NewHourlySchedule(now time.Time) *HourlySchedule {
	return &HourlySchedule{due: now.Add(30 * time.Second)}
}
func (s *HourlySchedule) Delay(now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.busy {
		return time.Hour
	}
	delay := s.due.Sub(now)
	if delay < 0 {
		return 0
	}
	return delay
}
func (s *HourlySchedule) TryStart(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.busy || now.Before(s.due) {
		return false
	}
	s.busy = true
	return true
}
func (s *HourlySchedule) Finish(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.busy {
		return false
	}
	s.busy = false
	s.due = now.Add(time.Hour)
	return true
}
func (s *HourlySchedule) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true }
