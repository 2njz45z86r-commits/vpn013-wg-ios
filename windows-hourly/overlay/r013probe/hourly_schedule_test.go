// SPDX-License-Identifier: MIT
package awgprobe

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHourlyScheduleInitialDelaySingleFlightAndNoWakeCatchup(t *testing.T) {
	initial := time.Now()
	schedule := NewHourlySchedule(initial)
	if schedule.Delay(initial) != 30*time.Second || schedule.TryStart(initial.Add(29*time.Second)) {
		t.Fatal("initial scan before thirty seconds")
	}
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if schedule.TryStart(initial.Add(30 * time.Second)) {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatal("overlapping hourly scans accepted")
	}
	if schedule.TryStart(initial.Add(100 * 24 * time.Hour)) {
		t.Fatal("late wake overlapped active scan")
	}
	completed := initial.Add(100 * 24 * time.Hour)
	if !schedule.Finish(completed) || schedule.Delay(completed) != time.Hour {
		t.Fatal("late completion replayed missed hours")
	}
	if schedule.TryStart(completed.Add(59 * time.Minute)) {
		t.Fatal("hourly cadence shortened")
	}
	if !schedule.TryStart(completed.Add(time.Hour)) {
		t.Fatal("next full hour unavailable")
	}
	if !schedule.Finish(completed.Add(time.Hour + 90*time.Second)) {
		t.Fatal("bounded scan completion refused")
	}
	schedule.Close()
	if schedule.TryStart(completed.Add(1000*time.Hour)) || schedule.Finish(completed.Add(1000*time.Hour)) {
		t.Fatal("closed schedule resumed work")
	}
}
