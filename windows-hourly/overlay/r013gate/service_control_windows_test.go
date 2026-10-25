// SPDX-License-Identifier: MIT
package r013gate

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestSCMStopInvalidatesWithoutWaitingForBusyOwnerOrRequestQueue(t *testing.T) {
	requireCI(t)
	for _, kind := range []string{"stop", "shutdown", "closed-input"} {
		t.Run(kind, func(t *testing.T) {
			g := testGate(t, testName(t))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			input := make(chan svc.ChangeRequest)
			var callbacks atomic.Uint32
			control, e := NewServiceControl(ctx, g, input, func() { callbacks.Add(1) })
			if e != nil {
				t.Fatal(e)
			}
			defer control.Close(context.Background())
			// The owner intentionally does not consume Requests. Repeated harmless
			// interrogates cannot queue unbounded work ahead of a stop request.
			for i := 0; i < 100; i++ {
				input <- svc.ChangeRequest{Cmd: svc.Interrogate}
			}
			if len(control.requests) > 1 {
				t.Fatal("unbounded control queue")
			}
			before := g.Current()
			if kind == "closed-input" {
				close(input)
			} else {
				cmd := svc.Stop
				if kind == "shutdown" {
					cmd = svc.Shutdown
				}
				input <- svc.ChangeRequest{Cmd: cmd}
			}
			select {
			case <-control.StopRequested():
			case <-ctx.Done():
				t.Fatal("busy owner delayed stop invalidation")
			}
			if !control.Stopped() || callbacks.Load() != 1 || g.Current() == before {
				t.Fatal("stop did not invalidate exactly once")
			}
			if e = control.Close(ctx); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestSCMForwarderCloseDrainsIdleWorkerWithoutInventedStop(t *testing.T) {
	requireCI(t)
	g := testGate(t, testName(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	input := make(chan svc.ChangeRequest)
	var callbacks atomic.Uint32
	control, e := NewServiceControl(ctx, g, input, func() { callbacks.Add(1) })
	if e != nil {
		t.Fatal(e)
	}
	before := g.Current()
	if e = control.Close(ctx); e != nil {
		t.Fatal(e)
	}
	if control.Stopped() || callbacks.Load() != 0 || g.Current() != before {
		t.Fatal("ordinary owner cleanup invented an SCM stop")
	}
	if e = control.Close(ctx); e != nil {
		t.Fatal(e)
	}
}
