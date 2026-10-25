// SPDX-License-Identifier: MIT
// Package r013gate provides a Windows cross-process mutation barrier. It has no
// init side effects and is not yet wired into the shipped tunnel services.
package r013gate

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ErrUnavailable = errors.New("cross-process VPN barrier unavailable")
var ErrStale = errors.New("cross-process VPN generation changed")
var ErrAbandoned = errors.New("abandoned VPN barrier requires fresh observation")

const objectACL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
const mappingSize = 64
const mappingMagic uint64 = 0x3150524733313052
const productionName = `Global\VPN013-WG-Comparison-v1`

type Gate struct {
	mu             sync.Mutex
	mutex, mapping windows.Handle
	view           uintptr
	closed         bool
	root           context.Context
	cancel         context.CancelFunc
	active         sync.WaitGroup
	drainOnce      sync.Once
	drained        chan struct{}
	disposeMu      sync.Mutex
}

// Open must precede privilege dropping. The production coordinator belongs in
// SYSTEM services, not the unprivileged GUI. No credential or key is mapped.
func Open() (*Gate, error) { return openNamed(productionName) }

func verifyACL(handle windows.Handle, fullAccess uint32) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("%w: reading kernel DACL: %v", ErrUnavailable, err)
	}
	// Windows maps GENERIC_ALL into the kernel object's specific mask. Preserve
	// the same protected two-trustee DACL; do not accept additional ACEs/SIDs.
	expected := fmt.Sprintf("D:P(A;;0x%x;;;SY)(A;;0x%x;;;BA)", fullAccess, fullAccess)
	if sd.String() != objectACL && sd.String() != expected {
		return fmt.Errorf("%w: kernel DACL differs: %s", ErrUnavailable, sd.String())
	}
	return nil
}

func openNamed(name string) (*Gate, error) {
	if len(name) > 180 || !(strings.HasPrefix(name, `Global\`) || strings.HasPrefix(name, `Local\`)) {
		return nil, ErrUnavailable
	}
	sd, err := windows.SecurityDescriptorFromString(objectACL)
	if err != nil {
		return nil, ErrUnavailable
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	mutexName, err := windows.UTF16PtrFromString(name + "-mutex")
	if err != nil {
		return nil, ErrUnavailable
	}
	mutex, err := windows.CreateMutex(&sa, false, mutexName)
	if mutex == 0 || err != nil && err != windows.ERROR_ALREADY_EXISTS {
		if mutex != 0 {
			windows.CloseHandle(mutex)
		}
		return nil, ErrUnavailable
	}
	fail := func() { windows.CloseHandle(mutex) }
	if aclErr := verifyACL(mutex, windows.MUTEX_ALL_ACCESS); aclErr != nil {
		fail()
		return nil, aclErr
	}
	mapName, err := windows.UTF16PtrFromString(name + "-epoch")
	if err != nil {
		fail()
		return nil, ErrUnavailable
	}
	mapping, err := windows.CreateFileMapping(windows.InvalidHandle, &sa, windows.PAGE_READWRITE, 0, mappingSize, mapName)
	runtime.KeepAlive(sd)
	if mapping == 0 || err != nil && err != windows.ERROR_ALREADY_EXISTS {
		if mapping != 0 {
			windows.CloseHandle(mapping)
		}
		fail()
		return nil, ErrUnavailable
	}
	if aclErr := verifyACL(mapping, windows.FILE_MAP_ALL_ACCESS); aclErr != nil {
		windows.CloseHandle(mapping)
		fail()
		return nil, aclErr
	}
	view, err := windows.MapViewOfFile(mapping, windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, mappingSize)
	if err != nil {
		windows.CloseHandle(mapping)
		fail()
		return nil, ErrUnavailable
	}
	magic := (*uint64)(unsafe.Pointer(view))
	atomic.CompareAndSwapUint64(magic, 0, mappingMagic)
	if atomic.LoadUint64(magic) != mappingMagic {
		windows.UnmapViewOfFile(view)
		windows.CloseHandle(mapping)
		fail()
		return nil, ErrUnavailable
	}
	epoch := (*uint64)(unsafe.Pointer(view + 8))
	atomic.CompareAndSwapUint64(epoch, 0, 1)
	instance := (*uint64)(unsafe.Pointer(view + 16))
	if atomic.LoadUint64(instance) == 0 {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			windows.UnmapViewOfFile(view)
			windows.CloseHandle(mapping)
			fail()
			return nil, ErrUnavailable
		}
		value := binary.LittleEndian.Uint64(random[:])
		if value == 0 {
			value = 1
		}
		atomic.CompareAndSwapUint64(instance, 0, value)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Gate{mutex: mutex, mapping: mapping, view: view, root: ctx, cancel: cancel, drained: make(chan struct{})}, nil
}

// Current is public generation data only. Access to mapped memory is also
// fenced against Close; a Token escaping its work function cannot read freed
// memory, even if its caller races cancellation and shutdown.
// Instance prevents generation ABA when every service/manager has exited and
// Windows has destroyed the previous mapping. It is public, not an auth token.
type Stamp struct{ Instance, Epoch uint64 }

func (g *Gate) Current() Stamp {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.view == 0 {
		return Stamp{}
	}
	return Stamp{atomic.LoadUint64((*uint64)(unsafe.Pointer(g.view + 16))), atomic.LoadUint64((*uint64)(unsafe.Pointer(g.view + 8)))}
}

// Abandonment persists in shared memory until an explicit, successful primary
// observation/mutation recovers it. Releasing WAIT_ABANDONED alone must not
// let the second candidate trust the previous crashed process's state.
func (g *Gate) poisoned(write *uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.view == 0 {
		return true
	}
	flag := (*uint64)(unsafe.Pointer(g.view + 24))
	if write != nil {
		atomic.StoreUint64(flag, *write)
	}
	return atomic.LoadUint64(flag) != 0
}
func (g *Gate) bump(expected Stamp) Stamp {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.view == 0 {
		return Stamp{}
	}
	epoch := (*uint64)(unsafe.Pointer(g.view + 8))
	instance := atomic.LoadUint64((*uint64)(unsafe.Pointer(g.view + 16)))
	if expected != (Stamp{}) {
		if expected.Instance != instance || expected.Epoch == 0 || expected.Epoch == ^uint64(0) || !atomic.CompareAndSwapUint64(epoch, expected.Epoch, expected.Epoch+1) {
			return Stamp{}
		}
		return Stamp{instance, expected.Epoch + 1}
	}
	return Stamp{instance, atomic.AddUint64(epoch, 1)}
}
func (g *Gate) enter(parent context.Context) (context.Context, func(), error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, ErrUnavailable
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	g.active.Add(1)
	g.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(g.root, cancel)
	return ctx, func() { stop(); cancel(); g.active.Done() }, nil
}

// All Windows mutex wait/release pairs MUST remain on the same OS thread.
// Primary requests bump the shared generation before waiting, and again on
// every bounded wait. A later request cannot be lost through event resets.
func (g *Gate) wait(ctx context.Context, pending func() error) (bool, error) {
	for {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		state, err := windows.WaitForSingleObject(g.mutex, 20)
		if err != nil {
			return false, ErrUnavailable
		}
		switch state {
		case windows.WAIT_OBJECT_0, windows.WAIT_ABANDONED:
			if ctx.Err() != nil {
				windows.ReleaseMutex(g.mutex)
				return false, ctx.Err()
			}
			return state == windows.WAIT_ABANDONED, nil
		case uint32(windows.WAIT_TIMEOUT):
			if pending != nil {
				if err := pending(); err != nil {
					return false, err
				}
			}
		default:
			return false, ErrUnavailable
		}
	}
}

type Token struct {
	gate  *Gate
	stamp Stamp
	ctx   context.Context
}

func (t Token) Stamp() Stamp { return t.stamp }
func (t Token) Valid() bool {
	return t.gate != nil && t.ctx != nil && t.ctx.Err() == nil && t.stamp.Epoch != 0 && t.gate.Current() == t.stamp
}

// Candidate holds the kernel barrier until work has returned. The work MUST
// close and actually drain every candidate/current UDP callback before return,
// including cancellation/errors. A timeout is never permission to fake that
// acknowledgement. Integration will register the proven transport's closers.
// Process death closes its descriptors and abandons the kernel mutex; the next
// candidate refuses abandoned state instead of trusting a saved identity.
func (g *Gate) Candidate(parent context.Context, work func(context.Context, Token) error) error {
	if work == nil {
		return ErrUnavailable
	}
	ctx, end, err := g.enter(parent)
	if err != nil {
		return err
	}
	defer end()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	abandoned, err := g.wait(ctx, nil)
	if err != nil {
		return err
	}
	defer windows.ReleaseMutex(g.mutex)
	if abandoned {
		one := uint64(1)
		g.poisoned(&one)
		g.bump(Stamp{})
		return ErrAbandoned
	}
	if g.poisoned(nil) {
		return ErrAbandoned
	}
	epoch := g.Current()
	if epoch.Epoch == 0 {
		return ErrUnavailable
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTicker(10 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if g.Current() != epoch {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	err = work(ctx, Token{g, epoch, ctx})
	return err
}

// Primary fences real service/route/UAPI mutations. An empty Stamp means an
// explicit ordinary mutation; nonzero is a one-shot measured-generation check.
// Failed/cancelled requests still invalidate prior measurements conservatively.
// Native lifecycle wiring and observed actual identity are separate requirements.
func (g *Gate) Primary(parent context.Context, expected Stamp, work func(context.Context) error) error {
	if work == nil {
		return ErrUnavailable
	}
	ctx, end, err := g.enter(parent)
	if err != nil {
		return err
	}
	defer end()
	mine := g.bump(expected)
	if mine.Epoch == 0 {
		return ErrStale
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	abandoned, err := g.wait(ctx, func() error {
		if expected != (Stamp{}) {
			mine = g.bump(mine)
		} else {
			mine = g.bump(Stamp{})
		}
		if mine.Epoch == 0 {
			return ErrStale
		}
		return nil
	})
	if err != nil {
		return err
	}
	defer windows.ReleaseMutex(g.mutex)
	defer g.bump(Stamp{})
	if abandoned {
		one := uint64(1)
		g.poisoned(&one)
	}
	if abandoned && expected != (Stamp{}) {
		return ErrAbandoned
	}
	if expected != (Stamp{}) && g.Current() != mine {
		return ErrStale
	}
	if expected != (Stamp{}) && g.poisoned(nil) {
		return ErrAbandoned
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	err = work(ctx)
	if err == nil && ctx.Err() == nil && expected == (Stamp{}) {
		zero := uint64(0)
		g.poisoned(&zero)
	}
	return err
}

// A failed Close retains kernel objects/mapping until real work returns. It is
// retryable and never reports an acknowledged drain while a worker owns UDP.
func (g *Gate) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrUnavailable
	}
	g.mu.Lock()
	if !g.closed && g.view != 0 {
		atomic.AddUint64((*uint64)(unsafe.Pointer(g.view+8)), 1)
	}
	g.closed = true
	g.cancel()
	g.mu.Unlock()
	g.drainOnce.Do(func() { go func() { g.active.Wait(); close(g.drained) }() })
	select {
	case <-g.drained:
	case <-ctx.Done():
		return ctx.Err()
	}
	g.disposeMu.Lock()
	defer g.disposeMu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.view != 0 {
		if windows.UnmapViewOfFile(g.view) != nil {
			return ErrUnavailable
		}
		g.view = 0
	}
	if g.mutex != 0 {
		if windows.CloseHandle(g.mutex) != nil {
			return ErrUnavailable
		}
		g.mutex = 0
	}
	if g.mapping != 0 {
		if windows.CloseHandle(g.mapping) != nil {
			return ErrUnavailable
		}
		g.mapping = 0
	}
	return nil
}
