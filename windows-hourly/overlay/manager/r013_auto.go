// SPDX-License-Identifier: MIT
package manager

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013prepare"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013vault"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"github.com/amnezia-vpn/amneziawg-windows/v3/services"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// The actual tunnel service owns health AND hourly choices. Manager supervision
// is read-only: it never stops/restarts a connected Auto after stale health data.
var autoControl sync.Mutex
var autoRun *autoSession
var saveR013Config = func(c *conf.Config, overwrite bool) error { return c.Save(overwrite) }
var stateR013Tunnel = actualR013TunnelState
var startR013Tunnel = func(s *ManagerService, name string) error { return s.startTunnel(name) }
var superviseR013Auto = launchAutoSupervision
var validateStoppedR013Auto = validateStoppedAutoWorking

type autoSession struct {
	cancel    context.CancelFunc
	done      chan struct{}
	confirmed atomic.Pointer[r013gate.ConfirmedMember]
}

func actualR013TunnelState(_ *ManagerService, name string) (TunnelState, error) {
	serviceName, err := services.ServiceNameOfTunnel(name)
	if err != nil {
		return TunnelUnknown, err
	}
	manager, err := serviceManager()
	if err != nil {
		return TunnelUnknown, err
	}
	service, err := manager.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return TunnelStopped, nil
	}
	if err != nil {
		return TunnelUnknown, err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return TunnelUnknown, err
	}
	switch status.State {
	case svc.Stopped:
		return TunnelStopped, nil
	case svc.Running:
		return TunnelStarted, nil
	case svc.StartPending:
		return TunnelStarting, nil
	case svc.StopPending:
		return TunnelStopping, nil
	default:
		return TunnelUnknown, r013gate.ErrUnavailable
	}
}
func resumeR013Auto() {
	autoControl.Lock()
	defer autoControl.Unlock()
	pruneAutoSession()
	if autoRun != nil {
		return
	}
	service := &ManagerService{}
	state, err := stateR013Tunnel(service, r013.AutoName)
	if err != nil || state != TunnelStarted {
		return
	}
	superviseR013Auto(service)
}
func launchAutoSupervision(service *ManagerService) {
	ctx, cancel := context.WithCancel(context.Background())
	run := &autoSession{cancel: cancel, done: make(chan struct{})}
	autoRun = run
	go func() { defer close(run.done); service.runAuto(ctx, run) }()
}
func stopAuto() {
	if autoRun != nil {
		autoRun.cancel()
		<-autoRun.done
		autoRun = nil
	}
}
func autoPath() (string, error) {
	root, err := conf.RootDirectory(true)
	return filepath.Join(root, "r013-auto.dat"), err
}
func loadAuto() ([]conf.Config, error) {
	snapshot, err := r013vault.Load()
	if err != nil {
		return nil, err
	}
	result := make([]conf.Config, 0, snapshot.Count())
	for i := 0; i < snapshot.Count(); i++ {
		member, _, e := snapshot.Member(i)
		if e != nil {
			return nil, e
		}
		result = append(result, member)
	}
	return result, nil
}
func (s *ManagerService) CreateAuto(configs []conf.Config) error {
	if s.elevatedToken == 0 {
		return windows.ERROR_ACCESS_DENIED
	}
	if err := r013.ValidateCandidates(configs); err != nil {
		return err
	}
	autoControl.Lock()
	defer autoControl.Unlock()
	pruneAutoSession()
	if autoRun != nil {
		return errors.New("Отключите Авто перед обновлением его состава.")
	}
	state, err := stateR013Tunnel(s, r013.AutoName)
	if err != nil {
		return err
	}
	if state != TunnelStopped {
		return errors.New("Отключите Авто перед обновлением его состава.")
	}
	file, err := autoPath()
	if err != nil {
		return err
	}
	old, oldErr := os.ReadFile(file)
	if _, err := conf.LoadFromName(r013.AutoName); err == nil && oldErr != nil {
		return errors.New("Имя R013-Auto занято обычной конфигурацией. Переименуйте её.")
	}
	contents, err := json.Marshal(configs)
	if err != nil {
		return err
	}
	encrypted, err := dpapi.Encrypt(contents, "VPN013-Auto-v1")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(file), ".r013-auto-*.pending")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err = temp.Write(encrypted); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	temp.Close()
	from, _ := windows.UTF16PtrFromString(name)
	to, _ := windows.UTF16PtrFromString(file)
	if err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	first := configs[0]
	first.Name = r013.AutoName
	if err = saveR013Config(&first, true); err != nil {
		if oldErr == nil {
			os.WriteFile(file, old, 0600)
		} else {
			os.Remove(file)
		}
		return err
	}
	IPCServerNotifyTunnelsChange()
	return nil
}
func (s *ManagerService) Start(name string) error {
	if r013Applying.Load() {
		return errors.New("Устанавливается обновление приложения. Дождитесь перезапуска.")
	}
	autoControl.Lock()
	defer autoControl.Unlock()
	if r013Applying.Load() {
		return errors.New("Устанавливается обновление приложения. Дождитесь перезапуска.")
	}
	stopAuto()
	if name != r013.AutoName {
		return startR013Tunnel(s, name)
	}
	state, err := stateR013Tunnel(s, name)
	if err != nil {
		return err
	}
	// Only a genuinely stopped Auto can be started. Its working seed must match
	// one FULL immutable vault member; no fallback to member zero or key pair.
	if state == TunnelStopped {
		if e := validateStoppedR013Auto(); e != nil {
			return e
		}
		if e := startR013Tunnel(s, name); e != nil {
			return e
		}
	} else if state != TunnelStarted && state != TunnelStarting {
		return errors.New("Состояние Авто пока не подтверждено. Дождитесь завершения подключения или отключения.")
	}
	superviseR013Auto(s)
	return nil
}
func (s *ManagerService) Stop(name string) error {
	autoControl.Lock()
	defer autoControl.Unlock()
	if name == r013.AutoName {
		stopAuto()
	}
	return s.stopTunnel(name)
}
func sleepAuto(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func confirmedAutoMember(actual r013gate.PrimarySnapshot, snapshot r013vault.Snapshot) (r013gate.ConfirmedMember, error) {
	observation := actual.Observation
	if observation.Version != r013gate.ObservationVersion || !observation.Ready || observation.Dirty || !observation.HealthOwned || observation.Member == nil || !observation.Member.Valid() {
		return r013gate.ConfirmedMember{}, r013gate.ErrUnavailable
	}
	state := *observation.Member
	member, digest, err := snapshot.Member(state.Index)
	if err != nil || state.Count != snapshot.Count() || state.Revision != snapshot.Revision() || state.Digest != digest {
		return r013gate.ConfirmedMember{}, r013gate.ErrUnavailable
	}
	// Same identity is necessary but not sufficient: exact settings above are
	// independently tied to the service's confirmed vault revision/member digest.
	identity, err := r013prepare.Identity(member)
	if err != nil || identity != observation.Identity {
		return r013gate.ConfirmedMember{}, r013gate.ErrUnavailable
	}
	return state, nil
}
func (s *ManagerService) runAuto(ctx context.Context, run *autoSession) {
	executable, err := os.Executable()
	if err != nil {
		return
	}
	image, err := r013gate.ExecutableDigest(executable)
	if err != nil {
		return
	}
	gate, err := r013gate.Open()
	if err != nil {
		return
	}
	defer gate.Close(context.Background())
	for ctx.Err() == nil {
		state, e := stateR013Tunnel(s, r013.AutoName)
		if e == nil && state == TunnelStopped {
			run.confirmed.Store(nil)
			return
		}
		if e == nil && state == TunnelStarted {
			work, cancel := context.WithTimeout(ctx, 3*time.Second)
			_ = gate.Candidate(work, func(held context.Context, token r013gate.Token) error {
				actual, e := r013gate.InspectPrimary(held, token, image, r013.AutoName)
				if e != nil {
					return e
				}
				snapshot, e := r013vault.Load()
				if e != nil {
					return e
				}
				member, e := confirmedAutoMember(actual, snapshot)
				if e != nil {
					return e
				}
				if !token.Valid() || ctx.Err() != nil {
					return r013gate.ErrStale
				}
				copy := member
				run.confirmed.Store(&copy)
				return nil
			})
			cancel()
		}
		// Unknown/old/multiple/temporary pipe failures are never converted into an
		// unconditional SCM stop or saved seed restart. Explicit manual Stop wins.
		if !sleepAuto(ctx, 15*time.Second) {
			return
		}
	}
}

// Called only with autoControl held. Never lock from a goroutine whose done
// channel Stop is currently waiting for under that same mutex.
func pruneAutoSession() {
	if autoRun != nil {
		select {
		case <-autoRun.done:
			autoRun = nil
		default:
		}
	}
}

func validateStoppedAutoWorking() error {
	snapshot, e := r013vault.Load()
	if e != nil {
		return errors.New("Не удалось проверить состав Авто. Прежние профили сохранены.")
	}
	seed, e := conf.LoadFromName(r013.AutoName)
	if e != nil {
		return e
	}
	if _, _, e = snapshot.WorkingMember(*seed); e != nil {
		return errors.New("Текущая конфигурация Авто не совпадает с его составом. Прежние профили сохранены.")
	}
	return nil
}
