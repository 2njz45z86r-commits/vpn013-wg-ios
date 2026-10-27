// SPDX-License-Identifier: MIT
package ui

import (
	"context"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/lxn/walk"
	"sync/atomic"
	"time"
)

type r013CurrentSnapshot struct {
	name, detail string
	target       r013.CurrentPingTarget
	active       bool
	controlName  string
	controlState manager.TunnelState
	controlKnown bool
}

type r013CurrentCard struct {
	owner              *ManageTunnelsWindow
	group              *walk.GroupBox
	detail             *walk.TextLabel
	result             *walk.Label
	button             *walk.PushButton
	power              *walk.PushButton
	powerError         *walk.TextLabel
	powerBusy          bool
	powerRefreshing    bool
	current            r013CurrentSnapshot
	cancel, pingCancel context.CancelFunc
	refresh            chan struct{}
	revision           atomic.Uint64
	displayRevision    uint64
	pingID             uint64
	disposed           atomic.Bool
	pingInFlight       atomic.Bool
	changes            *manager.TunnelChangeCallback
}

func addR013CurrentCard(owner *ManageTunnelsWindow) (*r013CurrentCard, error) {
	c := &r013CurrentCard{owner: owner, refresh: make(chan struct{}, 1)}
	var err error
	if c.group, err = walk.NewGroupBox(owner); err != nil {
		return nil, err
	}
	c.group.SetTitle("Текущее подключение · Не подключено")
	layout := walk.NewHBoxLayout()
	layout.SetMargins(walk.Margins{HNear: 12, VNear: 6, HFar: 12, VFar: 8})
	c.group.SetLayout(layout)
	content, err := walk.NewComposite(c.group)
	if err != nil {
		c.group.Dispose()
		return nil, err
	}
	contentLayout := walk.NewVBoxLayout()
	contentLayout.SetMargins(walk.Margins{})
	content.SetLayout(contentLayout)
	layout.SetStretchFactor(content, 1)
	if c.detail, err = walk.NewTextLabel(content); err != nil {
		c.group.Dispose()
		return nil, err
	}
	c.detail.SetText("Включите профиль или Авто. Выбор строки не меняет эту карточку.")
	row, err := walk.NewComposite(content)
	if err != nil {
		c.group.Dispose()
		return nil, err
	}
	rowLayout := walk.NewHBoxLayout()
	rowLayout.SetMargins(walk.Margins{})
	row.SetLayout(rowLayout)
	if c.result, err = walk.NewLabel(row); err != nil {
		c.group.Dispose()
		return nil, err
	}
	c.result.SetText("Пинг адреса · —")
	walk.NewHSpacer(row)
	if c.button, err = walk.NewPushButton(row); err != nil {
		c.group.Dispose()
		return nil, err
	}
	c.button.SetText("Пинг текущего")
	c.button.SetMinMaxSize(walk.Size{Width: 130, Height: 30}, walk.Size{Width: 130, Height: 30})
	c.button.SetEnabled(false)
	c.button.Clicked().Attach(c.ping)
	if c.powerError, err = walk.NewTextLabel(content); err != nil {
		c.group.Dispose()
		return nil, err
	}
	c.powerError.SetVisible(false)
	if err = c.addPowerButton(); err != nil {
		c.group.Dispose()
		return nil, err
	}
	return c, nil
}

// Read actual active state, independently of table selection. Never use Auto's
// stored seed as a substitute for its actual current runtime membership.
func readR013Current(ctx context.Context) r013CurrentSnapshot {
	none := r013CurrentSnapshot{detail: "VPN не подключён. Пинг адреса не подтверждает работу VPN."}
	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		none.detail = "Состояние подключения недоступно"
		return none
	}
	var active *manager.Tunnel
	for _, tunnel := range tunnels {
		if ctx.Err() != nil {
			return none
		}
		state, e := tunnel.State()
		if e != nil {
			none.detail = "Состояние подключения недоступно"
			return none
		}
		if state == manager.TunnelStarted {
			if active != nil {
				none.detail = "Несколько подключений; текущий сервер не определён"
				return none
			}
			copy := tunnel
			active = &copy
		}
	}
	if active == nil {
		global, e := manager.IPCClientGlobalState()
		if e == nil {
			none.controlState = global
			none.controlKnown = global == manager.TunnelStopped || global == manager.TunnelStarting || global == manager.TunnelStopping
			if global == manager.TunnelStarting {
				none.detail = "VPN включается…"
			}
			if global == manager.TunnelStopping {
				none.detail = "VPN выключается…"
			}
		}
		return none
	}
	shot := r013CurrentSnapshot{name: active.Name, active: true, controlName: active.Name, controlState: manager.TunnelStarted, controlKnown: true}
	if shot.name == r013.AutoName {
		shot.name = "Авто"
	}
	runtimeConfig, runtimeErr := active.RuntimeConfig()
	var live, stored *conf.Config
	if runtimeErr == nil {
		live = &runtimeConfig
	}
	if active.Name != r013.AutoName {
		if config, e := active.StoredConfig(); e == nil {
			stored = &config
		}
	}
	shot.target, err = r013.CurrentTarget(active.Name, live, stored)
	if err != nil {
		shot.detail = "VPN запущен · " + err.Error()
		return shot
	}
	shot.detail = "Сервер: " + shot.target.Endpoint
	if !shot.target.StoredFallback && live != nil && len(live.Peers) == 1 {
		peer := live.Peers[0]
		if peer.LastHandshakeTime == 0 {
			shot.detail += " · рукопожатие не подтверждено"
		} else {
			shot.detail += " · рукопожатие " + time.Unix(0, int64(peer.LastHandshakeTime)).Local().Format("15:04:05")
		}
		shot.detail += fmt.Sprintf(" · ↓ %s · ↑ %s", peer.RxBytes.String(), peer.TxBytes.String())
	} else {
		shot.detail += " · статистика недоступна"
	}
	if state, e := active.State(); e != nil || state != manager.TunnelStarted {
		return none
	}
	return shot
}

func (c *r013CurrentCard) start() {
	c.owner.tunnelsPage.listView.CurrentIndexChanged().Attach(c.updatePowerButton)
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.changes = manager.IPCClientRegisterTunnelChange(func(_ *manager.Tunnel, _, _ manager.TunnelState, _ error) {
		// Even a same-profile reconnection invalidates the old session's ping.
		c.revision.Add(1)
		select {
		case c.refresh <- struct{}{}:
		default:
		}
	})
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			revision := c.revision.Load()
			shot := readR013Current(ctx)
			if ctx.Err() != nil || c.disposed.Load() {
				return
			}
			c.owner.Synchronize(func() {
				if !c.disposed.Load() && c.revision.Load() == revision {
					c.apply(shot, revision)
				}
			})
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-c.refresh:
			}
		}
	}()
}

func (c *r013CurrentCard) apply(shot r013CurrentSnapshot, revision uint64) {
	if shot.target.Identity != c.current.target.Identity || shot.active != c.current.active || c.displayRevision != revision {
		c.pingID++
		if c.pingCancel != nil {
			c.pingCancel()
			c.pingCancel = nil
		}
		c.result.SetText("Пинг адреса · —")
		c.button.SetText("Пинг текущего")
	}
	c.displayRevision = revision
	c.current = shot
	c.powerRefreshing = false
	title := "Текущее подключение · Не подключено"
	if shot.active {
		title = "Текущее подключение · " + shot.name
	}
	c.group.SetTitle(title)
	c.detail.SetText(shot.detail)
	c.button.SetEnabled(shot.active && shot.target.Host != "" && (c.pingCancel != nil || !c.pingInFlight.Load()))
	c.updatePowerButton()
}

func (c *r013CurrentCard) ping() {
	if c.pingCancel != nil {
		c.pingCancel()
		return
	}
	target, revision := c.current.target, c.revision.Load()
	if target.Host == "" || !c.current.active {
		return
	}
	if !c.pingInFlight.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	c.pingID++
	pingID := c.pingID
	c.pingCancel = cancel
	c.button.SetText("Отменить пинг")
	c.result.SetText("Пинг адреса · …")
	go func() {
		defer func() {
			c.pingInFlight.Store(false)
			select {
			case c.refresh <- struct{}{}:
			default:
			}
		}()
		defer cancel()
		delay, err := r013.Echo(ctx, target.Host, nil, 2500*time.Millisecond)
		text := "Нет ответа ICMP"
		if err == nil {
			text = fmt.Sprintf("%d мс", delay.Milliseconds())
			if delay < time.Millisecond {
				text = "<1 мс"
			}
		}
		if ctx.Err() != nil {
			text = "Отменено"
		}
		if c.disposed.Load() {
			return
		}
		c.owner.Synchronize(func() {
			if c.disposed.Load() || c.pingID != pingID || c.revision.Load() != revision || c.current.target.Identity != target.Identity {
				return
			}
			c.pingCancel = nil
			c.button.SetText("Пинг текущего")
			c.result.SetText("Пинг адреса · " + text)
		})
	}()
}

func (c *r013CurrentCard) dispose() {
	if c == nil {
		return
	}
	c.disposed.Store(true)
	if c.cancel != nil {
		c.cancel()
	}
	if c.pingCancel != nil {
		c.pingCancel()
	}
	if c.changes != nil {
		c.changes.Unregister()
		c.changes = nil
	}
}
