// SPDX-License-Identifier: MIT
package ui

import (
	"errors"
	"math"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/lxn/walk"
)

// A native button retains keyboard focus, Space/Enter and UI Automation.
// Only its power image is drawn; its state always comes from the manager.
func (c *r013CurrentCard) addPowerButton() error {
	var err error
	c.power, err = walk.NewPushButton(c.group)
	if err != nil {
		return err
	}
	c.power.SetName("vpn013.power")
	c.power.SetMinMaxSize(walk.Size{Width: 96, Height: 92}, walk.Size{Width: 96, Height: 92})
	c.power.SetImageAboveText(true)
	c.power.Clicked().Attach(c.togglePower)
	c.power.SetEnabled(false)
	c.power.SetText("ВКЛ")
	return nil
}

func powerImage(active, enabled bool) walk.Image {
	return walk.NewPaintFuncImage(walk.Size{Width: 52, Height: 52}, func(canvas *walk.Canvas, bounds walk.Rectangle) error {
		color := walk.RGB(157, 178, 197)
		if active {
			color = walk.RGB(45, 209, 91)
		}
		if !enabled {
			color = walk.RGB(114, 130, 146)
		}
		brush, err := walk.NewSolidColorBrush(color)
		if err != nil {
			return err
		}
		defer brush.Dispose()
		size := bounds.Width
		if bounds.Height < size {
			size = bounds.Height
		}
		r := walk.Rectangle{X: bounds.X + (bounds.Width-size)/2 + 2, Y: bounds.Y + (bounds.Height-size)/2 + 2, Width: size - 4, Height: size - 4}
		if err = canvas.FillEllipse(brush, r); err != nil {
			return err
		}
		ink, err := walk.NewSolidColorBrush(walk.RGB(12, 25, 41))
		if err != nil {
			return err
		}
		defer ink.Dispose()
		pen, err := walk.NewGeometricPen(walk.PenSolid, 4, ink)
		if err != nil {
			return err
		}
		defer pen.Dispose()
		cx, cy := float64(r.X+r.Width/2), float64(r.Y+r.Height/2)
		radius := float64(r.Width) * 0.27
		points := make([]walk.Point, 49)
		for i := range points {
			a := (55.0 + 250.0*float64(i)/48.0) * math.Pi / 180
			points[i] = walk.Point{X: int(math.Round(cx + radius*math.Sin(a))), Y: int(math.Round(cy - radius*math.Cos(a)))}
		}
		if err = canvas.DrawPolyline(pen, points); err != nil {
			return err
		}
		return canvas.DrawLine(pen, walk.Point{X: int(cx), Y: int(cy - radius - 3)}, walk.Point{X: int(cx), Y: int(cy + 1)})
	})
}

func (c *r013CurrentCard) selectedPowerName() string {
	if c.owner.tunnelsPage != nil {
		if t := c.owner.tunnelsPage.listView.CurrentTunnel(); t != nil {
			return t.Name
		}
	}
	return ""
}

func (c *r013CurrentCard) updatePowerButton() {
	if c.power == nil || c.disposed.Load() {
		return
	}
	shot := c.current
	text, description := "ВКЛ", "Выберите профиль для включения VPN"
	enabled := shot.controlKnown && IsAdmin && !c.powerBusy && !c.powerRefreshing
	switch {
	case c.powerBusy || c.powerRefreshing:
		text, description, enabled = "Подождите…", "Выполняется переключение VPN", false
	case !shot.controlKnown:
		text, description, enabled = "ВКЛ", "Состояние VPN пока недоступно", false
	case shot.controlState == manager.TunnelStarting:
		text, description, enabled = "Включение…", "VPN включается", false
	case shot.controlState == manager.TunnelStopping:
		text, description, enabled = "Выключение…", "VPN выключается", false
	case shot.active && shot.controlState == manager.TunnelStarted && shot.controlName != "":
		text, description = "ВЫКЛ", "Отключить VPN · "+shot.name
	case shot.controlState == manager.TunnelStopped:
		name := c.selectedPowerName()
		if name == "" {
			enabled = false
		} else {
			if name == r013.AutoName {
				name = "Авто"
			}
			description = "Включить VPN · " + name
			c.detail.SetText("Выбран профиль: " + name + ". Нажмите «ВКЛ», чтобы подключиться.")
		}
	default:
		enabled = false
	}
	c.power.SetText(text)
	c.power.SetToolTipText(description)
	c.power.Accessibility().SetName(description)
	c.power.SetEnabled(enabled)
	old := c.power.Image()
	c.power.SetImage(powerImage(shot.active, enabled))
	if old != nil {
		old.Dispose()
	}
}

func (c *r013CurrentCard) togglePower() {
	if c.disposed.Load() || c.powerBusy || c.powerRefreshing || !c.power.Enabled() {
		return
	}
	shot := c.current
	name, start := shot.controlName, false
	if shot.controlState == manager.TunnelStopped {
		name, start = c.selectedPowerName(), true
	}
	if name == "" || !shot.controlKnown {
		return
	}
	c.powerBusy = true
	c.powerError.SetVisible(false)
	c.updatePowerButton()
	go func() {
		// Never use Toggle: a stale OFF request must not turn a stopped VPN ON.
		// A different selection must not replace the actual active connection.
		state, err := manager.IPCClientGlobalState()
		expected := manager.TunnelStarted
		if start {
			expected = manager.TunnelStopped
		}
		if err == nil && state != expected {
			err = errors.New("VPN state changed")
		}
		tunnel := manager.Tunnel{Name: name}
		if err == nil {
			var current manager.TunnelState
			current, err = tunnel.State()
			if err == nil && current != expected {
				err = errors.New("Profile state changed")
			}
		}
		if err == nil {
			if start {
				err = tunnel.Start()
			} else {
				err = tunnel.Stop()
			}
		}
		if c.disposed.Load() {
			return
		}
		c.owner.Synchronize(func() {
			if c.disposed.Load() {
				return
			}
			c.powerBusy = false
			c.powerRefreshing = true
			c.revision.Add(1)
			if err != nil {
				action := "выключить"
				if start {
					action = "включить"
				}
				c.powerError.SetText("Не удалось " + action + " VPN. Проверьте состояние и повторите попытку.")
				c.powerError.SetVisible(true)
			}
			c.updatePowerButton()
			select {
			case c.refresh <- struct{}{}:
			default:
			}
		})
	}()
}
