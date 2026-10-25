// SPDX-License-Identifier: MIT
package ui

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/version"
	"github.com/lxn/walk"
)

type r013UpgradeOffer struct {
	row        *walk.Composite
	label      *walk.TextLabel
	button     *walk.PushButton
	release    *r013.Release
	installing bool
}

func (tp *TunnelsPage) addR013UpgradeOffer(parent walk.Container) error {
	row, err := walk.NewComposite(parent)
	if err != nil {
		return err
	}
	row.SetName("vpn013.app-update")
	layout := walk.NewHBoxLayout()
	layout.SetMargins(walk.Margins{16, 8, 16, 8})
	row.SetLayout(layout)
	label, err := walk.NewTextLabel(row)
	if err != nil {
		return err
	}
	label.SetTextColor(pale)
	button, err := walk.NewPushButton(row)
	if err != nil {
		return err
	}
	button.SetText("Установить обновление")
	button.SetName("vpn013.install-update")
	button.SetMinMaxSize(walk.Size{190, 36}, walk.Size{190, 36})
	tp.r013Upgrade = &r013UpgradeOffer{row: row, label: label, button: button}
	button.Clicked().Attach(tp.installR013OfferedUpdate)
	row.SetVisible(false)
	return nil
}

func (tp *TunnelsPage) showR013Upgrade(release *r013.Release) {
	offer := tp.r013Upgrade
	if offer == nil || offer.installing {
		return
	}
	if release == nil || !release.Newer(version.Number, r013.CurrentBuild) {
		offer.release = nil
		offer.row.SetVisible(false)
		return
	}
	copy := *release
	offer.release = &copy
	offer.label.SetText("Доступно обновление " + release.Version + ". Профили и привязки к заявкам сохранятся.")
	offer.button.SetText("Установить обновление")
	offer.button.SetEnabled(true)
	offer.row.SetVisible(true)
}

func (tp *TunnelsPage) installR013OfferedUpdate() {
	offer := tp.r013Upgrade
	if offer == nil || offer.release == nil || offer.installing || r013Preview {
		return
	}
	build := offer.release.Build
	offer.installing = true
	offer.button.SetEnabled(false)
	offer.label.SetText("Загружаем и проверяем обновление…")
	go func() {
		// The privileged service fetches its own signed metadata again, checks
		// this exact build and the installer hash. No order/device is created.
		err := manager.IPCClientInstallR013Update(build)
		tp.Synchronize(func() {
			offer.installing = false
			if err != nil {
				offer.label.SetText(err.Error())
				offer.button.SetEnabled(true)
			} else {
				offer.label.SetText("Обновление проверено. Ожидаем установку; после успешного обновления приложение перезапустится.")
			}
		})
	}()
}

func (tp *TunnelsPage) onR013Updates() { tp.checkR013Updates(true) }

func (tp *TunnelsPage) startR013DailyUpdates() {
	if r013Preview {
		return
	}
	quit := make(chan struct{})
	tp.Disposing().Attach(func() { close(quit) })
	go func() {
		initial := time.NewTimer(4 * time.Second)
		defer initial.Stop()
		select {
		case <-quit:
			return
		case <-initial.C:
		}
		var attempt time.Time
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			clientStateLock.Lock()
			state, err := readClientState()
			clientStateLock.Unlock()
			if err == nil && time.Since(attempt) >= time.Hour {
				if state.Pending != nil || time.Now().Unix()-state.LastCheck >= 86400 {
					attempt = time.Now()
					tp.checkR013Updates(false)
				}
			}
			select {
			case <-quit:
				return
			case <-ticker.C:
			}
		}
	}()
}

func (tp *TunnelsPage) checkR013Updates(visible bool) {
	if r013Preview || !atomic.CompareAndSwapInt32(&tp.updatesBusy, 0, 1) {
		return
	}
	go func() {
		defer atomic.StoreInt32(&tp.updatesBusy, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		count, syncErr := refreshOrders(ctx)
		release, err := r013.FetchRelease(ctx)
		message := "Текущая версия: " + version.Number
		if syncErr != nil {
			message += "\n\n" + syncErr.Error()
		} else {
			message += fmt.Sprintf("\nОбновлено заявок: %d", count)
		}
		if err != nil {
			message += "\n\n" + err.Error()
		} else {
			message += "\nПоследний выпуск: " + release.Version + "\n\n" + release.Notes
		}
		available := err == nil && release.Newer(version.Number, r013.CurrentBuild)
		tp.Synchronize(func() {
			if err == nil {
				tp.showR013Upgrade(release)
			}
			// A discovered release exposes an Install button. A background or
			// manual version check never installs software on its own.
			if visible && !available {
				walk.MsgBox(tp.Form(), "Обновления VPN013.com WG", message, walk.MsgBoxIconInformation)
			}
		})
	}()
}
