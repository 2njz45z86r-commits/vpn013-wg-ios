// SPDX-License-Identifier: MIT
package ui

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/lxn/walk"
)

func loadNativeTrialState() (*r013.NativeTrialState, error) {
	clientStateLock.Lock()
	defer clientStateLock.Unlock()
	state, err := readClientState()
	if err != nil {
		return nil, err
	}
	if state.NativeTrial == nil {
		state.NativeTrial, err = r013.NewNativeTrialState()
		if err != nil {
			return nil, err
		}
		if err = writeClientState(state); err != nil {
			return nil, err
		}
	}
	copy := *state.NativeTrial
	return &copy, nil
}
func saveNativeTrialState(value *r013.NativeTrialState) error {
	clientStateLock.Lock()
	defer clientStateLock.Unlock()
	state, err := readClientState()
	if err != nil {
		return err
	}
	if state.NativeTrial == nil || state.NativeTrial.RequestID != value.RequestID {
		return r013.ErrDocument
	}
	if value.Info != nil && value.Info.Validate(state.NativeTrial.Info) != nil {
		return r013.ErrDocument
	}
	copy := *value
	state.NativeTrial = &copy
	return writeClientState(state)
}

type nativeTrialOperations struct {
	load          func() (*r013.NativeTrialState, error)
	save          func(*r013.NativeTrialState) error
	status        func(context.Context, *r013.NativeTrialState) (*r013.NativeTrialInfo, error)
	download      func(context.Context, *r013.NativeTrialState) ([]byte, error)
	bound         func(string) (bool, error)
	refresh       func(context.Context, string) (int, error)
	remember      func(*r013.NativeTrialInfo) error
	importArchive func(*r013.Archive) error
}

func productionNativeTrialOperations() nativeTrialOperations {
	return nativeTrialOperations{
		load: loadNativeTrialState, save: saveNativeTrialState, status: r013.NativeTrialStatus, download: r013.NativeTrialZIP,
		bound: func(id string) (bool, error) {
			clientStateLock.Lock()
			defer clientStateLock.Unlock()
			state, e := readClientState()
			if e != nil {
				return false, e
			}
			_, found := state.Bindings[id]
			return found, nil
		},
		refresh: refreshBoundOrders,
		remember: func(info *r013.NativeTrialInfo) error {
			clientStateLock.Lock()
			defer clientStateLock.Unlock()
			state, e := readClientState()
			if e != nil {
				return e
			}
			if state.NativeTrialBindings == nil {
				state.NativeTrialBindings = map[string]r013.NativeTrialMetadata{}
			}
			state.NativeTrialBindings[info.OrderID] = r013.NativeTrialMetadata{DurationSeconds: r013.NativeTrialDuration, RenewalURL: info.RenewalURL}
			return writeClientState(state)
		},
		importArchive: func(a *r013.Archive) error { return importManaged(a.Profiles, a.Access) },
	}
}
func acquireNativeTrial(ctx context.Context, beforeImport func() error) (*r013.NativeTrialInfo, int, error) {
	return acquireNativeTrialWith(ctx, beforeImport, productionNativeTrialOperations())
}

// The compositor has no external transport override. Its production constructor
// binds fixed HTTPS and the established DPAPI/manager transaction only.
func acquireNativeTrialWith(ctx context.Context, beforeImport func() error, operations nativeTrialOperations) (*r013.NativeTrialInfo, int, error) {
	state, err := operations.load()
	if err != nil {
		return nil, 0, err
	}
	until := time.Now().Add(2 * time.Minute)
	for {
		info, e := operations.status(ctx, state)
		if e != nil {
			return nil, 0, e
		}
		if info == nil || info.Validate(state.Info) != nil {
			return nil, 0, r013.ErrDocument
		}
		if state.Ticket == "" {
			state.Ticket = info.Ticket
		}
		state.Info = info
		state.ServerOffset = info.ServerTime - time.Now().UnixMilli()
		if e = operations.save(state); e != nil {
			return nil, 0, e
		}
		if info.State != "provisioning" {
			break
		}
		if time.Now().After(until) {
			return nil, 0, errors.New("Серверы ещё готовятся. Повторное нажатие продолжит тот же тест и не продлит его срок.")
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, 0, ctx.Err()
		case <-timer.C:
		}
	}
	info := state.Info
	if info.ExpiresAt <= info.ServerTime || info.State == "expired" {
		return info, 0, nil
	}
	if info.State != "active" {
		return nil, 0, r013.ErrDocument
	}
	already, e := operations.bound(info.OrderID)
	if e != nil {
		return nil, 0, e
	}
	if already {
		if e = beforeImport(); e != nil {
			return nil, 0, e
		}
		_, e = operations.refresh(ctx, info.OrderID)
		return info, 0, e
	}
	data, e := operations.download(ctx, state)
	if e != nil {
		return nil, 0, e
	}
	archive, e := r013.ReadNativeTrialZIP(data, info)
	if e != nil {
		return nil, 0, e
	}
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	if e = beforeImport(); e != nil {
		return nil, 0, e
	}
	e = operations.remember(info)
	if e != nil {
		return nil, 0, e
	}
	// The existing manager transaction rejects active/unknown service state;
	// this worker never stops a tunnel or alters routes itself.
	e = operations.importArchive(archive)
	return info, len(archive.Profiles), e
}
func (tp *TunnelsPage) onNativeTrial() {
	if r013Preview || !atomic.CompareAndSwapInt32(&tp.updatesBusy, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&tp.updatesBusy, 0)
	dialog, err := walk.NewDialog(tp.Form())
	if err != nil {
		showErrorCustom(tp.Form(), "Тестовые конфигурации", "Не удалось открыть загрузку.")
		return
	}
	defer dialog.Dispose()
	dialog.SetTitle(r013.NativeTrialLabel)
	dialog.SetLayout(walk.NewVBoxLayout())
	dialog.SetSize(walk.Size{460, 160})
	label, _ := walk.NewTextLabel(dialog)
	label.SetText("Готовим все серверы, загружаем ZIP и добавляем конфигурации…")
	stop, _ := walk.NewPushButton(dialog)
	stop.SetText("Отмена")
	dialog.SetCancelButton(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var phase int32 // network0, committing1, cancelled2, completed3
	stop.Clicked().Attach(func() {
		if atomic.CompareAndSwapInt32(&phase, 0, 2) {
			cancel()
			dialog.Cancel()
		}
	})
	dialog.Closing().Attach(func(canceled *bool, _ walk.CloseReason) {
		if atomic.LoadInt32(&phase) == 1 {
			*canceled = true
			return
		}
		if atomic.CompareAndSwapInt32(&phase, 0, 2) {
			cancel()
		}
	})
	disposal := tp.Disposing().Attach(cancel)
	defer tp.Disposing().Detach(disposal)
	go func() {
		info, count, e := acquireNativeTrial(ctx, func() error {
			if ctx.Err() != nil || !atomic.CompareAndSwapInt32(&phase, 0, 1) {
				return context.Canceled
			}
			tp.Synchronize(func() {
				if !dialog.IsDisposed() {
					stop.SetEnabled(false)
					label.SetText("Сохраняем конфигурации. Пожалуйста, подождите…")
				}
			})
			return nil
		})
		atomic.CompareAndSwapInt32(&phase, 1, 3)
		atomic.CompareAndSwapInt32(&phase, 0, 3)
		tp.Synchronize(func() {
			if tp.IsDisposed() || dialog.IsDisposed() || ctx.Err() == context.Canceled {
				return
			}
			dialog.Accept()
			if e != nil {
				showErrorCustom(tp.Form(), "Тест не добавлен", "Не удалось завершить загрузку. Прежние профили сохранены. Повторное нажатие продолжит ту же заявку.")
				return
			}
			if info.ExpiresAt <= info.ServerTime || info.State == "expired" {
				tp.offerNativeRenewal(info.OrderID, info.RenewalURL, true)
				return
			}
			tp.listView.Load(false)
			text := fmt.Sprintf("Добавлено профилей: %d. Доступ до %s. Выберите сервер и включите VPN.", count, time.UnixMilli(info.ExpiresAt).Local().Format("02.01.2006 15:04"))
			if count == 0 {
				text = "Конфигурации уже добавлены и проверены. Срок не изменён. Продление доступно через меню «Продлить конфигурацию»."
			}
			walk.MsgBox(tp.Form(), "Конфигурации добавлены", text, walk.MsgBoxIconInformation)
		})
	}()
	dialog.Run()
}
func (tp *TunnelsPage) offerNativeRenewal(id, url string, expired bool) {
	metadata := r013.NativeTrialMetadata{DurationSeconds: r013.NativeTrialDuration, RenewalURL: url}
	if metadata.Validate() != nil && url != r013.PurchaseURL+"?start=renew_"+id {
		return
	}
	title := "Продлить конфигурацию"
	if expired {
		title = "Срок доступа закончился"
	}
	if walk.MsgBox(tp.Form(), title, "После оплаты и ручного подтверждения в боте продлятся прежние профили и ключи. Повторный импорт не нужен.\n\nПерейти к продлению?", walk.MsgBoxYesNo|walk.MsgBoxIconInformation) != walk.DlgCmdYes {
		return
	}
	clientStateLock.Lock()
	state, err := readClientState()
	if err == nil {
		if state.RenewalsAwaitingReturn == nil {
			state.RenewalsAwaitingReturn = map[string]int64{}
		}
		expiry := state.Bindings[id].Expiry
		if expiry == 0 && state.NativeTrial != nil && state.NativeTrial.Info != nil {
			expiry = state.NativeTrial.Info.ExpiresAt
		}
		state.RenewalsAwaitingReturn[id] = expiry
		err = writeClientState(state)
	}
	clientStateLock.Unlock()
	if err != nil {
		showErrorCustom(tp.Form(), title, "Не удалось сохранить привязку. Прежние профили сохранены.")
		return
	}
	externalLink(tp.Form(), url)
}
func (tp *TunnelsPage) onNativeRenewal() {
	if r013Preview {
		return
	}
	clientStateLock.Lock()
	state, err := readClientState()
	clientStateLock.Unlock()
	if err != nil {
		showErrorCustom(tp.Form(), "Продление", "Не удалось открыть защищённые привязки.")
		return
	}
	links := map[string]string{}
	for id := range state.Bindings {
		links[id] = r013.PurchaseURL + "?start=renew_" + id
	}
	for id, trial := range state.NativeTrialBindings {
		if trial.Validate() == nil {
			links[id] = trial.RenewalURL
		}
	}
	if state.NativeTrial != nil && state.NativeTrial.Info != nil && state.NativeTrial.Info.Validate(nil) == nil {
		links[state.NativeTrial.Info.OrderID] = state.NativeTrial.Info.RenewalURL
	}
	if len(links) == 0 {
		externalLink(tp.Form(), r013.PurchaseURL)
		return
	}
	dialog, e := walk.NewDialog(tp.Form())
	if e != nil {
		return
	}
	defer dialog.Dispose()
	dialog.SetTitle("Продлить конфигурацию")
	dialog.SetLayout(walk.NewVBoxLayout())
	ids := make([]string, 0, len(links))
	for id := range links {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		order, url := id, links[id]
		button, _ := walk.NewPushButton(dialog)
		button.SetText("Заявка №" + id)
		button.Clicked().Attach(func() { dialog.Accept(); tp.offerNativeRenewal(order, url, false) })
	}
	close, _ := walk.NewPushButton(dialog)
	close.SetText("Закрыть")
	close.Clicked().Attach(func() { dialog.Cancel() })
	dialog.SetCancelButton(close)
	dialog.Run()
}
func (tray *Tray) startNativeTrialNotifications() {
	if r013Preview {
		return
	}
	quit := make(chan struct{})
	tray.mtw.Disposing().Attach(func() { close(quit) })
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			default:
			}
			tray.mtw.Synchronize(func() {
				if !tray.mtw.IsDisposed() {
					tray.checkNativeTrialExpiry()
				}
			})
			tray.mtw.tunnelsPage.refreshNativeRenewals()
			select {
			case <-quit:
				return
			case <-ticker.C:
			}
		}
	}()
}
func (tray *Tray) checkNativeTrialExpiry() {
	// Never block the UI behind an in-flight configuration/network transaction.
	if !clientStateLock.TryLock() {
		return
	}
	defer clientStateLock.Unlock()
	state, err := readClientState()
	if err != nil {
		return
	}
	offset := int64(0)
	if state.NativeTrial != nil {
		offset = state.NativeTrial.ServerOffset
	}
	for id, metadata := range state.NativeTrialBindings {
		binding, ok := state.Bindings[id]
		if !ok || metadata.Validate() != nil || binding.Expiry > time.Now().UnixMilli()+offset || state.NativeTrialNotices[id] == binding.Expiry {
			continue
		}
		tray.clicked = tray.onManageTunnels
		if tray.ShowInfo("Срок доступа закончился", "Продлите конфигурацию в меню приложения. Прежние профили и ключи сохранятся.") != nil {
			continue
		}
		if state.NativeTrialNotices == nil {
			state.NativeTrialNotices = map[string]int64{}
		}
		state.NativeTrialNotices[id] = binding.Expiry
		_ = writeClientState(state)
		break // One notification per tick; no burst after sleep or restart.
	}
}
func (tp *TunnelsPage) refreshNativeRenewals() {
	if !atomic.CompareAndSwapInt32(&tp.updatesBusy, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&tp.updatesBusy, 0)
	clientStateLock.Lock()
	state, err := readClientState()
	ids := []string{}
	if err == nil {
		for id := range state.RenewalsAwaitingReturn {
			ids = append(ids, id)
		}
	}
	clientStateLock.Unlock()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, id := range ids {
		_, err = refreshBoundOrders(ctx, id)
		if err != nil {
			continue
		}
		clientStateLock.Lock()
		fresh, e := readClientState()
		if e == nil && fresh.Bindings[id].Expiry > fresh.RenewalsAwaitingReturn[id] {
			delete(fresh.RenewalsAwaitingReturn, id)
			_ = writeClientState(fresh)
		}
		clientStateLock.Unlock()
	}
}
