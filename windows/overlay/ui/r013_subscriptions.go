// SPDX-License-Identifier: MIT
package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"golang.org/x/sys/windows"
)

type boundProfile struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type orderBinding struct {
	OrderID    string                  `json:"orderID"`
	Capability string                  `json:"capability"`
	Members    map[string]boundProfile `json:"members"`
	Revision   string                  `json:"revision"`
	Expiry     int64                   `json:"expiry"`
}
type pendingBinding struct {
	Binding orderBinding  `json:"binding"`
	Changes []r013.Change `json:"changes"`
}
type clientState struct {
	Bindings               map[string]orderBinding             `json:"bindings"`
	Pending                *pendingBinding                     `json:"pending,omitempty"`
	LastCheck              int64                               `json:"lastCheck"`
	NativeTrial            *r013.NativeTrialState              `json:"nativeTrial,omitempty"`
	NativeTrialBindings    map[string]r013.NativeTrialMetadata `json:"nativeTrialBindings,omitempty"`
	RenewalsAwaitingReturn map[string]int64                    `json:"renewalsAwaitingReturn,omitempty"`
	NativeTrialNotices     map[string]int64                    `json:"nativeTrialNotices,omitempty"`
}

var clientStateLock sync.Mutex

func r013SubscriptionSummary(state *clientState) string {
	if len(state.Bindings) == 0 {
		return "Нет привязанных подписок. Импортируйте ZIP из своей заявки в боте."
	}
	ids := make([]string, 0, len(state.Bindings))
	for id := range state.Bindings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	lines := make([]string, 0, len(ids))
	for _, id := range ids {
		binding := state.Bindings[id]
		lines = append(lines, fmt.Sprintf("Подписка №%s: %d серверов. Срок до %s.", id, len(binding.Members), time.UnixMilli(binding.Expiry).Local().Format("02.01.2006 15:04")))
	}
	return strings.Join(lines, "\n")
}

func clientStatePath() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "VPN013WG")
	if r013Preview {
		return "", errors.New("Предпросмотр не сохраняет привязки.")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "client-state.dat"), nil
}
func readClientState() (*clientState, error) {
	state := &clientState{Bindings: map[string]orderBinding{}}
	path, err := clientStatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 16*r013.MaxDocument {
		return nil, r013.ErrDocument
	}
	data, err = dpapi.Decrypt(data, "VPN013-client-state-v1")
	if err != nil {
		return nil, errors.New("Не удалось открыть защищённые привязки. Файл сохранён.")
	}
	if json.Unmarshal(data, state) != nil || state.Bindings == nil {
		return nil, r013.ErrDocument
	}
	return state, nil
}
func writeClientState(state *clientState) error {
	path, err := clientStatePath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	data, err = dpapi.Encrypt(data, "VPN013-client-state-v1")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".client-*.pending")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	file.Close()
	from, _ := windows.UTF16PtrFromString(temporary)
	to, _ := windows.UTF16PtrFromString(path)
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func resolvePending(state *clientState) error {
	if state.Pending == nil {
		return nil
	}
	tunnels, listErr := manager.IPCClientTunnels()
	if listErr != nil {
		return listErr
	}
	names := map[string]bool{}
	for _, t := range tunnels {
		names[t.Name] = true
	}
	applied, previous := true, true
	for _, change := range state.Pending.Changes {
		tunnel := manager.Tunnel{Name: change.Name}
		current, err := tunnel.StoredConfig()
		exists := names[change.Name]
		if exists && err != nil {
			return errors.New("Не удалось прочитать профиль для проверки обновления.")
		}
		if change.Remove {
			applied = applied && !exists
		} else {
			next, e := conf.FromWgQuick(change.Config, change.Name)
			applied = applied && e == nil && exists && r013.Digest(current.ToWgQuick()) == r013.Digest(next.ToWgQuick())
		}
		if change.Expected == "" {
			previous = previous && !exists
		} else {
			previous = previous && ((!exists && change.AllowMissing) || (exists && r013.Digest(current.ToWgQuick()) == change.Expected))
		}
	}
	if applied {
		state.Bindings[state.Pending.Binding.OrderID] = state.Pending.Binding
		state.Pending = nil
		return writeClientState(state)
	}
	if previous {
		state.Pending = nil
		return writeClientState(state)
	}
	return errors.New("Не удалось подтвердить завершение предыдущего обновления. Прежние данные сохранены; не импортируйте архив повторно.")
}
func canonical(text, name string) (*conf.Config, error) {
	c, err := conf.FromWgQuickWithUnknownEncoding(text, name)
	if err != nil {
		return nil, errors.New("Конфигурация не прошла проверку формата. Исходный файл сохранён.")
	}
	return c, nil
}
func importManaged(profiles []r013.Profile, document *r013.AccessDocument) error {
	clientStateLock.Lock()
	defer clientStateLock.Unlock()
	state, err := readClientState()
	if err != nil {
		return err
	}
	if err = resolvePending(state); err != nil {
		return err
	}
	snapshot := document.Snapshot
	if !snapshot.Active(time.Now()) {
		return r013.ErrAccessEnded
	}
	if _, exists := state.Bindings[snapshot.OrderID]; exists {
		return errors.New("Эта заявка уже привязана. Нажмите «Обновить», чтобы получить её актуальный состав.")
	}
	if len(profiles) != len(snapshot.Servers) {
		return r013.ErrDocument
	}
	available := map[string]r013.Profile{}
	for _, p := range profiles {
		c, e := canonical(p.Config, p.Name)
		if e != nil {
			return e
		}
		digest := r013.Digest(c.ToWgQuick())
		if _, exists := available[digest]; exists {
			return r013.ErrDocument
		}
		available[digest] = p
	}
	binding := orderBinding{snapshot.OrderID, document.Capability, map[string]boundProfile{}, snapshot.Revision, snapshot.Expiry}
	changes := []r013.Change{}
	for _, server := range snapshot.Servers {
		expected, e := canonical(server.Config, "validation")
		if e != nil {
			return e
		}
		digest := r013.Digest(expected.ToWgQuick())
		p, found := available[digest]
		if !found {
			return r013.ErrDocument
		}
		delete(available, digest)
		binding.Members[server.ID] = boundProfile{p.Name, digest}
		changes = append(changes, r013.Change{Name: p.Name, Config: p.Config})
	}
	state.Pending = &pendingBinding{binding, changes}
	if err = writeClientState(state); err != nil {
		return err
	}
	if err = manager.IPCClientApplyR013Changes(changes); err != nil {
		return err
	}
	return resolvePending(state)
}
func refreshOrders(ctx context.Context) (int, error) { return refreshBoundOrders(ctx, "") }
func boundRosterPresent(binding orderBinding, snapshot r013.Snapshot, available map[string]bool) bool {
	if len(binding.Members) != len(snapshot.Servers) {
		return false
	}
	seen := map[string]bool{}
	for _, server := range snapshot.Servers {
		member, ok := binding.Members[server.ID]
		name := strings.ToLower(member.Name)
		if !ok || !available[name] || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}
func refreshBoundOrders(ctx context.Context, only string) (int, error) {
	clientStateLock.Lock()
	defer clientStateLock.Unlock()
	state, err := readClientState()
	if err != nil {
		return 0, err
	}
	if err = resolvePending(state); err != nil {
		return 0, err
	}
	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return 0, err
	}
	available := map[string]bool{}
	for _, tunnel := range tunnels {
		available[strings.ToLower(tunnel.Name)] = true
	}
	updated := 0
	for id, binding := range state.Bindings {
		if only != "" && id != only {
			continue
		}
		snapshot, err := r013.FetchSnapshot(ctx, id, binding.Capability)
		if err != nil {
			return updated, err
		}
		if !snapshot.Active(time.Now()) {
			return updated, r013.ErrAccessEnded
		}
		if snapshot.Revision == binding.Revision && boundRosterPresent(binding, snapshot, available) {
			binding.Expiry = snapshot.Expiry
			state.Bindings[id] = binding
			continue
		}
		next := orderBinding{id, binding.Capability, map[string]boundProfile{}, snapshot.Revision, snapshot.Expiry}
		changes := []r013.Change{}
		currentIDs := map[string]bool{}
		for _, server := range snapshot.Servers {
			currentIDs[server.ID] = true
			old, exists := binding.Members[server.ID]
			name, expected := old.Name, old.Digest
			if !exists {
				name = "R013-" + id[:6] + "-" + r013.Digest(server.ID)[:10]
				expected = ""
			}
			c, e := canonical(server.Config, name)
			if e != nil {
				return updated, e
			}
			changes = append(changes, r013.Change{Name: name, Expected: expected, Config: c.ToWgQuick(), AllowMissing: exists && !available[strings.ToLower(name)]})
			next.Members[server.ID] = boundProfile{name, r013.Digest(c.ToWgQuick())}
		}
		for serverID, old := range binding.Members {
			if !currentIDs[serverID] {
				changes = append(changes, r013.Change{Name: old.Name, Expected: old.Digest, Remove: true, AllowMissing: !available[strings.ToLower(old.Name)]})
			}
		}
		state.Pending = &pendingBinding{next, changes}
		if err = writeClientState(state); err != nil {
			return updated, err
		}
		if err = manager.IPCClientApplyR013Changes(changes); err != nil {
			return updated, err
		}
		if err = resolvePending(state); err != nil {
			return updated, err
		}
		updated++
	}
	state.LastCheck = time.Now().Unix()
	return updated, writeClientState(state)
}
