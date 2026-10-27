// SPDX-License-Identifier: MIT
package manager

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"golang.org/x/sys/windows"
)

type rollbackFile struct {
	Name    string `json:"name"`
	Data    []byte `json:"data"`
	Present bool   `json:"present"`
}

func writeProtected(path string, contents []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".r013-write-*.pending")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(contents); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	from, _ := windows.UTF16PtrFromString(temporary)
	to, _ := windows.UTF16PtrFromString(path)
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func rollbackPath() (string, error) {
	root, err := conf.RootDirectory(true)
	return filepath.Join(root, "r013-transaction.dat"), err
}
func restoreFiles(files []rollbackFile) error {
	for _, f := range files {
		if f.Present {
			if err := writeProtected(f.Name, f.Data); err != nil {
				return err
			}
		} else if err := os.Remove(f.Name); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// Recovery is invoked in the manager service before accepting application RPCs.
func recoverR013Transaction() error {
	journal, err := rollbackPath()
	if err != nil {
		return err
	}
	contents, err := os.ReadFile(journal)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	contents, err = dpapi.Decrypt(contents, "VPN013-transaction-v1")
	if err != nil {
		return err
	}
	var files []rollbackFile
	if json.Unmarshal(contents, &files) != nil || len(files) > 94 {
		return r013.ErrDocument
	}
	root, _ := conf.RootDirectory(true)
	for _, f := range files {
		relative, err := filepath.Rel(root, f.Name)
		if err != nil || relative == ".." || len(relative) > 3 && relative[:3] == "..\\" || filepath.IsAbs(relative) {
			return r013.ErrDocument
		}
	}
	if err = restoreFiles(files); err != nil {
		return err
	}
	return os.Remove(journal)
}
func (s *ManagerService) ApplyR013Changes(changes []r013.Change) error {
	if s.elevatedToken == 0 {
		return windows.ERROR_ACCESS_DENIED
	}
	if len(changes) == 0 || len(changes) > 90 {
		return r013.ErrDocument
	}
	autoControl.Lock()
	defer autoControl.Unlock()
	if autoRun != nil {
		return errors.New("Обновление загружено. Сначала отключите Авто.")
	}
	tunnels, err := s.Tunnels()
	if err != nil {
		return err
	}
	for _, t := range tunnels {
		state, err := stateR013Tunnel(s, t.Name)
		if err != nil || state != TunnelStopped {
			return errors.New("Отключите VPN перед применением обновления конфигураций.")
		}
	}
	configs := map[string]*conf.Config{}
	byName := map[string]r013.Change{}
	backups := []rollbackFile{}
	appendBackup := func(path string) error {
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		backups = append(backups, rollbackFile{path, raw, err == nil})
		return nil
	}
	for _, change := range changes {
		if !conf.TunnelNameIsValid(change.Name) || strings.EqualFold(change.Name, r013.AutoName) {
			return r013.ErrDocument
		}
		if _, exists := byName[strings.ToLower(change.Name)]; exists {
			return r013.ErrDocument
		}
		byName[strings.ToLower(change.Name)] = change
		if change.AllowMissing {
			if decoded, e := hex.DecodeString(change.Expected); e != nil || len(decoded) != 32 {
				return r013.ErrDocument
			}
		}
		old, oldErr := conf.LoadFromName(change.Name)
		if oldErr != nil && !os.IsNotExist(oldErr) {
			return oldErr
		}
		if change.Expected == "" {
			if oldErr == nil || change.Remove {
				return errors.New("Имя нового профиля уже занято. Прежние настройки сохранены.")
			}
		} else if !(change.AllowMissing && os.IsNotExist(oldErr)) && (oldErr != nil || r013.Digest(old.ToWgQuick()) != change.Expected) {
			return errors.New("Профиль изменён вручную. Обновление остановлено, прежние настройки сохранены.")
		}
		if !change.Remove {
			if len(change.Config) > 65536 {
				return r013.ErrDocument
			}
			configs[change.Name], err = conf.FromWgQuick(change.Config, change.Name)
			if err != nil {
				return errors.New("Новая конфигурация не прошла проверку.")
			}
		}
		c := &conf.Config{Name: change.Name}
		path, err := c.Path()
		if err != nil {
			return err
		}
		if err = appendBackup(path); err != nil {
			return err
		}
	}
	// Only source members whose exact previous bytes were bound are eligible for
	// automatic replacement/removal. Unrelated Auto members remain untouched.
	var autoMembers []conf.Config
	autoChanged := false
	autoFile, _ := autoPath()
	if _, statErr := os.Stat(autoFile); statErr == nil {
		members, loadErr := loadAuto()
		if loadErr != nil {
			return errors.New("Не удалось проверить состав Авто. Прежние профили сохранены.")
		}
		for _, member := range members {
			change, found := byName[strings.ToLower(member.Name)]
			if !found {
				autoMembers = append(autoMembers, member)
				continue
			}
			if change.Expected == "" || r013.Digest(member.ToWgQuick()) != change.Expected {
				return errors.New("Состав Авто изменён вручную. Создайте Авто заново перед обновлением.")
			}
			autoChanged = true
			if !change.Remove {
				autoMembers = append(autoMembers, *configs[member.Name])
			}
		}
		if autoChanged {
			for _, change := range changes {
				if change.Expected == "" && !change.Remove {
					autoMembers = append(autoMembers, *configs[change.Name])
				}
			}
			if len(autoMembers) > 0 {
				if err = r013.ValidateCandidates(autoMembers); err != nil {
					return err
				}
			}
			if err = appendBackup(autoFile); err != nil {
				return err
			}
			c := &conf.Config{Name: r013.AutoName}
			path, err := c.Path()
			if err != nil {
				return err
			}
			if err = appendBackup(path); err != nil {
				return err
			}
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	journal, err := rollbackPath()
	if err != nil {
		return err
	}
	if _, err = os.Stat(journal); !os.IsNotExist(err) {
		return errors.New("Есть незавершённое обновление. Перезапустите приложение перед повтором.")
	}
	raw, err := json.Marshal(backups)
	if err != nil {
		return err
	}
	raw, err = dpapi.Encrypt(raw, "VPN013-transaction-v1")
	if err != nil {
		return err
	}
	if err = writeProtected(journal, raw); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if restoreFiles(backups) == nil {
				os.Remove(journal)
			}
		}
	}()
	for _, change := range changes {
		if change.Remove {
			err = conf.DeleteName(change.Name)
			if change.AllowMissing && os.IsNotExist(err) {
				err = nil
			}
		} else {
			err = saveR013Config(configs[change.Name], true)
		}
		if err != nil {
			return errors.New("Применение обновления прервано. Перед повтором проверьте восстановление прежних профилей.")
		}
	}
	if autoChanged {
		if len(autoMembers) == 0 {
			if err = conf.DeleteName(r013.AutoName); err != nil {
				return err
			}
			if err = os.Remove(autoFile); err != nil {
				return err
			}
		} else {
			raw, err = json.Marshal(autoMembers)
			if err != nil {
				return err
			}
			raw, err = dpapi.Encrypt(raw, "VPN013-Auto-v1")
			if err != nil {
				return err
			}
			if err = writeProtected(autoFile, raw); err != nil {
				return err
			}
			first := autoMembers[0]
			first.Name = r013.AutoName
			if err = saveR013Config(&first, true); err != nil {
				return err
			}
		}
	}
	if err = os.Remove(journal); err != nil {
		return err
	}
	committed = true
	IPCServerNotifyTunnelsChange()
	return nil
}
