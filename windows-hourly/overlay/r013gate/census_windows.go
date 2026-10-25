// SPDX-License-Identifier: MIT
package r013gate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc/namedpipe"
	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var ErrCensus = errors.New("actual supported primary membership is not confirmed")

const ownServicePrefix = "VPN013WGTunnel$"

type PrimarySnapshot struct {
	Name        string      `json:"name"`
	Observation Observation `json:"observation"`
	Membership  string      `json:"membership"`
	runtime     string
}

// RuntimeConfiguration contains existing sensitive UAPI values in memory only.
// It is deliberately unexported to JSON and must never be logged/persisted/UI.
func (s PrimarySnapshot) RuntimeConfiguration() string { return s.runtime }

func ExecutableDigest(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrCensus
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ErrCensus
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64*1024*1024 {
		return "", ErrCensus
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, 64*1024*1024+1))
	if err != nil || n != info.Size() {
		return "", ErrCensus
	}
	after, err := file.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", ErrCensus
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type censusEntry struct {
	name       string
	pid        uint32
	state      svc.State
	definition string
}

func enumeratePrimaryServices(ctx context.Context, token Token, image string) ([]censusEntry, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, ErrCensus
	}
	defer manager.Disconnect()
	names, err := manager.ListServices()
	if err != nil {
		return nil, ErrCensus
	}
	sort.Strings(names)
	var entries []censusEntry
	images := make(map[string]string)
	for _, name := range names {
		if ctx.Err() != nil || !token.Valid() {
			return nil, ErrCensus
		}
		prefix := func(value string) bool { return len(name) >= len(value) && strings.EqualFold(name[:len(value)], value) }
		own := prefix(ownServicePrefix)
		foreign := prefix("WireGuardTunnel$") || prefix("AmneziaWGTunnel$")
		if !own && !foreign {
			continue
		}
		service, err := manager.OpenService(name)
		if err != nil {
			return nil, ErrCensus
		}
		status, err := service.Query()
		if err != nil {
			service.Close()
			return nil, ErrCensus
		}
		if foreign {
			service.Close()
			if status.State != svc.Stopped {
				return nil, ErrCensus
			}
			continue
		}
		configuration, err := service.Config()
		service.Close()
		if err != nil {
			return nil, ErrCensus
		}
		if len(entries) >= 64 {
			return nil, ErrCensus
		}
		args, err := windows.DecomposeCommandLine(configuration.BinaryPathName)
		if err != nil || len(args) != 3 || args[1] != "/tunnelservice" || !filepath.IsAbs(args[0]) || !filepath.IsAbs(args[2]) || configuration.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || !strings.EqualFold(configuration.ServiceStartName, "LocalSystem") {
			return nil, ErrCensus
		}
		// Check stopped definitions too: a known old executable must not be able to
		// start outside the managed fence after this census. Administrators running
		// arbitrary external binaries are outside this cooperative lifecycle model.
		path := filepath.Clean(args[0])
		digest, exists := images[strings.ToLower(path)]
		if !exists {
			if len(images) >= 8 {
				return nil, ErrCensus
			}
			digest, err = ExecutableDigest(path)
			if err != nil {
				return nil, ErrCensus
			}
			images[strings.ToLower(path)] = digest
		}
		if digest != image {
			return nil, ErrCensus
		}
		if status.State != svc.Running && status.State != svc.Stopped {
			return nil, ErrCensus
		}
		if status.State == svc.Running && status.ProcessId == 0 {
			return nil, ErrCensus
		}
		entries = append(entries, censusEntry{name, status.ProcessId, status.State, configuration.BinaryPathName})
	}
	if !token.Valid() {
		return nil, ErrCensus
	}
	return entries, nil
}
func censusDigest(entries []censusEntry) string {
	hash := sha256.New()
	for _, entry := range entries {
		fmt.Fprintf(hash, "%d:%s:%d:%d:%d:%s\n", len(entry.name), entry.name, entry.pid, entry.state, len(entry.definition), entry.definition)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
func readActualRuntime(ctx context.Context, name string) (string, error) {
	bound, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	pipe, err := namedpipe.DialContext(bound, `\\.\pipe\ProtectedPrefix\Administrators\VPN013WG\`+name)
	if err != nil {
		return "", ErrCensus
	}
	defer pipe.Close()
	deadline, _ := bound.Deadline()
	pipe.SetDeadline(deadline)
	stop := context.AfterFunc(bound, func() { pipe.Close() })
	defer stop()
	if _, err = pipe.Write([]byte("get=1\n\n")); err != nil {
		return "", ErrCensus
	}
	reader := bufio.NewReader(pipe)
	var body strings.Builder
	for body.Len() < maxUAPIBytes {
		line, err := boundedUAPILine(reader, maxUAPIBytes-body.Len())
		if err != nil {
			return "", ErrCensus
		}
		if line == "\n" {
			if !strings.HasSuffix(body.String(), "errno=0\n") {
				return "", ErrCensus
			}
			return body.String(), nil
		}
		body.WriteString(line)
	}
	return "", ErrCensus
}

// InspectPrimary requires a concrete live Candidate token, exact authorized
// client image hash, fresh actual SCM definitions/PIDs and new pipe metadata.
// It never consults saved Tunnels/manager.State or substitutes an Auto seed.
// All known installed custom definitions are checked, even when stopped; any
// old/unknown/multiple/foreign-active state refuses without stopping profiles.
func InspectPrimary(ctx context.Context, token Token, image, activeName string) (PrimarySnapshot, error) {
	var zero PrimarySnapshot
	digest, err := hex.DecodeString(image)
	if ctx == nil || ctx.Err() != nil || !token.Valid() || err != nil || len(digest) != 32 || strings.ToLower(image) != image || activeName == "" {
		return zero, ErrCensus
	}
	entries, err := enumeratePrimaryServices(ctx, token, image)
	if err != nil {
		return zero, ErrCensus
	}
	var active *censusEntry
	for i := range entries {
		if entries[i].state == svc.Running {
			if active != nil {
				return zero, ErrCensus
			}
			active = &entries[i]
		}
	}
	if active == nil || active.name != ownServicePrefix+activeName {
		return zero, ErrCensus
	}
	observed, err := ReadObservation(ctx, activeName)
	if err != nil || observed.Validate(token, activeName, active.pid) != nil {
		return zero, ErrCensus
	}
	runtime, err := readActualRuntime(ctx, activeName)
	if err != nil {
		return zero, ErrCensus
	}
	identity, err := probe.PublicIdentityDigest(runtime)
	if err != nil || identity != observed.Identity {
		return zero, ErrCensus
	}
	// Both current and candidate transport indexes must be actual, up native
	// interfaces. This also denies an accidentally selected virtual default.
	if err = validateObservedInterfaces(observed); err != nil {
		return zero, ErrCensus
	}
	after, err := enumeratePrimaryServices(ctx, token, image)
	if err != nil || censusDigest(entries) != censusDigest(after) || !token.Valid() {
		return zero, ErrCensus
	}
	return PrimarySnapshot{Name: activeName, Observation: observed, Membership: censusDigest(entries), runtime: runtime}, nil
}
