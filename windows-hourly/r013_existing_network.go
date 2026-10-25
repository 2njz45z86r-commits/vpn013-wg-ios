// SPDX-License-Identifier: MIT
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013vault"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/sys/windows"
)

// These are existing-TUN owner operations, not an hourly coordinator. The
// caller must keep failed watchers owned for real retirement and rollback.
func (iw *interfaceWatcher) ConfigureExisting(ctx context.Context, binder conn.BindSocketToInterface, original *conf.Config, native *tun.NativeTun) error {
	if original == nil || binder == nil || native == nil {
		return windows.ERROR_INVALID_PARAMETER
	}
	copy, err := r013vault.CopyConfig(*original)
	if err != nil {
		return err
	}
	if len(copy.Interface.Addresses) == 0 || len(copy.Interface.Addresses) > 64 || len(copy.Interface.DNS) > 64 || len(copy.Peers) > 30 {
		return windows.ERROR_INVALID_PARAMETER
	}
	return iw.comparisonGate.Primary(ctx, r013gate.Stamp{}, func(context.Context) error {
		iw.setupMutex.Lock()
		defer iw.setupMutex.Unlock()
		if err := iw.comparisonContext.Err(); err != nil {
			return err
		}
		if iw.tun != nil || len(iw.changeCallbacks4) != 0 || len(iw.changeCallbacks6) != 0 {
			return errors.New("watcher already owns a backend")
		}
		luid := winipcfg.LUID(native.LUID())
		row, err := luid.Interface()
		if err != nil || row.InterfaceIndex == 0 {
			return errors.New("existing TUN interface unavailable")
		}
		iw.binder, iw.conf, iw.tun = binder, &copy, native
		iw.comparisonTunIndex.Store(row.InterfaceIndex)
		iw.storedEvents = nil
		for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			if _, err = luid.IPInterface(family); err != nil {
				if (errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_NOT_SUPPORTED)) && !networkNeedsFamily(&copy, family) {
					continue
				}
				return fmt.Errorf("existing TUN family unavailable: %w", err)
			}
			if err = iw.setupFamilyLocked(family, true); err != nil {
				return err
			}
		}
		// Native DAD is asynchronous; absence of a preferred source is never ready.
		verifyCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		for {
			err = verifyOwnNetwork(luid, &copy)
			if err == nil {
				return nil
			}
			select {
			case <-verifyCtx.Done():
				return fmt.Errorf("existing TUN readback: %w", errors.Join(err, verifyCtx.Err()))
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
}

func networkNeedsFamily(configuration *conf.Config, family winipcfg.AddressFamily) bool {
	matches := func(ip net.IP) bool {
		return (ip.To4() != nil && family == windows.AF_INET) || (ip.To4() == nil && ip.To16() != nil && family == windows.AF_INET6)
	}
	for _, address := range configuration.Interface.Addresses {
		if matches(address.IP) {
			return true
		}
	}
	for _, dns := range configuration.Interface.DNS {
		if matches(dns) {
			return true
		}
	}
	for _, peer := range configuration.Peers {
		for _, route := range peer.AllowedIPs {
			if matches(route.IP) {
				return true
			}
		}
	}
	return false
}

// FlushIPAddresses in the pinned SDK ignores each Delete result. Handover must
// instead collect the actual per-row errors, then independently read back.
func flushOwnNetwork(luid winipcfg.LUID) error {
	var result error
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(family)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("read owned routes: %w", err))
		} else {
			for i := range rows {
				if rows[i].InterfaceLUID == luid {
					if err = rows[i].Delete(); err != nil {
						result = errors.Join(result, fmt.Errorf("delete owned route: %w", err))
					}
				}
			}
		}
		addresses, err := winipcfg.GetUnicastIPAddressTable(family)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("read owned addresses: %w", err))
		} else {
			for i := range addresses {
				if addresses[i].InterfaceLUID == luid {
					if err = addresses[i].Delete(); err != nil {
						result = errors.Join(result, fmt.Errorf("delete owned address: %w", err))
					}
				}
			}
		}
		if _, err = luid.IPInterface(family); err != nil {
			if errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
				continue
			}
			result = errors.Join(result, err)
			continue
		}
		if err = luid.FlushDNS(family); err != nil {
			result = errors.Join(result, fmt.Errorf("clear owned DNS: %w", err))
		}
	}
	return result
}

func verifyOwnNetwork(luid winipcfg.LUID, configuration *conf.Config) error {
	for _, address := range configuration.Interface.Addresses {
		row, err := luid.IPAddress(address.IP)
		if err != nil {
			return fmt.Errorf("source address missing: %w", err)
		}
		if row.DadState != winipcfg.DadStatePreferred || row.OnLinkPrefixLength != address.Cidr {
			return errors.New("source address not preferred or prefix differs")
		}
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, err := luid.IPInterface(family)
		if err != nil {
			if !networkNeedsFamily(configuration, family) && (errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_NOT_SUPPORTED)) {
				continue
			}
			return err
		}
		if configuration.Interface.MTU > 0 && row.NLMTU != uint32(configuration.Interface.MTU) {
			return errors.New("MTU readback differs")
		}
	}
	if !configuration.Interface.TableOff {
		for _, peer := range configuration.Peers {
			for _, prefix := range peer.AllowedIPs {
				// Match the SDK: it installs a family's routes only with a source address.
				haveSource := false
				for _, source := range configuration.Interface.Addresses {
					if source.Bits() == prefix.Bits() {
						haveSource = true
					}
				}
				if !haveSource {
					continue
				}
				prefix.MaskSelf()
				hop := net.IPv6zero
				if prefix.Bits() == 32 {
					hop = net.IPv4zero
				}
				row, err := luid.Route(prefix.IPNet(), hop)
				if err != nil {
					return fmt.Errorf("route readback missing: %w", err)
				}
				if row.InterfaceLUID != luid || row.Metric != 0 {
					return errors.New("route readback differs")
				}
			}
		}
	}
	dns, err := luid.DNS()
	if err != nil {
		return err
	}
	wanted := make(map[string]bool)
	actual := make(map[string]bool)
	for _, ip := range configuration.Interface.DNS {
		wanted[ip.String()] = true
	}
	for _, ip := range dns {
		actual[ip.String()] = true
	}
	if len(actual) != len(wanted) {
		return errors.New("DNS count readback differs")
	}
	for ip := range wanted {
		if !actual[ip] {
			return errors.New("DNS readback differs")
		}
	}
	return nil
}
