// SPDX-License-Identifier: MIT
package firewall

import (
	"encoding/binary"
	"errors"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013routing"
	"net/netip"
	"runtime"
	"unsafe"
)

// Only outbound destination prefixes receive permission. This does not open
// inbound listeners, waive the DNS restriction or disable the terminal block.
// One prefix per filter avoids version-dependent repeated-condition OR rules.
func serviceFirewallNetworks() ([]netip.Prefix, error) {
	rows, err := r013routing.Networks()
	if err != nil {
		return nil, err
	}
	if r013routing.ServicePolicyMode() == r013routing.ServicesOnly {
		// Preserve the existing IPv6 policy; the new selection is IPv4 only.
		kept := rows[:0]
		for _, p := range rows {
			if p.Addr().Is6() {
				kept = append(kept, p)
			}
		}
		rows = kept
	}
	rows = append(rows, r013routing.ServiceDirectIPv4()...)
	if len(rows) > 60000 {
		return nil, errors.New("WFP service policy resource limit")
	}
	return rows, nil
}

func permitRussianNetworks(session uintptr, bo *baseObjects, weight uint8) error {
	rows, err := serviceFirewallNetworks()
	if err != nil {
		return err
	}
	// Stable heap-backed storage survives Go stack growth while the Win32
	// ABI receives integer addresses. WFP copies each condition synchronously.
	v4Masks := make([]wtFwpV4AddrAndMask, len(rows))
	v6Masks := make([]wtFwpV6AddrAndMask, len(rows))
	defer runtime.KeepAlive(v4Masks)
	defer runtime.KeepAlive(v6Masks)
	for i, p := range rows {
		filter := wtFwpmFilter0{providerKey: &bo.provider, subLayerKey: bo.filters, weight: filterWeight(weight), numFilterConditions: 1, action: wtFwpmAction0{_type: cFWP_ACTION_PERMIT}}
		display, err := createWtFwpmDisplayData0("VPN013 Russian destination outbound", r013routing.SnapshotSHA256)
		if err != nil {
			return err
		}
		filter.displayData = *display
		condition := wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: cFWP_MATCH_EQUAL}
		v4 := &v4Masks[i]
		v6 := &v6Masks[i]
		if p.Addr().Is4() {
			a := p.Addr().As4()
			v4.addr = binary.BigEndian.Uint32(a[:])
			v4.mask = ^uint32(0) << uint(32-p.Bits())
			condition.conditionValue = wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(v4))}
			filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4
		} else {
			a := p.Addr().As16()
			v6.addr = a
			v6.prefixLength = uint8(p.Bits())
			condition.conditionValue = wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(v6))}
			filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6
		}
		filter.filterCondition = &condition
		var id uint64
		if err = fwpmFilterAdd0(session, &filter, 0, &id); err != nil {
			return wrapErr(err)
		}
		runtime.KeepAlive(v4)
		runtime.KeepAlive(v6)
		runtime.KeepAlive(condition)
	}
	return nil
}
