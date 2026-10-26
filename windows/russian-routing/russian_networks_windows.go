// SPDX-License-Identifier: MIT
package firewall

import (
	"encoding/binary"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013routing"
	"runtime"
	"unsafe"
)

// Only outbound destination prefixes receive permission. This does not open
// inbound listeners, waive the DNS restriction or disable the terminal block.
// One prefix per filter avoids version-dependent repeated-condition OR rules.
func permitRussianNetworks(session uintptr, bo *baseObjects, weight uint8) error {
	rows, err := r013routing.Networks()
	if err != nil {
		return err
	}
	for _, p := range rows {
		filter := wtFwpmFilter0{providerKey: &bo.provider, subLayerKey: bo.filters, weight: filterWeight(weight), numFilterConditions: 1, action: wtFwpmAction0{_type: cFWP_ACTION_PERMIT}}
		display, err := createWtFwpmDisplayData0("VPN013 Russian destination outbound", r013routing.SnapshotSHA256)
		if err != nil {
			return err
		}
		filter.displayData = *display
		condition := wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: cFWP_MATCH_EQUAL}
		var v4 wtFwpV4AddrAndMask
		var v6 wtFwpV6AddrAndMask
		if p.Addr().Is4() {
			a := p.Addr().As4()
			v4.addr = binary.BigEndian.Uint32(a[:])
			v4.mask = ^uint32(0) << uint(32-p.Bits())
			condition.conditionValue = wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(&v4))}
			filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4
		} else {
			a := p.Addr().As16()
			v6.addr = a
			v6.prefixLength = uint8(p.Bits())
			condition.conditionValue = wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(&v6))}
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
