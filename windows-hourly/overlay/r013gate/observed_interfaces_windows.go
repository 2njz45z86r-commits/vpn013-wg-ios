// SPDX-License-Identifier: MIT
package r013gate

import "github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"

func validateObservedInterfaces(o Observation) error {
	tun, err := winipcfg.LUIDFromIndex(o.TunnelIndex)
	if err != nil {
		return ErrCensus
	}
	row, err := tun.Interface()
	if err != nil || row.OperStatus != winipcfg.IfOperStatusUp {
		return ErrCensus
	}
	for _, index := range []uint32{o.Physical4, o.Physical6} {
		if index == 0 {
			continue
		} // IPv6 may be absent; no IPv6 socket can use index zero.
		if index == o.TunnelIndex {
			return ErrCensus
		}
		physical, err := winipcfg.LUIDFromIndex(index)
		if err != nil {
			return ErrCensus
		}
		row, err = physical.Interface()
		if err != nil || row.OperStatus != winipcfg.IfOperStatusUp || (row.Type != winipcfg.IfTypeEthernetCSMACD && row.Type != winipcfg.IfTypeIEEE80211) {
			return ErrCensus
		}
	}
	return nil
}
