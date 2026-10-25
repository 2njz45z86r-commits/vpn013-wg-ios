// SPDX-License-Identifier: MIT
package r013winudp

import (
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

var ErrBind = errors.New("explicit unconnected UDP interface unavailable")

// Pin is only the low-level Windows socket operation. The coordinator MUST
// obtain the index from actual native state and validate its generation before
// and after this call. This function does not guess a physical or VPN interface.
// IPv4 SET is network byte order, GET is host byte order (Microsoft IP_UNICAST_IF).
func Pin(fd uintptr, family int, index uint32) error {
	if fd == 0 || windows.Handle(fd) == windows.InvalidHandle || index == 0 {
		return ErrBind
	}
	level := windows.IPPROTO_IP
	value := index
	switch family {
	case windows.AF_INET:
		if index >= 1<<24 {
			return ErrBind
		}
		var bytes [4]byte
		binary.BigEndian.PutUint32(bytes[:], index)
		value = *(*uint32)(unsafe.Pointer(&bytes[0]))
	case windows.AF_INET6:
		level = windows.IPPROTO_IPV6
	default:
		return ErrBind
	}
	socket := windows.Handle(fd)
	// SO_TYPE is also 0x1008 in the pinned Go SDK's internal/syscall/windows.
	const socketType = 0x1008
	kind, err := windows.GetsockoptInt(socket, windows.SOL_SOCKET, socketType)
	if err != nil || kind != windows.SOCK_DGRAM {
		return ErrBind
	}
	if _, err = windows.Getpeername(socket); err != windows.WSAENOTCONN {
		return ErrBind
	}
	const unicastInterface = 31
	if windows.SetsockoptInt(socket, level, unicastInterface, int(value)) != nil {
		return ErrBind
	}
	actual, err := windows.GetsockoptInt(socket, level, unicastInterface)
	if err != nil || uint32(actual) != index {
		return ErrBind
	}
	return nil
}
