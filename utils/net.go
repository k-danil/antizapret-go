package utils

import (
	"encoding/binary"
	"net/netip"
)

func AddrToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func Uint32ToAddr(u uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return netip.AddrFrom4(b)
}
