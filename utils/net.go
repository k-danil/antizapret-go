package utils

import (
	"encoding/binary"
	"iter"
	"net"
)

func GetIPv4HostIterator(cidr *net.IPNet) iter.Seq[uint32] {
	ip := IPToUint32(cidr.IP)
	wildcard := ^binary.BigEndian.Uint32(cidr.Mask)
	broadcast := ip | wildcard

	return func(yield func(uint32) bool) {
		for ; ip < broadcast; ip++ {
			if !yield(ip) {
				break
			}
		}
	}
}

func IPToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func Uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}
