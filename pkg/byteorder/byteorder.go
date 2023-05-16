// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package byteorder

import (
	"net"
	"net/netip"
)

// NetIPv4ToHost32 converts an net.IP to a uint32 in host byte order. ip
// must be a IPv4 address, otherwise the function will panic.
func NetIPv4ToHost32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	_ = ipv4[3] // Assert length of ipv4.
	return Native.Uint32(ipv4)
}

// NetAddrV4ToHost32 converts a netip.Addr to a uint32 in host byte order. ip
// must be a IPv4 address, otherwise the function will panic.
func NetAddrV4ToHost32(addr netip.Addr) uint32 {
	ipv4 := addr.AsSlice()
	_ = ipv4[3] // Assert length of ipv4.
	return Native.Uint32(ipv4)
}
