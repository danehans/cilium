// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package node

import "net"

func firstGlobalV4Addr(intf, preferredIP string, preferPublic bool) (string, error) {
	return "", nil
}

func firstGlobalV6Addr(intf, preferredIP string, preferPublic bool) (string, error) {
	return "", nil
}

// getCiliumHostIPsFromNetDev returns the first IPv4 link local and returns
// it
func getCiliumHostIPsFromNetDev(devName string) (ipv4GW, ipv6Router string) {
	return "", ""
}
