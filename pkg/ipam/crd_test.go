// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

func TestIPNotAvailableInPoolError(t *testing.T) {
	err := NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	err2 := NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	assert.Equal(t, err, err2)
	assert.True(t, errors.Is(err, err2))

	err = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.False(t, errors.Is(err, err2))

	err = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	err2 = errors.New("another error")
	assert.NotEqual(t, err, err2)
	assert.False(t, errors.Is(err, err2))

	err = errors.New("another error")
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.False(t, errors.Is(err, err2))

	err = NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	err2 = nil
	assert.False(t, errors.Is(err, err2))

	err = nil
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("1.1.1.1"))
	assert.False(t, errors.Is(err, err2))

	// We don't match against strings. It must be the sentinel value.
	err = errors.New("IP 2.1.1.1 is not available")
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("2.1.1.1"))
	assert.NotEqual(t, err, err2)
	assert.False(t, errors.Is(err, err2))

	// IPv6 Test Cases
	err = NewIPNotAvailableInPoolError(net.ParseIP("2001:db8::1"))
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("2001:db8::1"))
	assert.Equal(t, err, err2)
	assert.True(t, errors.Is(err, err2))

	err = NewIPNotAvailableInPoolError(net.ParseIP("2001:db8::1"))
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("2001:db8::2"))
	assert.NotEqual(t, err, err2)
	assert.False(t, errors.Is(err, err2))

	err = NewIPNotAvailableInPoolError(net.ParseIP("2001:db8::2"))
	err2 = errors.New("another error")
	assert.NotEqual(t, err, err2)
	assert.False(t, errors.Is(err, err2))

	err = errors.New("another IPv6 error")
	err2 = NewIPNotAvailableInPoolError(net.ParseIP("2001:db8::2"))
	assert.NotEqual(t, err, err2)
	assert.False(t, errors.Is(err, err2))
}

var testConfigurationCRD = &option.DaemonConfig{
	EnableIPv4:              true,
	EnableIPv6:              false,
	EnableHealthChecking:    true,
	EnableUnreachableRoutes: false,
	IPAM:                    ipamOption.IPAMCRD,
}

func newFakeNodeStore(conf *option.DaemonConfig, t *testing.T) *nodeStore {
	tr, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "fake-crd-allocator-node-refresher",
		MinInterval: 3 * time.Second,
		TriggerFunc: func(reasons []string) {},
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize CiliumNode synchronization trigger")
	}
	store := &nodeStore{
		allocators:         []*crdAllocator{},
		allocationPoolSize: map[Family]int{},
		conf:               conf,
		refreshTrigger:     tr,
	}
	return store
}

func TestMarkForReleaseNoAllocate(t *testing.T) {
	cn := newCiliumNode("node1", 4, 4, 0)
	dummyResource := ipamTypes.AllocationIP{Resource: "foo"}
	for i := 1; i <= 4; i++ {
		cn.Spec.IPAM.Pool[fmt.Sprintf("1.1.1.%d", i)] = dummyResource
	}

	fakeAddressing := fakeTypes.NewNodeAddressing()
	conf := testConfigurationCRD
	initNodeStore.Do(func() {
		sharedNodeStore = newFakeNodeStore(conf, t)
		sharedNodeStore.ownNode = cn
	})
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(fakeAddressing, conf, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil)
	sharedNodeStore.updateLocalNodeResource(cn)

	// Allocate the first 3 IPs
	for i := 1; i <= 3; i++ {
		epipv4 := netip.MustParseAddr(fmt.Sprintf("1.1.1.%d", i))
		_, err := ipam.IPv4Allocator.Allocate(epipv4.AsSlice(), fmt.Sprintf("test%d", i), PoolDefault())
		require.Nil(t, err)
	}

	// Update 1.1.1.4 as marked for release like operator would.
	cn.Status.IPAM.ReleaseIPs["1.1.1.4"] = ipamOption.IPAMMarkForRelease
	// Attempts to allocate 1.1.1.4 should fail, since it's already marked for release
	epipv4 := netip.MustParseAddr("1.1.1.4")
	_, err := ipam.IPv4Allocator.Allocate(epipv4.AsSlice(), "test", PoolDefault())
	require.Error(t, err)
	// Call agent's CRD update function. status for 1.1.1.4 should change from marked for release to ready for release
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMReadyForRelease, string(cn.Status.IPAM.ReleaseIPs["1.1.1.4"]))

	// Verify that 1.1.1.3 is denied for release, since it's already in use
	cn.Status.IPAM.ReleaseIPs["1.1.1.3"] = ipamOption.IPAMMarkForRelease
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMDoNotRelease, string(cn.Status.IPAM.ReleaseIPs["1.1.1.3"]))
}

func TestMarkForReleaseNoAllocateIPv6(t *testing.T) {
	// Enable IPv6 and disable IPv4 for this test
	testConfigurationCRD.EnableIPv4 = false
	testConfigurationCRD.EnableIPv6 = true

	cn := newIPv6CiliumNode("node-ipv6", 4, 4, 0)
	dummyResource := ipamTypes.AllocationIP{Resource: "foo"}
	for i := 1; i <= 4; i++ {
		cn.Spec.IPAM.IPv6Pool[fmt.Sprintf("fd00::%d", i)] = dummyResource
	}

	fakeAddressing := fakeTypes.NewIPv6OnlyNodeAddressing()
	conf := testConfigurationCRD
	initNodeStore.Do(func() {
		sharedNodeStore = newFakeNodeStore(conf, t)
		sharedNodeStore.ownNode = cn
	})
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(fakeAddressing, conf, &ownerMock{}, localNodeStore, &ownerMock{}, &resourceMock{}, &mtuMock, nil)
	sharedNodeStore.updateLocalNodeResource(cn)

	// Allocate the first 3 IPv6 IPs
	for i := 1; i <= 3; i++ {
		epipv6 := netip.MustParseAddr(fmt.Sprintf("fd00::%d", i))
		_, err := ipam.IPv6Allocator.Allocate(epipv6.AsSlice(), fmt.Sprintf("test%d", i), PoolDefault())
		require.Nil(t, err)
	}

	// Mark fd00::4 for release and verify behavior
	ipv6Addr := "fd00::4"
	cn.Status.IPAM.ReleaseIPv6s[ipv6Addr] = ipamOption.IPAMMarkForRelease

	// Attempts to allocate fd00::4 should fail
	epipv6 := netip.MustParseAddr(ipv6Addr)
	_, err := ipam.IPv6Allocator.Allocate(epipv6.AsSlice(), "test4", PoolDefault())
	require.NotNil(t, err)

	// Call agent's CRD update function. Status for fd00::4 should change from marked for release to ready for release
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMReadyForRelease, string(cn.Status.IPAM.ReleaseIPv6s[ipv6Addr]))

	// Verify that fd00::3 is denied for release, since they are already in use
	cn.Status.IPAM.ReleaseIPv6s["fd00::3"] = ipamOption.IPAMMarkForRelease
	sharedNodeStore.updateLocalNodeResource(cn)
	require.Equal(t, ipamOption.IPAMDoNotRelease, string(cn.Status.IPAM.ReleaseIPv6s["fd00::3"]))

	// Reset IPv4 and IPv6 enable flags after test
	testConfigurationCRD.EnableIPv6 = false
	testConfigurationCRD.EnableIPv4 = true
}
