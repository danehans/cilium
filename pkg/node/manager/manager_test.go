// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gopkg.in/check.v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath/fake"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type managerTestSuite struct{}

var _ = check.Suite(&managerTestSuite{})

type configMock struct {
	Tunneling          bool
	RemoteNodeIdentity bool
	NodeEncryption     bool
	Encryption         bool
}

func (c *configMock) TunnelingEnabled() bool {
	return c.Tunneling
}

func (c *configMock) RemoteNodeIdentitiesEnabled() bool {
	return c.RemoteNodeIdentity
}

func (c *configMock) NodeEncryptionEnabled() bool {
	return c.NodeEncryption
}

func (c *configMock) EncryptionEnabled() bool {
	return c.Encryption
}

type nodeEvent struct {
	event string
	ip    *netip.Addr
}

type ipcacheMock struct {
	events chan nodeEvent
}

func newIPcacheMock() *ipcacheMock {
	return &ipcacheMock{
		events: make(chan nodeEvent, 1024),
	}
}

func AddrOrPrefixToIP(ip string) (*netip.Addr, error) {
	prefix, err := netip.ParsePrefix(ip)
	if err == nil {
		addr := prefix.Addr()
		return &addr, nil
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}

	return &addr, nil
}

func (i *ipcacheMock) Upsert(ip string, hostIP *netip.Addr, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error) {
	addr, err := AddrOrPrefixToIP(ip)
	if err != nil {
		i.events <- nodeEvent{fmt.Sprintf("upsert failed: %s", err), addr}
		return false, err
	}
	i.events <- nodeEvent{"upsert", addr}
	return false, nil
}

func (i *ipcacheMock) Delete(ip string, source source.Source) bool {
	addr, err := AddrOrPrefixToIP(ip)
	if err != nil {
		i.events <- nodeEvent{fmt.Sprintf("delete failed: %s", err), addr}
		return false
	}
	i.events <- nodeEvent{"delete", addr}
	return false
}

func (i *ipcacheMock) UpsertLabels(netip.Prefix, labels.Labels, source.Source, ipcacheTypes.ResourceID) {
}

type signalNodeHandler struct {
	EnableNodeAddEvent                    bool
	NodeAddEvent                          chan nodeTypes.Node
	NodeUpdateEvent                       chan nodeTypes.Node
	EnableNodeUpdateEvent                 bool
	NodeDeleteEvent                       chan nodeTypes.Node
	EnableNodeDeleteEvent                 bool
	NodeValidateImplementationEvent       chan nodeTypes.Node
	EnableNodeValidateImplementationEvent bool
}

func newSignalNodeHandler() *signalNodeHandler {
	return &signalNodeHandler{
		NodeAddEvent:                    make(chan nodeTypes.Node, 10),
		NodeUpdateEvent:                 make(chan nodeTypes.Node, 10),
		NodeDeleteEvent:                 make(chan nodeTypes.Node, 10),
		NodeValidateImplementationEvent: make(chan nodeTypes.Node, 4096),
	}
}

func (n *signalNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	if n.EnableNodeAddEvent {
		n.NodeAddEvent <- newNode
	}
	return nil
}

func (n *signalNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	if n.EnableNodeUpdateEvent {
		n.NodeUpdateEvent <- newNode
	}
	return nil
}

func (n *signalNodeHandler) NodeDelete(node nodeTypes.Node) error {
	if n.EnableNodeDeleteEvent {
		n.NodeDeleteEvent <- node
	}
	return nil
}

func (n *signalNodeHandler) NodeValidateImplementation(node nodeTypes.Node) error {
	if n.EnableNodeValidateImplementationEvent {
		n.NodeValidateImplementationEvent <- node
	}
	return nil
}

func (n *signalNodeHandler) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {
	return nil
}

func (n *signalNodeHandler) NodeNeighDiscoveryEnabled() bool {
	return false
}

func (n *signalNodeHandler) NodeNeighborRefresh(ctx context.Context, node nodeTypes.Node) {
	return
}

func (n *signalNodeHandler) NodeCleanNeighbors(migrateOnly bool) {
	return
}

func (n *signalNodeHandler) AllocateNodeID(_ *netip.Addr) uint16 {
	return 0
}

func (n *signalNodeHandler) DumpNodeIDs() []*models.NodeID {
	return nil
}

func (n *signalNodeHandler) RestoreNodeIDs() {
	return
}

func (s *managerTestSuite) SetUpSuite(c *check.C) {
}

func (s *managerTestSuite) TestNodeLifecycle(c *check.C) {
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	ipcacheMock := newIPcacheMock()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	mngr.Subscribe(dp)
	c.Assert(err, check.IsNil)

	n1 := nodeTypes.Node{Name: "node1", Cluster: "c1"}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	n2 := nodeTypes.Node{Name: "node2", Cluster: "c1"}
	mngr.NodeUpdated(n2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n2)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeUpdate() event for node2")
	}

	nodes := mngr.GetNodes()
	n, ok := nodes[n1.Identity()]
	c.Assert(ok, check.Equals, true)
	c.Assert(n, checker.DeepEquals, n1)

	mngr.NodeDeleted(n1)
	select {
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeDelete() event for node1")
	}
	nodes = mngr.GetNodes()
	_, ok = nodes[n1.Identity()]
	c.Assert(ok, check.Equals, false)

	err = mngr.Stop(context.TODO())
	c.Assert(err, check.IsNil)
}

func (s *managerTestSuite) TestMultipleSources(c *check.C) {
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	ipcacheMock := newIPcacheMock()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1k8s := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Kubernetes}
	mngr.NodeUpdated(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1k8s)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	// agent can overwrite kubernetes
	n1agent := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Local}
	mngr.NodeUpdated(n1agent)
	select {
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1agent)
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeUpdate() event for node1")
	}

	// kubernetes cannot overwrite local node
	mngr.NodeUpdated(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(100 * time.Millisecond):
	}

	// delete from kubernetes, should not remove local node
	mngr.NodeDeleted(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(100 * time.Millisecond):
	}

	mngr.NodeDeleted(n1agent)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1agent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeDelete() event for node1")
	}
}

func (s *managerTestSuite) BenchmarkUpdateAndDeleteCycle(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := fake.NewNodeHandler()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeUpdated(n)
	}

	for i := 0; i < c.N; i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeDeleted(n)
	}
	c.StopTimer()
}

func (s *managerTestSuite) TestClusterSizeDependantInterval(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := fake.NewNodeHandler()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	prevInterval := time.Nanosecond

	for i := 0; i < 1000; i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeUpdated(n)
		newInterval := mngr.ClusterSizeDependantInterval(time.Minute)
		c.Assert(newInterval > prevInterval, check.Equals, true)
	}
}

func (s *managerTestSuite) TestBackgroundSync(c *check.C) {
	c.Skip("GH-6751 Test is disabled due to being unstable")

	// set the base background sync interval to a very low value so the
	// background sync runs aggressively
	baseBackgroundSyncIntervalBackup := baseBackgroundSyncInterval
	baseBackgroundSyncInterval = 10 * time.Millisecond
	defer func() { baseBackgroundSyncInterval = baseBackgroundSyncIntervalBackup }()

	signalNodeHandler := newSignalNodeHandler()
	signalNodeHandler.EnableNodeValidateImplementationEvent = true
	ipcacheMock := newIPcacheMock()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	mngr.Subscribe(signalNodeHandler)
	c.Assert(err, check.IsNil)
	defer mngr.Stop(context.TODO())

	numNodes := 4096

	allNodeValidateCallsReceived := &sync.WaitGroup{}
	allNodeValidateCallsReceived.Add(1)

	go func() {
		nodeValidationsReceived := 0
		timer, timerDone := inctimer.New()
		defer timerDone()
		for {
			select {
			case <-signalNodeHandler.NodeValidateImplementationEvent:
				nodeValidationsReceived++
				if nodeValidationsReceived >= numNodes {
					allNodeValidateCallsReceived.Done()
					return
				}
			case <-timer.After(time.Second * 5):
				c.Errorf("Timeout while waiting for NodeValidateImplementation() to be called")
			}
		}
	}()

	for i := 0; i < numNodes; i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Kubernetes}
		mngr.NodeUpdated(n)
	}

	allNodeValidateCallsReceived.Wait()
}

func (s *managerTestSuite) TestIpcache(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())
	ci := netip.MustParseAddr("1.1.1.1")

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: ci},
			{Type: addressing.NodeInternalIP, IP: netip.MustParseAddr("10.0.0.2")},
			{Type: addressing.NodeExternalIP, IP: netip.MustParseAddr("f00d::1")},
		},
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &ci})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", ci.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &ci})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", ci.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestIpcacheHealthIP(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())
	ci := netip.MustParseAddr("1.1.1.1")
	healthV4 := netip.MustParseAddr("10.0.0.4")
	healthV6 := netip.MustParseAddr("f00d::4")

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: ci},
		},
		IPv4HealthIP: &healthV4,
		IPv6HealthIP: &healthV6,
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &ci})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", ci.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &healthV4})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", healthV4.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &healthV6})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", healthV6.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &ci})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", ci.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &healthV4})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", healthV4.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &healthV6})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", healthV6.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestRemoteNodeIdentities(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	mngr, err := New("test", &configMock{RemoteNodeIdentity: true}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())
	ci := netip.MustParseAddr("1.1.1.1")
	intV4 := netip.MustParseAddr("10.0.0.2")
	extV6 := netip.MustParseAddr("f00d::1")

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: ci},
			{Type: addressing.NodeInternalIP, IP: intV4},
			{Type: addressing.NodeExternalIP, IP: extV6},
		},
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &ci})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", ci.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &intV4})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", intV4.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &extV6})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", extV6.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &ci})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", ci.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &intV4})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", intV4.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &extV6})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", extV6.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestNodeEncryption(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	mngr, err := New("test", &configMock{NodeEncryption: true, Encryption: true}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())
	ci := netip.MustParseAddr("1.1.1.1")
	intV4 := netip.MustParseAddr("10.0.0.2")
	extV6 := netip.MustParseAddr("f00d::1")

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: ci},
			{Type: addressing.NodeInternalIP, IP: intV4},
			{Type: addressing.NodeExternalIP, IP: extV6},
		},
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &ci})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", intV4.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &intV4})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", intV4.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: &extV6})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP %s", extV6.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &ci})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", ci.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &intV4})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", intV4.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: &extV6})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP %s", extV6.String())
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestNode(c *check.C) {
	ipcacheMock := newIPcacheMock()
	ipcacheExpect := func(eventType, ipStr string) {
		select {
		case event := <-ipcacheMock.events:
			ip := netip.MustParseAddr(ipStr)
			if !c.Check(event, checker.DeepEquals, nodeEvent{event: eventType, ip: &ip}) {
				// Panic just to get a stack trace so you can find the source of the problem
				panic("assertion failed")
			}
		case <-time.After(5 * time.Second):
			c.Errorf("timeout while waiting for ipcache upsert for IP %s", ipStr)
		}
	}

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())
	ciV4 := netip.MustParseAddr("192.0.2.1")
	ciV6 := netip.MustParseAddr("2001:DB8::1")
	healthV4 := netip.MustParseAddr("192.0.2.2")
	healthV6 := netip.MustParseAddr("2001:DB8::2")

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   ciV4,
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   ciV6,
			},
		},
		IPv4HealthIP: &healthV4,
		IPv6HealthIP: &healthV6,
		Source:       source.KVStore,
	}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	ipcacheExpect("upsert", ciV4.String())
	ipcacheExpect("upsert", ciV6.String())
	ipcacheExpect("upsert", healthV4.String())
	ipcacheExpect("upsert", healthV6.String())

	n1V2 := n1.DeepCopy()
	nextCIv4 := ciV4.Next()
	nextCIv6 := ciV6.Next()
	nextHealthV4 := healthV4.Next()
	nextHealthV6 := healthV6.Next()
	n1V2.IPAddresses = []nodeTypes.Address{
		{
			Type: addressing.NodeCiliumInternalIP,
			IP:   nextCIv4,
		},
		{
			// We will keep the IPv6 the same to make sure we will not delete it
			Type: addressing.NodeCiliumInternalIP,
			IP:   nextCIv6,
		},
	}
	n1V2.IPv4HealthIP = &nextHealthV4
	n1V2.IPv6HealthIP = &nextHealthV6
	mngr.NodeUpdated(*n1V2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Assert(nodeEvent, checker.DeepEquals, *n1V2)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeUpdate() event for node2")
	}

	ipcacheExpect("upsert", nextCIv4.String())
	ipcacheExpect("upsert", nextCIv6.String())
	ipcacheExpect("upsert", nextHealthV4.String())
	ipcacheExpect("upsert", nextHealthV6.String())

	ipcacheExpect("delete", ciV4.String())
	ipcacheExpect("delete", healthV4.String())
	ipcacheExpect("delete", healthV6.String())

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("Received unexpected event %s", event)
	case <-time.After(1 * time.Second):
	}

	nodes := mngr.GetNodes()
	c.Assert(len(nodes), check.Equals, 1)
	n, ok := nodes[n1.Identity()]
	c.Assert(ok, check.Equals, true)
	// Needs to be the same as n2
	c.Assert(n, checker.DeepEquals, *n1V2)
}
