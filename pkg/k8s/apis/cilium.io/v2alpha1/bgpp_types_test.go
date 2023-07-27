// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	"errors"
	"fmt"
	"testing"

	"k8s.io/utils/pointer"

	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestBGPPeeringPolicyDefaulting(t *testing.T) {
	var testPolicy = &CiliumBGPPeeringPolicy{
		Spec: CiliumBGPPeeringPolicySpec{
			VirtualRouters: []CiliumBGPVirtualRouter{{LocalASN: 65000}},
		},
	}
	var steps = []struct {
		description      string
		neighbors        []CiliumBGPNeighbor
		validateDefaults func(p *CiliumBGPPeeringPolicy) bool
	}{
		{
			description: "simple policy defaulting",
			neighbors: []CiliumBGPNeighbor{
				{
					PeerASN:     65001,
					PeerAddress: "172.0.0.1/32",
				},
				{
					PeerASN:     65002,
					PeerAddress: "172.0.0.2/32",
				},
			},
			validateDefaults: func(p *CiliumBGPPeeringPolicy) bool {
				for _, r := range p.Spec.VirtualRouters {
					if *r.ExportPodCIDR != DefaultBGPExportPodCIDR {
						return false
					}
					for _, n := range r.Neighbors {
						if *n.PeerPort != DefaultBGPPeerPort ||
							*n.EBGPMultihopTTL != DefaultBGPEBGPMultihopTTL ||
							*n.ConnectRetryTimeSeconds != DefaultBGPConnectRetryTimeSeconds ||
							*n.HoldTimeSeconds != DefaultBGPHoldTimeSeconds ||
							*n.KeepAliveTimeSeconds != DefaultBGPKeepAliveTimeSeconds {
							return false
						}
					}
				}
				return true
			},
		},
		{
			description: "graceful restart defaulting",
			neighbors: []CiliumBGPNeighbor{
				{
					PeerASN:     65001,
					PeerAddress: "172.0.0.1/32",
					GracefulRestart: &CiliumBGPNeighborGracefulRestart{
						Enabled: true,
					},
				},
			},
			validateDefaults: func(p *CiliumBGPPeeringPolicy) bool {
				for _, r := range p.Spec.VirtualRouters {
					for _, n := range r.Neighbors {
						if *n.GracefulRestart.RestartTimeSeconds != DefaultBGPGRRestartTimeSeconds {
							return false
						}
					}
				}
				return true
			},
		},
	}
	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			p := testPolicy.DeepCopy()
			p.Spec.VirtualRouters[0].Neighbors = step.neighbors

			p.SetDefaults()
			if !step.validateDefaults(p) {
				t.Fatalf("policy: not defaulted properly")
			}
		})
	}
}

func TestBGPNeighborValidation(t *testing.T) {
	var steps = []struct {
		description string
		neighbor    *CiliumBGPNeighbor
		expectError error
	}{
		{
			description: "empty timers",
			neighbor: &CiliumBGPNeighbor{
				PeerASN:     65001,
				PeerAddress: "172.0.0.1/32",
			},
			expectError: nil,
		},
		{
			description: "correct timers",
			neighbor: &CiliumBGPNeighbor{
				PeerASN:              65001,
				PeerAddress:          "172.0.0.1/32",
				KeepAliveTimeSeconds: pointer.Int32(3),
				HoldTimeSeconds:      pointer.Int32(9),
			},
			expectError: nil,
		},
		{
			description: "incorrect timers",
			neighbor: &CiliumBGPNeighbor{
				PeerASN:     65001,
				PeerAddress: "172.0.0.1/32",
				// KeepAliveTimeSeconds larger than HoldTimeSeconds = error
				KeepAliveTimeSeconds: pointer.Int32(10),
				HoldTimeSeconds:      pointer.Int32(5),
			},
			expectError: fmt.Errorf("some-error"),
		},
		{
			description: "incorrect timers with default value",
			neighbor: &CiliumBGPNeighbor{
				PeerASN:     65001,
				PeerAddress: "172.0.0.1/32",
				// KeepAliveTimeSeconds larger than default HoldTimeSeconds (90) = error
				KeepAliveTimeSeconds: pointer.Int32(100),
			},
			expectError: fmt.Errorf("some-error"),
		},
	}
	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			err := step.neighbor.Validate()
			if (step.expectError == nil) != (err == nil) {
				t.Fatalf("incorrect validation result - want: %v, got: %v", step.expectError, err)
			}
		})
	}
}

func TestBGPVirtualRouterValidation(t *testing.T) {
	var tests = []struct {
		name   string
		router *CiliumBGPVirtualRouter
		err    error
	}{
		{
			name: "nil ip pool selector",
			router: &CiliumBGPVirtualRouter{
				LocalASN:          1234,
				Neighbors:         []CiliumBGPNeighbor{},
				PodIPPoolSelector: nil,
			},
			err: nil,
		},
		{
			name: "empty ip pool selector",
			router: &CiliumBGPVirtualRouter{
				LocalASN:  1234,
				Neighbors: []CiliumBGPNeighbor{},
				PodIPPoolSelector: &v1.LabelSelector{
					MatchLabels: map[string]string{},
				},
			},
			err: nil,
		},
		{
			name: "ip pool selector with valid prefixes",
			router: &CiliumBGPVirtualRouter{
				LocalASN:  1234,
				Neighbors: []CiliumBGPNeighbor{},
				PodIPPoolSelector: &v1.LabelSelector{
					MatchLabels: map[string]string{"test1": "1.2.3.4/16", "test2": "2001:db8::/32"},
				},
			},
			err: nil,
		},
		{
			name: "ip pool selector with invalid prefix",
			router: &CiliumBGPVirtualRouter{
				LocalASN:  1234,
				Neighbors: []CiliumBGPNeighbor{},
				PodIPPoolSelector: &v1.LabelSelector{
					MatchLabels: map[string]string{"test1": "1.2.3.4.16", "test2": "2001:db8::/32"},
				},
			},
			err: errors.New(""),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.router.Validate()
			if (test.err == nil) != (err == nil) {
				t.Fatalf("incorrect validation result - want: %v, got: %v", test.err, err)
			}
		})
	}
}
