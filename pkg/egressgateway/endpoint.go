// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/types"

	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
)

// endpointMetadata stores relevant metadata associated with a endpoint that's updated during endpoint
// add/update events
type endpointMetadata struct {
	// Endpoint labels
	labels map[string]string
	// Endpoint ID
	id endpointID
	// ips are endpoint's unique IPs
	ips []netip.Addr
}

// endpointID includes endpoint name and namespace
type endpointID = types.NamespacedName

func getEndpointMetadata(endpoint *k8sTypes.CiliumEndpoint, identityLabels labels.Labels) (*endpointMetadata, error) {
	var ipv4s []netip.Addr
	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	if endpoint.Networking == nil {
		return nil, fmt.Errorf("endpoint has no networking metadata")
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			ip, err := netip.ParseAddr(pair.IPV4)
			if err != nil || !ip.Is4() {
				log.Errorf("failed to parse IPV4 pair: %v", err)
				continue
			}
			ipv4s = append(ipv4s, ip)
		}
	}

	if endpoint.Identity == nil {
		return nil, fmt.Errorf("endpoint has no identity metadata")
	}

	data := &endpointMetadata{
		ips:    ipv4s,
		labels: identityLabels.K8sStringMap(),
		id:     id,
	}

	return data, nil
}
