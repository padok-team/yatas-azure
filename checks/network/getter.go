package network

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/padok-team/yatas-azure/internal"
)

// Subnet is the part of an Azure subnet the checks care about.
type Subnet struct {
	ID     string
	Name   string
	Public bool // at least one IP configuration of the subnet is bound to a public IP
}

// VNet is a virtual network with everything the HDS network checks need,
// resolved by the getter so the checks stay pure.
type VNet struct {
	ID       string
	Name     string
	Location string
	Subnets  []Subnet
	// VMCount / VMZones describe the virtual machines whose NICs sit in the VNet.
	VMCount int
	VMZones []string
	// FlowLogged is true when an enabled flow log targets the VNet, one of its
	// subnets, or a network security group attached to one of its subnets.
	FlowLogged bool
}

// GetVNets lists the virtual networks of the target and resolves their public
// subnets, VM zone spread and flow-log coverage.
func GetVNets(s internal.Session) ([]VNet, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	ctx := context.TODO()
	sub := s.Target.SubscriptionID

	vnetClient, err := armnetwork.NewVirtualNetworksClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var rawVNets []*armnetwork.VirtualNetwork
	pager := vnetClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		rawVNets = append(rawVNets, page.Value...)
	}

	publicIPConfigs, err := publicIPConfigurationIDs(ctx, s)
	if err != nil {
		return nil, err
	}
	subnetZones, subnetVMs, err := vmsBySubnet(ctx, s)
	if err != nil {
		return nil, err
	}
	flowLogTargets, err := enabledFlowLogTargets(ctx, s)
	if err != nil {
		return nil, err
	}

	var vnets []VNet
	for _, raw := range rawVNets {
		id := internal.Deref(raw.ID)
		if !s.Target.InScope(id) {
			continue
		}
		v := VNet{ID: id, Name: internal.Deref(raw.Name), Location: strings.ToLower(internal.Deref(raw.Location))}
		covered := flowLogTargets[strings.ToLower(id)]
		zones := map[string]bool{}
		if raw.Properties != nil {
			for _, sn := range raw.Properties.Subnets {
				subnetID := internal.Deref(sn.ID)
				subnet := Subnet{ID: subnetID, Name: internal.Deref(sn.Name)}
				if sn.Properties != nil {
					for _, ipc := range sn.Properties.IPConfigurations {
						if publicIPConfigs[strings.ToLower(internal.Deref(ipc.ID))] {
							subnet.Public = true
							break
						}
					}
					if nsg := sn.Properties.NetworkSecurityGroup; nsg != nil && flowLogTargets[strings.ToLower(internal.Deref(nsg.ID))] {
						covered = true
					}
				}
				if flowLogTargets[strings.ToLower(subnetID)] {
					covered = true
				}
				v.Subnets = append(v.Subnets, subnet)
				v.VMCount += subnetVMs[strings.ToLower(subnetID)]
				for z := range subnetZones[strings.ToLower(subnetID)] {
					zones[z] = true
				}
			}
		}
		for z := range zones {
			v.VMZones = append(v.VMZones, z)
		}
		v.FlowLogged = covered
		vnets = append(vnets, v)
	}
	return vnets, nil
}

// publicIPConfigurationIDs returns the (lower-cased) IP configuration IDs that
// are bound to a public IP address.
func publicIPConfigurationIDs(ctx context.Context, s internal.Session) (map[string]bool, error) {
	client, err := armnetwork.NewPublicIPAddressesClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ip := range page.Value {
			if ip.Properties != nil && ip.Properties.IPConfiguration != nil {
				ids[strings.ToLower(internal.Deref(ip.Properties.IPConfiguration.ID))] = true
			}
		}
	}
	return ids, nil
}

// vmsBySubnet maps a (lower-cased) subnet ID to the zones used by the VMs whose
// NICs are in it, and to the number of such VMs.
func vmsBySubnet(ctx context.Context, s internal.Session) (map[string]map[string]bool, map[string]int, error) {
	sub := s.Target.SubscriptionID
	nicClient, err := armnetwork.NewInterfacesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, nil, err
	}
	nicSubnets := map[string][]string{} // lower-cased NIC ID -> lower-cased subnet IDs
	nicPager := nicClient.NewListAllPager(nil)
	for nicPager.More() {
		page, err := nicPager.NextPage(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, nic := range page.Value {
			if nic.Properties == nil {
				continue
			}
			for _, ipc := range nic.Properties.IPConfigurations {
				if ipc.Properties != nil && ipc.Properties.Subnet != nil {
					key := strings.ToLower(internal.Deref(nic.ID))
					nicSubnets[key] = append(nicSubnets[key], strings.ToLower(internal.Deref(ipc.Properties.Subnet.ID)))
				}
			}
		}
	}

	vmClient, err := armcompute.NewVirtualMachinesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, nil, err
	}
	zones := map[string]map[string]bool{}
	counts := map[string]int{}
	vmPager := vmClient.NewListAllPager(nil)
	for vmPager.More() {
		page, err := vmPager.NextPage(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, vm := range page.Value {
			if vm.Properties == nil || vm.Properties.NetworkProfile == nil {
				continue
			}
			seen := map[string]bool{}
			for _, ref := range vm.Properties.NetworkProfile.NetworkInterfaces {
				for _, subnetID := range nicSubnets[strings.ToLower(internal.Deref(ref.ID))] {
					if seen[subnetID] {
						continue
					}
					seen[subnetID] = true
					counts[subnetID]++
					if zones[subnetID] == nil {
						zones[subnetID] = map[string]bool{}
					}
					for _, z := range vm.Zones {
						zones[subnetID][internal.Deref(z)] = true
					}
				}
			}
		}
	}
	return zones, counts, nil
}

// enabledFlowLogTargets returns the (lower-cased) IDs targeted by an enabled flow
// log (NSG flow logs and VNet flow logs) in every Network Watcher.
func enabledFlowLogTargets(ctx context.Context, s internal.Session) (map[string]bool, error) {
	sub := s.Target.SubscriptionID
	watchers, err := armnetwork.NewWatchersClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	flowLogs, err := armnetwork.NewFlowLogsClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	targets := map[string]bool{}
	wPager := watchers.NewListAllPager(nil)
	for wPager.More() {
		page, err := wPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, w := range page.Value {
			rg := internal.ResourceGroupOf(internal.Deref(w.ID))
			fPager := flowLogs.NewListPager(rg, internal.Deref(w.Name), nil)
			for fPager.More() {
				fPage, err := fPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, fl := range fPage.Value {
					if fl.Properties != nil && internal.Deref(fl.Properties.Enabled) {
						targets[strings.ToLower(internal.Deref(fl.Properties.TargetResourceID))] = true
					}
				}
			}
		}
	}
	return targets, nil
}
