package network

import (
	"fmt"
	"sort"
	"strings"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	SingleVNetID           = "AZURE_NET_001"
	PublicPrivateSubnetsID = "AZURE_NET_002"
	TwoSubnetsID           = "AZURE_NET_003"
	ZonesID                = "AZURE_NET_004"
	FlowLogsID             = "AZURE_NET_005"
)

// AZURE_NET_001 (≈ AWS "VPC can't be in the same account"): a subscription is the
// Azure isolation boundary, so it should hold a single VNet per region.
func checkIfSingleVNetPerRegion(checkConfig commons.CheckConfig, vnets internal.Fetched[VNet], testName string) {
	check := internal.NewHDSCheck("VNet can't be in the same subscription", "Check that the subscription has only one virtual network per region", testName)
	if vnets.Failed(&check, "virtual networks") {
		checkConfig.Queue <- check
		return
	}
	byLocation := map[string][]string{}
	for _, v := range vnets.Items {
		byLocation[v.Location] = append(byLocation[v.Location], v.Name)
	}
	locations := make([]string, 0, len(byLocation))
	for l := range byLocation {
		locations = append(locations, l)
	}
	sort.Strings(locations)
	for _, l := range locations {
		names := byLocation[l]
		if len(names) > 1 {
			internal.Fail(&check, l, fmt.Sprintf("Region %s has %d VNets in the subscription (%s)", l, len(names), strings.Join(names, ", ")))
		} else {
			internal.Pass(&check, l, fmt.Sprintf("Region %s has a single VNet (%s)", l, names[0]))
		}
	}
	checkConfig.Queue <- check
}

// AZURE_NET_002 (≈ AWS "VPCs have private and public subnets"). A subnet is
// public when one of its IP configurations is bound to a public IP address.
func checkIfPrivateAndPublicSubnets(checkConfig commons.CheckConfig, vnets internal.Fetched[VNet], testName string) {
	check := internal.NewHDSCheck("VNets have private and public subnets", "Check that VNets segment public-facing subnets (public IP) from private subnets", testName)
	if vnets.Failed(&check, "virtual networks") {
		checkConfig.Queue <- check
		return
	}
	for _, v := range vnets.Items {
		hasPublic, hasPrivate := false, false
		for _, sn := range v.Subnets {
			if sn.Public {
				hasPublic = true
			} else {
				hasPrivate = true
			}
		}
		switch {
		case !hasPublic:
			internal.Fail(&check, v.ID, "VNet "+v.Name+" has no public subnet")
		case !hasPrivate:
			internal.Fail(&check, v.ID, "VNet "+v.Name+" has no private subnet")
		default:
			internal.Pass(&check, v.ID, "VNet "+v.Name+" has at least one public and one private subnet")
		}
	}
	checkConfig.Queue <- check
}

// AZURE_NET_003 (≈ AWS "VPC have at least 2 subnets").
func checkIfAtLeastTwoSubnets(checkConfig commons.CheckConfig, vnets internal.Fetched[VNet], testName string) {
	check := internal.NewHDSCheck("VNet have at least 2 subnets", "Check that VNets have at least 2 subnets (network segmentation baseline)", testName)
	if vnets.Failed(&check, "virtual networks") {
		checkConfig.Queue <- check
		return
	}
	for _, v := range vnets.Items {
		if len(v.Subnets) < 2 {
			internal.Fail(&check, v.ID, fmt.Sprintf("VNet %s has %d subnet(s), at least 2 are required", v.Name, len(v.Subnets)))
		} else {
			internal.Pass(&check, v.ID, fmt.Sprintf("VNet %s has %d subnets", v.Name, len(v.Subnets)))
		}
	}
	checkConfig.Queue <- check
}

// AZURE_NET_004 (≈ AWS "VPC's Subnets are in different zones"). Azure subnets
// are regional, so zone spread is judged on the VMs hosted in the VNet: when it
// hosts several VMs they must run in at least 2 availability zones.
func checkIfZoneRedundant(checkConfig commons.CheckConfig, vnets internal.Fetched[VNet], testName string) {
	check := internal.NewHDSCheck("VNet resources are spread over availability zones", "Check that the virtual machines of a VNet are deployed in at least 2 availability zones", testName)
	if vnets.Failed(&check, "virtual networks") {
		checkConfig.Queue <- check
		return
	}
	for _, v := range vnets.Items {
		switch {
		case v.VMCount < 2:
			internal.Pass(&check, v.ID, fmt.Sprintf("VNet %s hosts %d VM(s), no zone spread needed", v.Name, v.VMCount))
		case len(v.VMZones) < 2:
			internal.Fail(&check, v.ID, fmt.Sprintf("VNet %s hosts %d VMs but they use %d availability zone(s)", v.Name, v.VMCount, len(v.VMZones)))
		default:
			internal.Pass(&check, v.ID, fmt.Sprintf("VNet %s hosts %d VMs over %d availability zones", v.Name, v.VMCount, len(v.VMZones)))
		}
	}
	checkConfig.Queue <- check
}

// AZURE_NET_005 (≈ AWS "VPC Flow Logs are activated").
func checkIfFlowLogsEnabled(checkConfig commons.CheckConfig, vnets internal.Fetched[VNet], testName string) {
	check := internal.NewHDSCheck("VNet Flow Logs are activated", "Check that VNet flow logs (or NSG flow logs) are enabled for every VNet", testName)
	if vnets.Failed(&check, "virtual networks and flow logs") {
		checkConfig.Queue <- check
		return
	}
	for _, v := range vnets.Items {
		if v.FlowLogged {
			internal.Pass(&check, v.ID, "Flow logs are enabled for VNet "+v.Name)
		} else {
			internal.Fail(&check, v.ID, "Flow logs are not enabled for VNet "+v.Name)
		}
	}
	checkConfig.Queue <- check
}
