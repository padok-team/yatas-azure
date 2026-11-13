package network

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	vnetList, err := GetVNets(s)
	vnets := internal.Fetch("virtual networks", vnetList, err)

	internal.RunCategory("NET", c, queue,
		internal.Bind(SingleVNetID, vnets, checkIfSingleVNetPerRegion),
		internal.Bind(PublicPrivateSubnetsID, vnets, checkIfPrivateAndPublicSubnets),
		internal.Bind(TwoSubnetsID, vnets, checkIfAtLeastTwoSubnets),
		internal.Bind(ZonesID, vnets, checkIfZoneRedundant),
		internal.Bind(FlowLogsID, vnets, checkIfFlowLogsEnabled),
		internal.Bind(CIDRSizeID, vnets, checkIfCIDRSize),
		internal.Bind(SingleNATID, vnets, checkIfSingleNATGateway),
	)
}
