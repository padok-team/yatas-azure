package network

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	logger.Logger.Debug("NET - Checks started")
	var checkConfig commons.CheckConfig
	checkConfig.Init(c)
	var checks []commons.Check

	vnetList, err := GetVNets(s)
	vnets := internal.Fetch("virtual networks", vnetList, err)

	go commons.CheckTest(checkConfig.Wg, c, SingleVNetID, checkIfSingleVNetPerRegion)(checkConfig, vnets, SingleVNetID)
	go commons.CheckTest(checkConfig.Wg, c, PublicPrivateSubnetsID, checkIfPrivateAndPublicSubnets)(checkConfig, vnets, PublicPrivateSubnetsID)
	go commons.CheckTest(checkConfig.Wg, c, TwoSubnetsID, checkIfAtLeastTwoSubnets)(checkConfig, vnets, TwoSubnetsID)
	go commons.CheckTest(checkConfig.Wg, c, ZonesID, checkIfZoneRedundant)(checkConfig, vnets, ZonesID)
	go commons.CheckTest(checkConfig.Wg, c, FlowLogsID, checkIfFlowLogsEnabled)(checkConfig, vnets, FlowLogsID)

	go func() {
		for t := range checkConfig.Queue {
			t.EndCheck()
			checks = append(checks, t)
			checkConfig.Wg.Done()
		}
	}()

	checkConfig.Wg.Wait()

	queue <- checks
	logger.Logger.Debug("NET - Checks done")
}
