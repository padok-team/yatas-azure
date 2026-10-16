package aks

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	logger.Logger.Debug("AKS - Checks started")
	var checkConfig commons.CheckConfig
	checkConfig.Init(c)
	var checks []commons.Check

	list, err := GetClusters(s)
	clusters := internal.Fetch("AKS clusters", list, err)

	go commons.CheckTest(checkConfig.Wg, c, PrivateEndpointID, checkIfPrivateOrRestricted)(checkConfig, clusters, PrivateEndpointID)

	go func() {
		for t := range checkConfig.Queue {
			t.EndCheck()
			checks = append(checks, t)
			checkConfig.Wg.Done()
		}
	}()

	checkConfig.Wg.Wait()

	queue <- checks
	logger.Logger.Debug("AKS - Checks done")
}
