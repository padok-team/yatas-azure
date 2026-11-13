package aks

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetClusters(s)
	clusters := internal.Fetch("AKS clusters", list, err)

	internal.RunCategory("AKS", c, queue,
		internal.Bind(PrivateEndpointID, clusters, checkIfPrivateOrRestricted),
		internal.Bind(LoggingID, clusters, checkIfControlPlaneLogs),
	)
}
