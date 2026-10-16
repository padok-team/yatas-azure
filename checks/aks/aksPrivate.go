package aks

import (
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// PrivateEndpointID is the check's unique, stable ID.
const PrivateEndpointID = "AZURE_AKS_001"

// checkIfPrivateOrRestricted (≈ AWS "EKS clusters have private endpoint or strict
// public access"): a private cluster, or a public API server limited to
// authorized IP ranges that don't include the whole Internet.
func checkIfPrivateOrRestricted(checkConfig commons.CheckConfig, clusters internal.Fetched[Cluster], testName string) {
	check := internal.NewHDSCheck("AKS clusters have private endpoint or strict public access", "Check that AKS API servers are private or restricted to authorized IP ranges", testName)
	if clusters.Failed(&check, "AKS clusters") {
		checkConfig.Queue <- check
		return
	}
	for _, c := range clusters.Items {
		openToAll := false
		for _, r := range c.AuthorizedIPRanges {
			if r == "0.0.0.0/0" {
				openToAll = true
			}
		}
		switch {
		case c.Private:
			internal.Pass(&check, c.ID, "AKS cluster "+c.Name+" is a private cluster")
		case len(c.AuthorizedIPRanges) == 0:
			internal.Fail(&check, c.ID, "AKS cluster "+c.Name+" has a public API server open to every IP")
		case openToAll:
			internal.Fail(&check, c.ID, "AKS cluster "+c.Name+" authorizes 0.0.0.0/0 on its public API server")
		default:
			internal.Pass(&check, c.ID, "AKS cluster "+c.Name+" restricts its public API server to authorized IP ranges")
		}
	}
	checkConfig.Queue <- check
}
