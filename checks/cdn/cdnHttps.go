package cdn

import (
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// HTTPSID is the check's unique, stable ID.
const HTTPSID = "AZURE_CDN_001"

// checkIfHTTPSOnly (≈ AWS "Cloudfronts only allow HTTPS or redirect to HTTPS").
func checkIfHTTPSOnly(checkConfig commons.CheckConfig, entrypoints internal.Fetched[Entrypoint], testName string) {
	check := internal.NewHDSCheck("CDN and Front Door only allow HTTPS or redirect to HTTPS", "Check that all CDN endpoints and Front Door routes are HTTPS only", testName)
	if entrypoints.Failed(&check, "CDN endpoints and Front Door routes") {
		checkConfig.Queue <- check
		return
	}
	for _, e := range entrypoints.Items {
		if e.HTTPSOnly {
			internal.Pass(&check, e.ID, e.Name+" only allows HTTPS or redirects HTTP to HTTPS")
		} else {
			internal.Fail(&check, e.ID, e.Name+" allows plain HTTP traffic")
		}
	}
	checkConfig.Queue <- check
}
