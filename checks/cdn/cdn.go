package cdn

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetEntrypoints(s)
	entrypoints := internal.Fetch("CDN endpoints and Front Door routes", list, err)
	profileList, err := GetProfiles(s)
	profiles := internal.Fetch("CDN and Front Door profiles", profileList, err)

	internal.RunCategory("CDN", c, queue,
		internal.Bind(HTTPSID, entrypoints, checkIfHTTPSOnly),
		internal.Bind(WAFID, profiles, checkIfWAF),
		internal.Bind(LogsID, profiles, checkIfLogs),
		internal.Bind(TLSID, profiles, checkIfTLS12),
	)
}
