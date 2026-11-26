package functions

import (
	"context"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	VNetID  = "AZURE_FUNC_001"
	HTTPSID = "AZURE_FUNC_002"
)

// App is an Azure Function App.
type App struct {
	ID        string
	Name      string
	VNet      bool // regional VNet integration
	PublicOff bool // public network access disabled
	HTTPSOnly bool
}

// GetApps lists the Function Apps of the target.
func GetApps(s internal.Session) ([]App, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armappservice.NewWebAppsClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var apps []App
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			id := internal.Deref(raw.ID)
			if !s.Target.InScope(id) || !strings.Contains(strings.ToLower(internal.Deref(raw.Kind)), "functionapp") {
				continue
			}
			a := App{ID: id, Name: internal.Deref(raw.Name)}
			if p := raw.Properties; p != nil {
				a.VNet = internal.Deref(p.VirtualNetworkSubnetID) != ""
				a.PublicOff = strings.EqualFold(internal.Deref(p.PublicNetworkAccess), "Disabled")
				a.HTTPSOnly = internal.Deref(p.HTTPSOnly)
			}
			apps = append(apps, a)
		}
	}
	return apps, nil
}

// checkIfPrivate (≈ AWS "Lambda are in a VPC / private").
func checkIfPrivate(cfg commons.CheckConfig, in internal.Fetched[App], id string) {
	check := internal.NewCheck("Function Apps are private", "Check that Function Apps use VNet integration or have public network access disabled", id)
	internal.Evaluate(cfg, check, in, "Function Apps", func(a App) *internal.Verdict {
		if a.VNet || a.PublicOff {
			return internal.Yes(a.ID, "Function App "+a.Name+" is private")
		}
		return internal.No(a.ID, "Function App "+a.Name+" has no VNet integration and is publicly reachable")
	})
}

// checkIfHTTPSOnly: functions must not serve plain HTTP.
func checkIfHTTPSOnly(cfg commons.CheckConfig, in internal.Fetched[App], id string) {
	check := internal.NewCheck("Function Apps only accept HTTPS", "Check that Function Apps redirect HTTP to HTTPS", id)
	internal.Evaluate(cfg, check, in, "Function Apps", func(a App) *internal.Verdict {
		if a.HTTPSOnly {
			return internal.Yes(a.ID, "Function App "+a.Name+" is HTTPS only")
		}
		return internal.No(a.ID, "Function App "+a.Name+" accepts plain HTTP")
	})
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetApps(s)
	apps := internal.Fetch("Function Apps", list, err)
	internal.RunCategory("FUNC", c, queue,
		internal.Bind(VNetID, apps, checkIfPrivate),
		internal.Bind(HTTPSID, apps, checkIfHTTPSOnly),
	)
}
