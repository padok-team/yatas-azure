package loadbalancer

import (
	"context"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// LogsID is the check's unique, stable ID.
const LogsID = "AZURE_LB_001"

// Gateway is an Application Gateway, the Azure L7 load balancer that has access logs.
type Gateway struct {
	ID         string
	Name       string
	AccessLogs bool
}

// GetGateways lists the Application Gateways of the target.
func GetGateways(s internal.Session) ([]Gateway, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armnetwork.NewApplicationGatewaysClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var gateways []Gateway
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			id := internal.Deref(raw.ID)
			if !s.Target.InScope(id) {
				continue
			}
			diag, err := internal.GetDiagnosticSettings(s, id)
			if err != nil {
				return nil, err
			}
			gateways = append(gateways, Gateway{ID: id, Name: internal.Deref(raw.Name), AccessLogs: internal.LogsShipped(diag, "ApplicationGatewayAccessLog")})
		}
	}
	return gateways, nil
}

// checkIfAccessLogs (≈ AWS "ELB have access logs enabled").
func checkIfAccessLogs(cfg commons.CheckConfig, in internal.Fetched[Gateway], id string) {
	check := internal.NewCheck("Application Gateways have access logs enabled", "Check that Application Gateway access logs are sent to a log destination", id)
	internal.Evaluate(cfg, check, in, "Application Gateways", func(g Gateway) *internal.Verdict {
		if g.AccessLogs {
			return internal.Yes(g.ID, "Access logs of "+g.Name+" are exported")
		}
		return internal.No(g.ID, "Access logs of "+g.Name+" are not exported")
	})
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetGateways(s)
	gateways := internal.Fetch("Application Gateways", list, err)
	internal.RunCategory("LB", c, queue, internal.Bind(LogsID, gateways, checkIfAccessLogs))
}
