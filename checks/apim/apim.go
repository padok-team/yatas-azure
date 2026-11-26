package apim

import (
	"context"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement/v3"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	LogsID    = "AZURE_APIM_001"
	NetworkID = "AZURE_APIM_002"
)

// Service is an API Management instance.
type Service struct {
	ID          string
	Name        string
	GatewayLogs bool
	InVNet      bool
	PublicOff   bool
}

// GetServices lists the API Management services of the target.
func GetServices(s internal.Session) ([]Service, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armapimanagement.NewServiceClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var services []Service
	pager := client.NewListPager(nil)
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
			svc := Service{ID: id, Name: internal.Deref(raw.Name)}
			if p := raw.Properties; p != nil {
				svc.InVNet = p.VirtualNetworkType != nil && *p.VirtualNetworkType != armapimanagement.VirtualNetworkTypeNone
				svc.PublicOff = p.PublicNetworkAccess != nil && *p.PublicNetworkAccess == armapimanagement.PublicNetworkAccessDisabled
			}
			diag, err := internal.GetDiagnosticSettings(s, id)
			if err != nil {
				return nil, err
			}
			svc.GatewayLogs = internal.LogsShipped(diag, "GatewayLogs")
			services = append(services, svc)
		}
	}
	return services, nil
}

// checkIfLogs (≈ AWS "API Gateways have logging enabled").
func checkIfLogs(cfg commons.CheckConfig, in internal.Fetched[Service], id string) {
	check := internal.NewCheck("API Management gateway logs are exported", "Check that API Management gateway logs are sent to a log destination", id)
	internal.Evaluate(cfg, check, in, "API Management services", func(s Service) *internal.Verdict {
		if s.GatewayLogs {
			return internal.Yes(s.ID, "Gateway logs of "+s.Name+" are exported")
		}
		return internal.No(s.ID, "Gateway logs of "+s.Name+" are not exported")
	})
}

// checkIfNetworkRestricted (≈ AWS "API Gateways are protected by an ACL / WAF").
func checkIfNetworkRestricted(cfg commons.CheckConfig, in internal.Fetched[Service], id string) {
	check := internal.NewCheck("API Management services are network restricted", "Check that API Management is injected in a VNet or has public network access disabled", id)
	internal.Evaluate(cfg, check, in, "API Management services", func(s Service) *internal.Verdict {
		if s.InVNet || s.PublicOff {
			return internal.Yes(s.ID, s.Name+" is network restricted")
		}
		return internal.No(s.ID, s.Name+" is publicly reachable (no VNet integration, public access enabled)")
	})
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetServices(s)
	services := internal.Fetch("API Management services", list, err)
	internal.RunCategory("APIM", c, queue,
		internal.Bind(LogsID, services, checkIfLogs),
		internal.Bind(NetworkID, services, checkIfNetworkRestricted),
	)
}
