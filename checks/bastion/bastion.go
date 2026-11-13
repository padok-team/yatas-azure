package bastion

import (
	"context"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// LogsID is the check's unique, stable ID.
const LogsID = "AZURE_BAS_001"

// Host is an Azure Bastion host.
type Host struct {
	ID   string
	Name string
	Logs bool // BastionAuditLogs shipped to a destination
}

// GetHosts lists the Bastion hosts of the target.
func GetHosts(s internal.Session) ([]Host, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armnetwork.NewBastionHostsClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var hosts []Host
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
			diag, err := internal.GetDiagnosticSettings(s, id)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, Host{ID: id, Name: internal.Deref(raw.Name), Logs: internal.LogsShipped(diag, "BastionAuditLogs")})
		}
	}
	return hosts, nil
}

// checkIfLogs (≈ AWS "SSM sessions logs are exported").
func checkIfLogs(cfg commons.CheckConfig, in internal.Fetched[Host], id string) {
	check := internal.NewCheck("Bastion audit logs are exported", "Check that Azure Bastion audit logs are sent to a log destination", id)
	internal.Evaluate(cfg, check, in, "Bastion hosts", func(h Host) *internal.Verdict {
		if h.Logs {
			return internal.Yes(h.ID, "Audit logs of Bastion "+h.Name+" are exported")
		}
		return internal.No(h.ID, "Audit logs of Bastion "+h.Name+" are not exported")
	})
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetHosts(s)
	hosts := internal.Fetch("Bastion hosts", list, err)
	internal.RunCategory("BAS", c, queue, internal.Bind(LogsID, hosts, checkIfLogs))
}
