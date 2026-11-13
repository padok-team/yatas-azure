package vm

import (
	"context"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	NoPublicIPID = "AZURE_VM_001"
	BootDiagID   = "AZURE_VM_002"
)

// Machine is a virtual machine with the properties the checks need.
type Machine struct {
	ID       string
	Name     string
	PublicIP bool // one of its NICs has a public IP
	BootDiag bool
}

// GetMachines lists the VMs of the target and resolves their NIC public IPs.
func GetMachines(s internal.Session) ([]Machine, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	nics, err := nicsWithPublicIP(s)
	if err != nil {
		return nil, err
	}
	client, err := armcompute.NewVirtualMachinesClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var machines []Machine
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
			m := Machine{ID: id, Name: internal.Deref(raw.Name)}
			if p := raw.Properties; p != nil {
				if p.NetworkProfile != nil {
					for _, n := range p.NetworkProfile.NetworkInterfaces {
						if n != nil && nics[strings.ToLower(internal.Deref(n.ID))] {
							m.PublicIP = true
						}
					}
				}
				if p.DiagnosticsProfile != nil && p.DiagnosticsProfile.BootDiagnostics != nil {
					m.BootDiag = internal.Deref(p.DiagnosticsProfile.BootDiagnostics.Enabled)
				}
			}
			machines = append(machines, m)
		}
	}
	return machines, nil
}

// nicsWithPublicIP returns the lower-cased IDs of the NICs holding a public IP.
func nicsWithPublicIP(s internal.Session) (map[string]bool, error) {
	client, err := armnetwork.NewInterfacesClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	nics := map[string]bool{}
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			if raw.Properties == nil {
				continue
			}
			for _, ipc := range raw.Properties.IPConfigurations {
				if ipc != nil && ipc.Properties != nil && ipc.Properties.PublicIPAddress != nil {
					nics[strings.ToLower(internal.Deref(raw.ID))] = true
				}
			}
		}
	}
	return nics, nil
}

// checkIfNoPublicIP (≈ AWS "EC2 instances have no public IP").
func checkIfNoPublicIP(cfg commons.CheckConfig, in internal.Fetched[Machine], id string) {
	check := internal.NewCheck("VMs have no public IP", "Check that virtual machines are not directly exposed with a public IP address", id)
	internal.Evaluate(cfg, check, in, "virtual machines", func(m Machine) *internal.Verdict {
		if m.PublicIP {
			return internal.No(m.ID, "VM "+m.Name+" has a public IP address")
		}
		return internal.Yes(m.ID, "VM "+m.Name+" has no public IP address")
	})
}

// checkIfBootDiagnostics (≈ AWS "EC2 instances have detailed monitoring").
func checkIfBootDiagnostics(cfg commons.CheckConfig, in internal.Fetched[Machine], id string) {
	check := internal.NewCheck("VMs have boot diagnostics enabled", "Check that boot diagnostics are enabled on virtual machines", id, "Reliability", "Good Practice")
	internal.Evaluate(cfg, check, in, "virtual machines", func(m Machine) *internal.Verdict {
		if m.BootDiag {
			return internal.Yes(m.ID, "Boot diagnostics are enabled on "+m.Name)
		}
		return internal.No(m.ID, "Boot diagnostics are not enabled on "+m.Name)
	})
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetMachines(s)
	machines := internal.Fetch("virtual machines", list, err)
	internal.RunCategory("VM", c, queue,
		internal.Bind(NoPublicIPID, machines, checkIfNoPublicIP),
		internal.Bind(BootDiagID, machines, checkIfBootDiagnostics),
	)
}
