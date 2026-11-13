package acr

import (
	"context"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/padok-team/yatas-azure/checks/defender"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	EncryptedID = "AZURE_ACR_001"
	RetentionID = "AZURE_ACR_002"
	AdminID     = "AZURE_ACR_003"
	ScanningID  = "AZURE_ACR_004"
)

// Registry is an Azure Container Registry.
type Registry struct {
	ID               string
	Name             string
	CustomerKey      bool
	RetentionPolicy  bool // untagged manifests retention (Premium)
	AdminUserEnabled bool
}

// GetRegistries lists the container registries of the target.
func GetRegistries(s internal.Session) ([]Registry, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armcontainerregistry.NewRegistriesClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var registries []Registry
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
			r := Registry{ID: id, Name: internal.Deref(raw.Name)}
			if p := raw.Properties; p != nil {
				r.AdminUserEnabled = internal.Deref(p.AdminUserEnabled)
				r.CustomerKey = p.Encryption != nil && p.Encryption.Status != nil && *p.Encryption.Status == armcontainerregistry.EncryptionStatusEnabled
				r.RetentionPolicy = p.Policies != nil && p.Policies.RetentionPolicy != nil && p.Policies.RetentionPolicy.Status != nil &&
					*p.Policies.RetentionPolicy.Status == armcontainerregistry.PolicyStatusEnabled
			}
			registries = append(registries, r)
		}
	}
	return registries, nil
}

// checkIfEncrypted (≈ AWS "ECR repositories are encrypted").
func checkIfEncrypted(cfg commons.CheckConfig, in internal.Fetched[Registry], id string) {
	check := internal.NewCheck("Container registries are encrypted with a customer-managed key", "Check that ACR registries use a customer-managed key", id)
	internal.Evaluate(cfg, check, in, "container registries", func(r Registry) *internal.Verdict {
		if r.CustomerKey {
			return internal.Yes(r.ID, "Registry "+r.Name+" is encrypted with a customer-managed key")
		}
		return internal.No(r.ID, "Registry "+r.Name+" only uses a Microsoft-managed key")
	})
}

// checkIfRetention (≈ AWS "ECR repositories have immutable images / lifecycle").
func checkIfRetention(cfg commons.CheckConfig, in internal.Fetched[Registry], id string) {
	check := internal.NewCheck("Container registries have a retention policy", "Check that untagged manifests are purged by a retention policy", id, "Cost", "Good Practice")
	internal.Evaluate(cfg, check, in, "container registries", func(r Registry) *internal.Verdict {
		if r.RetentionPolicy {
			return internal.Yes(r.ID, "Registry "+r.Name+" has a retention policy")
		}
		return internal.No(r.ID, "Registry "+r.Name+" has no retention policy")
	})
}

// checkIfAdminDisabled: the shared admin account bypasses Entra authentication.
func checkIfAdminDisabled(cfg commons.CheckConfig, in internal.Fetched[Registry], id string) {
	check := internal.NewCheck("Container registries have the admin user disabled", "Check that the shared admin account of ACR registries is disabled", id)
	internal.Evaluate(cfg, check, in, "container registries", func(r Registry) *internal.Verdict {
		if r.AdminUserEnabled {
			return internal.No(r.ID, "The admin user is enabled on registry "+r.Name)
		}
		return internal.Yes(r.ID, "The admin user is disabled on registry "+r.Name)
	})
}

// checkIfScanning (≈ AWS "ECR repositories have image scanning"): Defender for
// Containers (or the legacy container registries plan) scans pushed images.
func checkIfScanning(registries internal.Fetched[Registry], plans internal.Fetched[defender.Plan]) func(commons.CheckConfig, string) {
	return func(cfg commons.CheckConfig, id string) {
		check := internal.NewCheck("Container registries are scanned for vulnerabilities", "Check that Defender for Containers scans the images of ACR registries", id)
		if plans.Failed(&check, "Defender for Cloud plans") {
			cfg.Queue <- check
			return
		}
		scanning := false
		for _, p := range plans.Items {
			if p.Standard && (strings.EqualFold(p.Name, "Containers") || strings.EqualFold(p.Name, "ContainerRegistry")) {
				scanning = true
			}
		}
		internal.Evaluate(cfg, check, registries, "container registries", func(r Registry) *internal.Verdict {
			if scanning {
				return internal.Yes(r.ID, "Defender for Containers scans registry "+r.Name)
			}
			return internal.No(r.ID, "Defender for Containers is not enabled, registry "+r.Name+" is not scanned")
		})
	}
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetRegistries(s)
	registries := internal.Fetch("container registries", list, err)
	planList, err := defender.GetPlans(s)
	plans := internal.Fetch("Defender for Cloud plans", planList, err)
	internal.RunCategory("ACR", c, queue,
		internal.Bind(EncryptedID, registries, checkIfEncrypted),
		internal.Bind(RetentionID, registries, checkIfRetention),
		internal.Bind(AdminID, registries, checkIfAdminDisabled),
		internal.Entry{ID: ScanningID, Run: checkIfScanning(registries, plans)},
	)
}
