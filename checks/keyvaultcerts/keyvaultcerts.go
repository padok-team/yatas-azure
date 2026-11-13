package keyvaultcerts

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	ExpiryID  = "AZURE_KVC_001"
	ValidID   = "AZURE_KVC_002"
	expiresIn = 30 * 24 * time.Hour
)

// Certificate is a certificate stored in a Key Vault. When the vault itself
// could not be read (the identity lacks the data-plane "Key Vault Certificates
// Officer/User" or "Reader" role), Err carries the reason instead.
type Certificate struct {
	ID        string
	Name      string // <vault>/<certificate>
	Enabled   bool
	NotBefore time.Time
	Expires   time.Time
	Err       string
}

// GetCertificates lists the certificates of every Key Vault of the target. The
// certificates are data-plane objects: reading them needs a data-plane role on
// each vault in addition to the ARM Reader role.
func GetCertificates(s internal.Session) ([]Certificate, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	vaults, err := armkeyvault.NewVaultsClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var certs []Certificate
	pager := vaults.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			vaultID := internal.Deref(v.ID)
			if !s.Target.InScope(vaultID) || v.Properties == nil || internal.Deref(v.Properties.VaultURI) == "" {
				continue
			}
			list, err := listVault(s, internal.Deref(v.Name), *v.Properties.VaultURI)
			if err != nil {
				certs = append(certs, Certificate{ID: vaultID, Name: internal.Deref(v.Name), Err: err.Error()})
				continue
			}
			certs = append(certs, list...)
		}
	}
	return certs, nil
}

func listVault(s internal.Session, vault, uri string) ([]Certificate, error) {
	client, err := azcertificates.NewClient(uri, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var certs []Certificate
	pager := client.NewListCertificatePropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			c := Certificate{Name: vault}
			if raw.ID != nil {
				c.ID = string(*raw.ID)
				c.Name = vault + "/" + raw.ID.Name()
			}
			if a := raw.Attributes; a != nil {
				c.Enabled = internal.Deref(a.Enabled)
				if a.Expires != nil {
					c.Expires = *a.Expires
				}
				if a.NotBefore != nil {
					c.NotBefore = *a.NotBefore
				}
			}
			certs = append(certs, c)
		}
	}
	return certs, nil
}

// checkIfNotExpiring (≈ AWS "ACM certificates are not expiring soon").
func checkIfNotExpiring(cfg commons.CheckConfig, in internal.Fetched[Certificate], id string) {
	check := internal.NewCheck("Key Vault certificates are not expiring soon", "Check that no Key Vault certificate is expired or expires within 30 days", id)
	internal.Evaluate(cfg, check, in, "Key Vault certificates", func(c Certificate) *internal.Verdict {
		switch {
		case c.Err != "":
			return internal.No(c.ID, "Unable to evaluate: could not list certificates of vault "+c.Name+": "+c.Err)
		case c.Expires.IsZero():
			return internal.Yes(c.ID, c.Name+" has no expiry date")
		case time.Until(c.Expires) < 0:
			return internal.No(c.ID, c.Name+" expired on "+c.Expires.Format("2006-01-02"))
		case time.Until(c.Expires) < expiresIn:
			return internal.No(c.ID, fmt.Sprintf("%s expires in %d days", c.Name, int(time.Until(c.Expires).Hours()/24)))
		}
		return internal.Yes(c.ID, c.Name+" is valid until "+c.Expires.Format("2006-01-02"))
	})
}

// checkIfValid (≈ AWS "ACM certificates are valid / in use"): enabled and already active.
func checkIfValid(cfg commons.CheckConfig, in internal.Fetched[Certificate], id string) {
	check := internal.NewCheck("Key Vault certificates are enabled", "Check that Key Vault certificates are enabled and already valid", id, "Reliability", "Good Practice")
	internal.Evaluate(cfg, check, in, "Key Vault certificates", func(c Certificate) *internal.Verdict {
		switch {
		case c.Err != "":
			return nil // already reported by the expiry check
		case !c.Enabled:
			return internal.No(c.ID, c.Name+" is disabled")
		case time.Until(c.NotBefore) > 0:
			return internal.No(c.ID, c.Name+" is not valid yet")
		}
		return internal.Yes(c.ID, c.Name+" is enabled")
	})
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetCertificates(s)
	certs := internal.Fetch("Key Vault certificates", list, err)
	internal.RunCategory("KVC", c, queue,
		internal.Bind(ExpiryID, certs, checkIfNotExpiring),
		internal.Bind(ValidID, certs, checkIfValid),
	)
}
