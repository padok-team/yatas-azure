package cdn

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v4"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	WAFID  = "AZURE_CDN_002"
	LogsID = "AZURE_CDN_003"
	TLSID  = "AZURE_CDN_004"
)

// Profile is a CDN or Front Door profile.
type Profile struct {
	ID         string
	Name       string
	FrontDoor  bool // Front Door Standard/Premium (WAF and custom domains exist only there)
	WAF        bool // a security policy attaches a WAF policy
	AccessLogs bool
	// WeakTLSDomains lists the custom domains whose minimum TLS version is below 1.2.
	WeakTLSDomains []string
}

// GetProfiles lists the CDN and Front Door profiles of the target.
func GetProfiles(s internal.Session) ([]Profile, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	ctx := context.TODO()
	sub := s.Target.SubscriptionID
	profiles, err := armcdn.NewProfilesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	policies, err := armcdn.NewSecurityPoliciesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	domains, err := armcdn.NewAFDCustomDomainsClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var result []Profile
	pager := profiles.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			id := internal.Deref(raw.ID)
			if !s.Target.InScope(id) {
				continue
			}
			p := Profile{ID: id, Name: internal.Deref(raw.Name)}
			if raw.SKU != nil && raw.SKU.Name != nil {
				p.FrontDoor = *raw.SKU.Name == armcdn.SKUNameStandardAzureFrontDoor || *raw.SKU.Name == armcdn.SKUNamePremiumAzureFrontDoor
			}
			diag, err := internal.GetDiagnosticSettings(s, id)
			if err != nil {
				return nil, err
			}
			p.AccessLogs = internal.LogsShipped(diag, "FrontDoorAccessLog", "AzureCdnAccessLog")
			if p.FrontDoor {
				rg := internal.ResourceGroupOf(id)
				sp := policies.NewListByProfilePager(rg, p.Name, nil)
				for sp.More() {
					spPage, err := sp.NextPage(ctx)
					if err != nil {
						return nil, err
					}
					if len(spPage.Value) > 0 {
						p.WAF = true
					}
				}
				dp := domains.NewListByProfilePager(rg, p.Name, nil)
				for dp.More() {
					dPage, err := dp.NextPage(ctx)
					if err != nil {
						return nil, err
					}
					for _, d := range dPage.Value {
						if d.Properties == nil || d.Properties.TLSSettings == nil || d.Properties.TLSSettings.MinimumTLSVersion == nil {
							continue
						}
						if *d.Properties.TLSSettings.MinimumTLSVersion != armcdn.AfdMinimumTLSVersionTLS12 {
							p.WeakTLSDomains = append(p.WeakTLSDomains, internal.Deref(d.Name))
						}
					}
				}
			}
			result = append(result, p)
		}
	}
	return result, nil
}

// checkIfWAF (≈ AWS "Cloudfronts have a WAF").
func checkIfWAF(cfg commons.CheckConfig, in internal.Fetched[Profile], id string) {
	check := internal.NewCheck("Front Door profiles are protected by a WAF", "Check that Front Door profiles attach a WAF policy through a security policy", id)
	internal.Evaluate(cfg, check, in, "CDN profiles", func(p Profile) *internal.Verdict {
		switch {
		case !p.FrontDoor:
			return nil
		case p.WAF:
			return internal.Yes(p.ID, "Profile "+p.Name+" has a WAF policy")
		}
		return internal.No(p.ID, "Profile "+p.Name+" has no WAF policy")
	})
}

// checkIfLogs (≈ AWS "Cloudfronts have access logs").
func checkIfLogs(cfg commons.CheckConfig, in internal.Fetched[Profile], id string) {
	check := internal.NewCheck("CDN and Front Door access logs are exported", "Check that CDN and Front Door access logs are sent to a log destination", id)
	internal.Evaluate(cfg, check, in, "CDN profiles", func(p Profile) *internal.Verdict {
		if p.AccessLogs {
			return internal.Yes(p.ID, "Access logs of "+p.Name+" are exported")
		}
		return internal.No(p.ID, "Access logs of "+p.Name+" are not exported")
	})
}

// checkIfTLS12 (≈ AWS "Cloudfronts use TLS 1.2 minimum").
func checkIfTLS12(cfg commons.CheckConfig, in internal.Fetched[Profile], id string) {
	check := internal.NewCheck("Front Door custom domains require TLS 1.2", "Check that the custom domains of Front Door profiles have a minimum TLS version of 1.2", id)
	internal.Evaluate(cfg, check, in, "CDN profiles", func(p Profile) *internal.Verdict {
		switch {
		case !p.FrontDoor:
			return nil
		case len(p.WeakTLSDomains) > 0:
			return internal.No(p.ID, "Profile "+p.Name+" has custom domains below TLS 1.2: "+join(p.WeakTLSDomains))
		}
		return internal.Yes(p.ID, "Custom domains of "+p.Name+" require TLS 1.2")
	})
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
