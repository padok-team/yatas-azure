package internal

import "github.com/Azure/azure-sdk-for-go/sdk/azcore"

// Target is one Azure subscription to audit (the equivalent of yatas-aws's
// AWS_Account). Targets are read from `.yatas.yml` by UnmarshalConfig.
type Target struct {
	Name           string `yaml:"name"`                     // Name of the target, shown in the reports
	SubscriptionID string `yaml:"subscription_id"`          // Subscription to audit
	TenantID       string `yaml:"tenant_id,omitempty"`      // Optional: DefaultAzureCredential covers most cases
	ResourceGroup  string `yaml:"resource_group,omitempty"` // Optional: scope the audit to one resource group
}

// Session holds the credential shared by every getter of a target. It is built
// once by initSession in main.go; each category's getter builds its own typed
// SDK client from it.
type Session struct {
	Target     Target
	Credential azcore.TokenCredential
	// CredentialErr is set when the credential could not be built. Getters report
	// it as an error instead of silently returning empty (compliant) data.
	CredentialErr error
}

// InScope reports whether an ARM resource ID is inside the audited scope: always
// true for the whole subscription, or only the configured resource group.
func (t Target) InScope(resourceID string) bool {
	return t.ResourceGroup == "" || ResourceGroupOf(resourceID) == lower(t.ResourceGroup)
}
