package entra

import (
	"context"
	"strconv"
	"time"

	"github.com/padok-team/yatas-azure/internal"
)

// Entra ID lives in Microsoft Graph, not ARM. Every getter below needs a Graph
// application permission granted with tenant-admin consent (see README):
//   - service principals: Application.Read.All
//   - users + MFA registration: User.Read.All + AuditLog.Read.All (Entra ID P1+)
//   - password policy: Domain.Read.All + Directory.Read.All
//   - application credentials: Application.Read.All

// ServicePrincipal is an enterprise application / managed identity.
type ServicePrincipal struct {
	ID          string
	DisplayName string
	Type        string // Application, ManagedIdentity, Legacy, SocialIdp
	SSOMode     string // preferredSingleSignOnMode: password, saml, oidc, notSupported, ...
}

// User is an enabled member user and whether it registered MFA.
type User struct {
	ID            string
	UPN           string
	MFARegistered bool
}

// Domain is a verified tenant domain and its password expiration policy.
type Domain struct {
	Name         string
	Federated    bool
	ValidityDays int64 // passwordValidityPeriodInDays; NeverExpires when disabled
}

// NeverExpires is the Graph value meaning "passwords never expire".
const NeverExpires int64 = 2147483647

// PasswordPolicy is the tenant-level password configuration.
type PasswordPolicy struct {
	Domains []Domain
	// LockoutThreshold is the custom smart-lockout threshold; 0 when no custom
	// "Password Rule Settings" exist (the Microsoft default of 10 applies).
	LockoutThreshold int64
}

// Credential is a client secret or certificate of an app registration.
type Credential struct {
	Name  string
	Kind  string // secret or certificate
	Start *time.Time
	End   *time.Time
}

// Application is an app registration with its credentials.
type Application struct {
	ID          string
	DisplayName string
	Credentials []Credential
}

func graphClient(s internal.Session) (*internal.Graph, error) { return internal.NewGraph(s) }

type spJSON struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Type        string `json:"servicePrincipalType"`
	SSOMode     string `json:"preferredSingleSignOnMode"`
}

// GetServicePrincipals lists the service principals of the tenant.
func GetServicePrincipals(s internal.Session) ([]ServicePrincipal, error) {
	g, err := graphClient(s)
	if err != nil {
		return nil, err
	}
	raw, err := internal.GraphList[spJSON](context.TODO(), g, "/servicePrincipals?$select=id,displayName,servicePrincipalType,preferredSingleSignOnMode&$top=999")
	if err != nil {
		return nil, err
	}
	sps := make([]ServicePrincipal, 0, len(raw))
	for _, r := range raw {
		sps = append(sps, ServicePrincipal{ID: r.ID, DisplayName: r.DisplayName, Type: r.Type, SSOMode: r.SSOMode})
	}
	return sps, nil
}

type userJSON struct {
	ID             string `json:"id"`
	UPN            string `json:"userPrincipalName"`
	AccountEnabled bool   `json:"accountEnabled"`
	UserType       string `json:"userType"`
}

type registrationJSON struct {
	ID              string `json:"id"`
	IsMfaRegistered bool   `json:"isMfaRegistered"`
}

// GetUsers lists the enabled member users with their MFA registration status.
func GetUsers(s internal.Session) ([]User, error) {
	g, err := graphClient(s)
	if err != nil {
		return nil, err
	}
	ctx := context.TODO()
	users, err := internal.GraphList[userJSON](ctx, g, "/users?$select=id,userPrincipalName,accountEnabled,userType&$top=999")
	if err != nil {
		return nil, err
	}
	regs, err := internal.GraphList[registrationJSON](ctx, g, "/reports/authenticationMethods/userRegistrationDetails?$top=999")
	if err != nil {
		return nil, err
	}
	mfa := make(map[string]bool, len(regs))
	for _, r := range regs {
		mfa[r.ID] = r.IsMfaRegistered
	}
	var result []User
	for _, u := range users {
		if !u.AccountEnabled || u.UserType == "Guest" {
			continue
		}
		result = append(result, User{ID: u.ID, UPN: u.UPN, MFARegistered: mfa[u.ID]})
	}
	return result, nil
}

type domainJSON struct {
	ID                         string `json:"id"`
	IsVerified                 bool   `json:"isVerified"`
	AuthenticationType         string `json:"authenticationType"`
	PasswordValidityPeriodDays *int64 `json:"passwordValidityPeriodInDays"`
}

type settingJSON struct {
	TemplateID string `json:"templateId"`
	Values     []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"values"`
}

// passwordRuleSettingsTemplate is the directory settings template of the
// "Password Rule Settings" (smart lockout, banned passwords).
const passwordRuleSettingsTemplate = "5cf42378-d67d-4f36-ba46-e8b86229381d"

// GetPasswordPolicy reads the verified domains and the custom lockout settings.
func GetPasswordPolicy(s internal.Session) ([]PasswordPolicy, error) {
	g, err := graphClient(s)
	if err != nil {
		return nil, err
	}
	ctx := context.TODO()
	domains, err := internal.GraphList[domainJSON](ctx, g, "/domains")
	if err != nil {
		return nil, err
	}
	settings, err := internal.GraphList[settingJSON](ctx, g, "/groupSettings")
	if err != nil {
		return nil, err
	}
	policy := PasswordPolicy{}
	for _, d := range domains {
		if !d.IsVerified {
			continue
		}
		dom := Domain{Name: d.ID, Federated: d.AuthenticationType == "Federated", ValidityDays: NeverExpires}
		if d.PasswordValidityPeriodDays != nil {
			dom.ValidityDays = *d.PasswordValidityPeriodDays
		}
		policy.Domains = append(policy.Domains, dom)
	}
	for _, st := range settings {
		if st.TemplateID != passwordRuleSettingsTemplate {
			continue
		}
		for _, v := range st.Values {
			if v.Name == "LockoutThreshold" {
				policy.LockoutThreshold, _ = strconv.ParseInt(v.Value, 10, 64)
			}
		}
	}
	return []PasswordPolicy{policy}, nil
}

type credentialJSON struct {
	DisplayName string     `json:"displayName"`
	Start       *time.Time `json:"startDateTime"`
	End         *time.Time `json:"endDateTime"`
}

type appJSON struct {
	ID                  string           `json:"id"`
	DisplayName         string           `json:"displayName"`
	PasswordCredentials []credentialJSON `json:"passwordCredentials"`
	KeyCredentials      []credentialJSON `json:"keyCredentials"`
}

// GetApplications lists the app registrations with their secrets and certificates.
func GetApplications(s internal.Session) ([]Application, error) {
	g, err := graphClient(s)
	if err != nil {
		return nil, err
	}
	raw, err := internal.GraphList[appJSON](context.TODO(), g, "/applications?$select=id,displayName,passwordCredentials,keyCredentials&$top=999")
	if err != nil {
		return nil, err
	}
	apps := make([]Application, 0, len(raw))
	for _, r := range raw {
		app := Application{ID: r.ID, DisplayName: r.DisplayName}
		for _, c := range r.PasswordCredentials {
			app.Credentials = append(app.Credentials, Credential{Name: c.DisplayName, Kind: "secret", Start: c.Start, End: c.End})
		}
		for _, c := range r.KeyCredentials {
			app.Credentials = append(app.Credentials, Credential{Name: c.DisplayName, Kind: "certificate", Start: c.Start, End: c.End})
		}
		apps = append(apps, app)
	}
	return apps, nil
}
