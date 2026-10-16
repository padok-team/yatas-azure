package entra

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
)

// Entra ID lives in Microsoft Graph, not ARM. Every getter below needs Graph
// access (an Entra directory role for a signed-in user, or application
// permissions with admin consent, see README).
//
// Every IAM check is scoped to the subscription: getters only evaluate the
// identities holding a role assignment that applies to it (see
// internal.GetAssignees), never the whole tenant.

// ServicePrincipal is an enterprise application / managed identity with access
// to the subscription.
type ServicePrincipal struct {
	ID          string
	AppID       string
	DisplayName string
	Type        string // Application, ManagedIdentity, Legacy, SocialIdp
	SSOMode     string // preferredSingleSignOnMode: password, saml, oidc, notSupported, ...
}

// User is an enabled user (member or guest) with access to the subscription
// (directly or through a group).
type User struct {
	ID     string
	UPN    string
	Guest  bool   // B2B guest: its credentials live in its home tenant
	Domain string // domain part of the UPN; empty for guests
}

// Domain is a verified tenant domain and its password expiration policy.
type Domain struct {
	Name         string
	Federated    bool
	ValidityDays int64 // passwordValidityPeriodInDays; NeverExpires when disabled
}

// NeverExpires is the Graph value meaning "passwords never expire".
const NeverExpires int64 = 2147483647

// PasswordPolicy is the password configuration relevant to the subscription's
// users: the domains they sign in with, plus the tenant-wide lockout setting.
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

// ---------------------------------------------------------------- service principals

type spJSON struct {
	ID          string `json:"id"`
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`
	Type        string `json:"servicePrincipalType"`
	SSOMode     string `json:"preferredSingleSignOnMode"`
}

// GetServicePrincipals resolves the service principals among the assignees.
// Deleted principals (orphan assignments) are skipped.
func GetServicePrincipals(s internal.Session, assignees []internal.Assignee) ([]ServicePrincipal, error) {
	var sps []ServicePrincipal
	var g *internal.Graph
	for _, a := range assignees {
		if a.Type != "ServicePrincipal" {
			continue
		}
		if g == nil {
			var err error
			if g, err = internal.NewGraph(s); err != nil {
				return nil, err
			}
		}
		r, err := internal.GraphGet[spJSON](context.TODO(), g, "/servicePrincipals/"+a.ID+"?$select=id,appId,displayName,servicePrincipalType,preferredSingleSignOnMode")
		if internal.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sps = append(sps, ServicePrincipal{ID: r.ID, AppID: r.AppID, DisplayName: r.DisplayName, Type: r.Type, SSOMode: r.SSOMode})
	}
	return sps, nil
}

// ---------------------------------------------------------------- users

type userJSON struct {
	ID             string `json:"id"`
	UPN            string `json:"userPrincipalName"`
	AccountEnabled bool   `json:"accountEnabled"`
	UserType       string `json:"userType"`
}

const userSelect = "?$select=id,userPrincipalName,accountEnabled,userType"

// GetUsers returns the enabled users, members and guests, with access to the
// subscription: users assigned directly plus the (transitive) members of
// assigned groups.
func GetUsers(s internal.Session, assignees []internal.Assignee) ([]User, error) {
	ctx := context.TODO()
	var g *internal.Graph
	graph := func() (*internal.Graph, error) {
		var err error
		if g == nil {
			g, err = internal.NewGraph(s)
		}
		return g, err
	}

	byID := map[string]userJSON{}
	var order []string
	add := func(u userJSON) {
		if _, ok := byID[u.ID]; !ok {
			order = append(order, u.ID)
		}
		byID[u.ID] = u
	}
	for _, a := range assignees {
		switch a.Type {
		case "User":
			gr, err := graph()
			if err != nil {
				return nil, err
			}
			u, err := internal.GraphGet[userJSON](ctx, gr, "/users/"+a.ID+userSelect)
			if internal.IsNotFound(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			add(u)
		case "Group":
			gr, err := graph()
			if err != nil {
				return nil, err
			}
			members, err := internal.GraphList[userJSON](ctx, gr, "/groups/"+a.ID+"/transitiveMembers/microsoft.graph.user"+userSelect+"&$top=999")
			if internal.IsNotFound(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			for _, u := range members {
				add(u)
			}
		}
	}

	var members []userJSON
	for _, id := range order {
		u := byID[id]
		if u.AccountEnabled {
			members = append(members, u)
		}
	}
	users := make([]User, 0, len(members))
	for _, u := range members {
		user := User{ID: u.ID, UPN: u.UPN, Guest: isGuest(u)}
		if !user.Guest {
			// A guest's UPN domain is the resource tenant's, but its password
			// policy is its home tenant's: it says nothing about this tenant.
			user.Domain = domainOf(u.UPN)
		}
		users = append(users, user)
	}
	guests := 0
	for _, u := range users {
		if u.Guest {
			guests++
		}
	}
	logger.Logger.Debug("Entra users with access to the subscription", "subscription", s.Target.SubscriptionID, "members", len(users)-guests, "guests", guests)
	return users, nil
}

// isGuest recognises external (B2B) accounts. Invited users can have
// userType "Member", but their UPN always carries the "#EXT#" marker.
func isGuest(u userJSON) bool {
	return u.UserType == "Guest" || strings.Contains(u.UPN, "#EXT#")
}

func domainOf(upn string) string {
	if i := strings.LastIndex(upn, "@"); i >= 0 {
		return strings.ToLower(upn[i+1:])
	}
	return ""
}

// ---------------------------------------------------------------- password policy

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

// GetPasswordPolicy reads the password policy of the domains the subscription's
// users sign in with, and the tenant's custom lockout settings.
func GetPasswordPolicy(s internal.Session, users []User) ([]PasswordPolicy, error) {
	wanted := map[string]bool{}
	for _, u := range users {
		if u.Domain != "" {
			wanted[u.Domain] = true
		}
	}
	g, err := internal.NewGraph(s)
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
		if !d.IsVerified || !wanted[strings.ToLower(d.ID)] {
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

// ---------------------------------------------------------------- app registrations

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

// GetApplications returns the app registrations behind the service principals
// with access to the subscription. Service principals without an app
// registration in this tenant (managed identities, Microsoft apps) are skipped.
func GetApplications(s internal.Session, sps []ServicePrincipal) ([]Application, error) {
	var apps []Application
	var g *internal.Graph
	for _, sp := range sps {
		if sp.AppID == "" {
			continue
		}
		if g == nil {
			var err error
			if g, err = internal.NewGraph(s); err != nil {
				return nil, err
			}
		}
		r, err := internal.GraphGet[appJSON](context.TODO(), g, "/applications(appId='"+url.PathEscape(sp.AppID)+"')?$select=id,displayName,passwordCredentials,keyCredentials")
		if internal.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
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
