package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
)

// AZURE_ENT_002 decides whether a user has MFA from several sources, strongest
// first. A user passes as soon as one source covers them:
//
//  1. Azure Policy: both built-in "Users must authenticate with MFA" definitions
//     (create/update and delete) assigned in Deny mode, everywhere (ARM only).
//  2. Security Defaults enabled on the tenant.
//  3. An enabled Conditional Access policy requiring MFA for all users on Azure
//     management, not excluding the user.
//  4. The user registered an MFA method (registration report, or authentication
//     methods on tenants without Entra ID P1). Only read for users the first
//     three sources don't already cover.
//
// Each source may be unreadable (permissions, licence). That is remembered and
// reported when a user can't be confirmed; it never turns into a pass.

// Built-in Azure Policy definitions for self-enforced MFA.
const (
	mfaPolicyDeleteID = "db4a9d17-db75-4f46-9fcb-9f9526604417" // ...to delete resources
	mfaPolicyWriteID  = "4e6c27d5-a6ee-49cf-b2b4-d8fe90fa2b8b" // ...to create or update resources
)

// azureManagementAppID is the "Windows Azure Service Management API" app that
// Conditional Access targets for Azure Resource Manager.
const azureManagementAppID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"

// UserMFA is the MFA verdict for one user.
type UserMFA struct {
	// Source names what enforces MFA for the user ("" when nothing does).
	Source string
	// Registered is true when the user registered an MFA method.
	Registered bool
}

// MFAEvidence is everything the ENT_002 check needs.
type MFAEvidence struct {
	ByUser map[string]UserMFA
	// Notes explain what couldn't be read or was only partially in place; they
	// are added to the failure of a user that couldn't be confirmed.
	Notes []string
	// Unconfirmed is true when a source was unreadable, so a missing MFA could
	// be a visibility gap rather than a real gap.
	Unconfirmed bool
}

// MFAInput bundles the users and their MFA evidence for the check.
type MFAInput struct {
	Users    internal.Fetched[User]
	Evidence MFAEvidence
}

// ---------------------------------------------------------------- Azure Policy

// policyAssignment is the part of an Azure Policy assignment that matters here.
type policyAssignment struct {
	DefinitionID string
	Enforced     bool   // enforcementMode == Default
	Effect       string // resolved effect (override, parameter, or default audit)
	Partial      bool   // limited by resource selectors, effect-override selectors or notScopes
}

func isDeny(effect string) bool {
	return strings.EqualFold(effect, "deny") || strings.EqualFold(effect, "denyaction")
}

// policyEnforcement reports whether the delete and the create/update MFA
// policies are both assigned in Deny mode with no regional/scope limitation, plus
// notes for what is only partially in place.
func policyEnforcement(assignments []policyAssignment) (enforced bool, notes []string) {
	state := map[string]string{} // definition suffix -> "full" | "partial: ..."
	for _, a := range assignments {
		id := ""
		switch {
		case strings.HasSuffix(strings.ToLower(a.DefinitionID), mfaPolicyDeleteID):
			id = mfaPolicyDeleteID
		case strings.HasSuffix(strings.ToLower(a.DefinitionID), mfaPolicyWriteID):
			id = mfaPolicyWriteID
		default:
			continue
		}
		switch {
		case !a.Enforced:
			state[id] = "assigned but enforcement mode is DoNotEnforce"
		case !isDeny(a.Effect):
			if state[id] != "full" {
				state[id] = "assigned in " + a.Effect + " mode only (audit does not enforce)"
			}
		case a.Partial:
			if state[id] != "full" {
				state[id] = "denies only on part of the resources (resource selectors, overrides or notScopes)"
			}
		default:
			state[id] = "full"
		}
	}
	names := map[string]string{mfaPolicyDeleteID: "delete", mfaPolicyWriteID: "create/update"}
	enforced = true
	for _, id := range []string{mfaPolicyDeleteID, mfaPolicyWriteID} {
		switch s := state[id]; s {
		case "full":
		case "":
			enforced = false
		default:
			enforced = false
			notes = append(notes, fmt.Sprintf("Azure Policy MFA (%s): %s", names[id], s))
		}
	}
	if !enforced && len(notes) == 0 {
		notes = append(notes, "no Azure Policy MFA enforcement assigned")
	}
	return enforced, notes
}

func getMFAPolicyAssignments(s internal.Session) ([]policyAssignment, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armpolicy.NewAssignmentsClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var out []policyAssignment
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			p := raw.Properties
			if p == nil || p.PolicyDefinitionID == nil {
				continue
			}
			def := strings.ToLower(*p.PolicyDefinitionID)
			if !strings.HasSuffix(def, mfaPolicyDeleteID) && !strings.HasSuffix(def, mfaPolicyWriteID) {
				continue
			}
			a := policyAssignment{
				DefinitionID: *p.PolicyDefinitionID,
				Enforced:     p.EnforcementMode == nil || *p.EnforcementMode == armpolicy.EnforcementModeDefault,
				Effect:       "Audit",
				Partial:      len(p.ResourceSelectors) > 0 || len(p.NotScopes) > 0,
			}
			if v, ok := p.Parameters["effect"]; ok && v != nil {
				if str, ok := v.Value.(string); ok && str != "" {
					a.Effect = str
				}
			}
			for _, o := range p.Overrides {
				if o != nil && o.Kind != nil && *o.Kind == armpolicy.OverrideKindPolicyEffect && o.Value != nil {
					a.Effect = *o.Value
					if len(o.Selectors) > 0 {
						a.Partial = true
					}
				}
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- Conditional Access

// CAPolicy is a Conditional Access policy reduced to what decides "MFA for all
// users on Azure management".
type CAPolicy struct {
	Name             string
	Enabled          bool
	AllUsers         bool
	ExcludeUsers     map[string]bool
	ExcludeGroups    map[string]bool
	ExcludesRoles    bool
	CoversAzureMgmt  bool
	RequiresMFA      bool
	NarrowConditions bool // locations, risk levels, platforms or device filters limit it
}

type caJSON struct {
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	Conditions  struct {
		Users struct {
			IncludeUsers  []string `json:"includeUsers"`
			ExcludeUsers  []string `json:"excludeUsers"`
			ExcludeGroups []string `json:"excludeGroups"`
			ExcludeRoles  []string `json:"excludeRoles"`
		} `json:"users"`
		Applications struct {
			IncludeApplications []string `json:"includeApplications"`
			ExcludeApplications []string `json:"excludeApplications"`
		} `json:"applications"`
		Locations *struct {
			IncludeLocations []string `json:"includeLocations"`
			ExcludeLocations []string `json:"excludeLocations"`
		} `json:"locations"`
		SignInRiskLevels []string        `json:"signInRiskLevels"`
		UserRiskLevels   []string        `json:"userRiskLevels"`
		Platforms        json.RawMessage `json:"platforms"`
		Devices          json.RawMessage `json:"devices"`
	} `json:"conditions"`
	GrantControls *struct {
		Operator               string           `json:"operator"`
		BuiltInControls        []string         `json:"builtInControls"`
		AuthenticationStrength *json.RawMessage `json:"authenticationStrength"`
	} `json:"grantControls"`
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func set(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, x := range list {
		m[strings.ToLower(x)] = true
	}
	return m
}

func present(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null"
}

func toCAPolicy(j caJSON) CAPolicy {
	c := j.Conditions
	p := CAPolicy{
		Name:          j.DisplayName,
		Enabled:       j.State == "enabled",
		AllUsers:      contains(c.Users.IncludeUsers, "All"),
		ExcludeUsers:  set(c.Users.ExcludeUsers),
		ExcludeGroups: set(c.Users.ExcludeGroups),
		ExcludesRoles: len(c.Users.ExcludeRoles) > 0,
	}
	p.CoversAzureMgmt = (contains(c.Applications.IncludeApplications, "All") || contains(c.Applications.IncludeApplications, azureManagementAppID)) &&
		!contains(c.Applications.ExcludeApplications, azureManagementAppID)
	if g := j.GrantControls; g != nil {
		hasStrength := g.AuthenticationStrength != nil && present(*g.AuthenticationStrength)
		if (contains(g.BuiltInControls, "mfa") || hasStrength) && (strings.EqualFold(g.Operator, "AND") || len(g.BuiltInControls) <= 1) {
			p.RequiresMFA = true
		}
	}
	if l := c.Locations; l != nil && (len(l.ExcludeLocations) > 0 || (len(l.IncludeLocations) > 0 && !contains(l.IncludeLocations, "All"))) {
		p.NarrowConditions = true
	}
	if len(c.SignInRiskLevels) > 0 || len(c.UserRiskLevels) > 0 || present(c.Platforms) || present(c.Devices) {
		p.NarrowConditions = true
	}
	return p
}

// covers reports whether the policy requires MFA of the user on Azure
// management. groups are the user's group IDs (lower-cased), only needed when
// the policy excludes groups.
func (p CAPolicy) covers(userID string, groups map[string]bool) bool {
	if !p.Enabled || !p.AllUsers || !p.CoversAzureMgmt || !p.RequiresMFA || p.NarrowConditions || p.ExcludesRoles {
		return false
	}
	if p.ExcludeUsers[strings.ToLower(userID)] {
		return false
	}
	for g := range p.ExcludeGroups {
		if groups[g] {
			return false
		}
	}
	return true
}

func (p CAPolicy) needsGroups() bool { return len(p.ExcludeGroups) > 0 }

func getConditionalAccess(ctx context.Context, g *internal.Graph) ([]CAPolicy, error) {
	raw, err := internal.GraphList[caJSON](ctx, g, "/identity/conditionalAccess/policies")
	if err != nil {
		return nil, err
	}
	out := make([]CAPolicy, 0, len(raw))
	for _, r := range raw {
		out = append(out, toCAPolicy(r))
	}
	return out, nil
}

type securityDefaultsJSON struct {
	IsEnabled bool `json:"isEnabled"`
}

// ---------------------------------------------------------------- evidence

var guidRe = regexp.MustCompile(`[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}`)

// briefErr shortens an error for per-user messages: Graph answers become
// "<path> returned <status>" (IDs and query stripped), anything else its first
// line. The full error is logged where it happens.
func briefErr(err error) string {
	var ge *internal.GraphError
	if errors.As(err, &ge) {
		path := ge.Path
		if i := strings.Index(path, "?"); i >= 0 {
			path = path[:i]
		}
		return fmt.Sprintf("%s returned %d", guidRe.ReplaceAllString(path, "{id}"), ge.Status)
	}
	msg := strings.SplitN(err.Error(), "\n", 2)[0]
	if len(msg) > 140 {
		msg = msg[:140] + "..."
	}
	return msg
}

// GetMFAEvidence gathers the MFA evidence for the given users, strongest source
// first, and only reads per-user registrations for users still uncovered.
func GetMFAEvidence(s internal.Session, users []User) MFAEvidence {
	ev := MFAEvidence{ByUser: map[string]UserMFA{}}
	if len(users) == 0 {
		return ev
	}
	ctx := context.TODO()
	note := func(unconfirmed bool, format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if !contains(ev.Notes, msg) {
			ev.Notes = append(ev.Notes, msg)
		}
		if unconfirmed {
			ev.Unconfirmed = true
		}
	}

	// 1. Azure Policy (ARM).
	policyEnforced := false
	if assignments, err := getMFAPolicyAssignments(s); err != nil {
		logger.Logger.Error("Unable to read Azure Policy assignments for the MFA check", "error", err.Error())
		note(true, "Azure Policy unreadable (%s)", briefErr(err))
	} else {
		var notes []string
		policyEnforced, notes = policyEnforcement(assignments)
		for _, n := range notes {
			note(false, "%s", n)
		}
	}

	// 2 and 3. Security Defaults, Conditional Access (Graph).
	g, gerr := internal.NewGraph(s)
	securityDefaults := false
	var ca []CAPolicy
	if gerr != nil {
		logger.Logger.Error("Microsoft Graph unavailable for the MFA check", "error", gerr.Error())
		note(true, "Microsoft Graph unavailable (%s)", briefErr(gerr))
	} else {
		if sd, err := internal.GraphGet[securityDefaultsJSON](ctx, g, "/policies/identitySecurityDefaultsEnforcementPolicy"); err != nil {
			logger.Logger.Error("Unable to read Security Defaults", "error", err.Error())
			note(true, "Security Defaults unreadable (%s)", briefErr(err))
		} else {
			securityDefaults = sd.IsEnabled
			if !sd.IsEnabled {
				note(false, "Security Defaults are disabled")
			}
		}
		var err error
		if ca, err = getConditionalAccess(ctx, g); err != nil {
			logger.Logger.Error("Unable to read Conditional Access policies", "error", err.Error())
			note(true, "Conditional Access unreadable (%s)", briefErr(err))
		} else if len(ca) == 0 {
			note(false, "no Conditional Access policy")
		}
	}

	groupsOf := func(userID string) map[string]bool {
		groups := map[string]bool{}
		if g == nil {
			return groups
		}
		list, err := internal.GraphList[struct {
			ID string `json:"id"`
		}](ctx, g, "/users/"+userID+"/transitiveMemberOf?$select=id&$top=999")
		if err != nil {
			logger.Logger.Error("Unable to read group membership", "user", userID, "error", err.Error())
			note(true, "group membership unreadable (%s)", briefErr(err))
			return groups
		}
		for _, x := range list {
			groups[strings.ToLower(x.ID)] = true
		}
		return groups
	}

	var uncovered []string
	for _, u := range users {
		source := ""
		switch {
		case policyEnforced:
			source = "Azure Policy (MFA required, Deny)"
		case securityDefaults:
			source = "Security Defaults"
		default:
			var groups map[string]bool
			for _, p := range ca {
				if p.needsGroups() && groups == nil && p.Enabled {
					groups = groupsOf(u.ID)
				}
				if p.covers(u.ID, groups) {
					source = "Conditional Access policy " + p.Name
					break
				}
			}
		}
		ev.ByUser[u.ID] = UserMFA{Source: source}
		if source == "" {
			uncovered = append(uncovered, u.ID)
		}
	}

	// 4. Per-user registration, only for the users nothing else covers.
	if len(uncovered) > 0 && g != nil {
		registered, err := mfaStatuses(ctx, g, uncovered)
		if err != nil {
			logger.Logger.Error("Unable to read per-user MFA registration", "error", err.Error())
			note(true, "per-user MFA registration unreadable (%s)", briefErr(err))
		} else {
			for _, id := range uncovered {
				u := ev.ByUser[id]
				u.Registered = registered[id]
				ev.ByUser[id] = u
			}
		}
	}
	return ev
}
