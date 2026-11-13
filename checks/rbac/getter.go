package rbac

import (
	"context"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
)

// ElevationAction is the ARM permission that lets a principal grant itself (or
// anyone) more rights, i.e. elevate.
const ElevationAction = "Microsoft.Authorization/roleAssignments/write"

// Permission is one Actions / NotActions block of a role definition.
type Permission struct {
	Actions    []string
	NotActions []string
	// Condition is the ABAC condition of the block (e.g. the Defender scanner
	// operator roles may only assign a handful of roles). "" when unconditional.
	Condition string
}

// Principal is an identity holding role assignments at subscription scope or
// above, and the roles through which it can elevate rights (if any).
type Principal struct {
	ID             string
	Name           string // display name / UPN, "" when it could not be resolved
	Type           string
	ElevatingRoles []string // "<role> at <scope>", unconditional
	// ConstrainedRoles are elevating roles whose assignment carries an ABAC
	// condition (delegation limited to some roles): not counted as elevation.
	ConstrainedRoles []string
}

// matchAction reports whether an ARM action pattern ("*", "Microsoft.Authorization/*",
// "*/write", ...) matches an action. Matching is case-insensitive; "*" matches any
// run of characters.
func matchAction(pattern, action string) bool {
	pattern, action = strings.ToLower(pattern), strings.ToLower(action)
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == action
	}
	if !strings.HasPrefix(action, parts[0]) {
		return false
	}
	action = action[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(action, mid)
		if i < 0 {
			return false
		}
		action = action[i+len(mid):]
	}
	return strings.HasSuffix(action, parts[len(parts)-1])
}

// CanElevate reports whether a role definition's permissions grant
// ElevationAction unconditionally (Actions matches it and NotActions doesn't
// carve it out). Blocks carrying an ABAC condition are not counted.
func CanElevate(permissions []Permission) bool {
	return grants(permissions, false)
}

// CanElevateUnderCondition reports whether ElevationAction is only granted
// through blocks carrying an ABAC condition (constrained delegation).
func CanElevateUnderCondition(permissions []Permission) bool {
	return grants(permissions, true)
}

func grants(permissions []Permission, conditional bool) bool {
	for _, p := range permissions {
		if (p.Condition != "") != conditional {
			continue
		}
		allowed := false
		for _, a := range p.Actions {
			if matchAction(a, ElevationAction) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		excluded := false
		for _, n := range p.NotActions {
			if matchAction(n, ElevationAction) {
				excluded = true
				break
			}
		}
		if !excluded {
			return true
		}
	}
	return false
}

// isBroadScope: the subscription itself, a management group, or the root.
func isBroadScope(scope, subscriptionID string) bool {
	scope = strings.ToLower(strings.TrimRight(scope, "/"))
	return scope == "" ||
		scope == "/subscriptions/"+strings.ToLower(subscriptionID) ||
		strings.HasPrefix(scope, "/providers/microsoft.management/managementgroups/")
}

// roleDefinitionsAPIVersion is the first ARM API version exposing the ABAC
// condition of a role definition's permission block. The SDK module is
// generated from 2022-04-01, which drops it, so the listing is a raw REST call.
const roleDefinitionsAPIVersion = "2022-05-01-preview"

type roleDefinition struct {
	ID         string `json:"id"`
	Properties struct {
		RoleName    string `json:"roleName"`
		Permissions []struct {
			Actions    []string `json:"actions"`
			NotActions []string `json:"notActions"`
			Condition  string   `json:"condition"`
		} `json:"permissions"`
	} `json:"properties"`
}

func (d roleDefinition) permissions() []Permission {
	var perms []Permission
	for _, p := range d.Properties.Permissions {
		perms = append(perms, Permission{Actions: p.Actions, NotActions: p.NotActions, Condition: p.Condition})
	}
	return perms
}

func listRoleDefinitions(ctx context.Context, s internal.Session) ([]roleDefinition, error) {
	client, err := arm.NewClient("yatas-azure/rbac", "v0.0.0", s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var all []roleDefinition
	next := client.Endpoint() + internal.SubscriptionScope(s.Target.SubscriptionID) + "/providers/Microsoft.Authorization/roleDefinitions?api-version=" + roleDefinitionsAPIVersion
	for next != "" {
		req, err := runtime.NewRequest(ctx, http.MethodGet, next)
		if err != nil {
			return nil, err
		}
		resp, err := client.Pipeline().Do(req)
		if err != nil {
			return nil, err
		}
		if !runtime.HasStatusCode(resp, http.StatusOK) {
			return nil, runtime.NewResponseError(resp)
		}
		var page struct {
			Value    []roleDefinition `json:"value"`
			NextLink string           `json:"nextLink"`
		}
		if err := runtime.UnmarshalAsJSON(resp, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Value...)
		next = page.NextLink
	}
	return all, nil
}

// GetPrincipals lists the identities that hold a role assignment at subscription
// scope or above, flagging the ones able to elevate rights.
func GetPrincipals(s internal.Session) ([]Principal, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	ctx := context.TODO()
	sub := s.Target.SubscriptionID

	type role struct {
		name        string
		elevates    bool
		constrained bool
	}
	roles := map[string]role{}
	defs, err := listRoleDefinitions(ctx, s)
	if err != nil {
		return nil, err
	}
	for _, d := range defs {
		roles[strings.ToLower(d.ID)] = role{name: d.Properties.RoleName, elevates: CanElevate(d.permissions()), constrained: CanElevateUnderCondition(d.permissions())}
	}

	assignClient, err := armauthorization.NewRoleAssignmentsClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	byPrincipal := map[string]*Principal{}
	var order []string
	pager := assignClient.NewListForSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, a := range page.Value {
			if a.Properties == nil || !isBroadScope(internal.Deref(a.Properties.Scope), sub) {
				continue
			}
			pid := internal.Deref(a.Properties.PrincipalID)
			p, ok := byPrincipal[pid]
			if !ok {
				ptype := ""
				if a.Properties.PrincipalType != nil {
					ptype = string(*a.Properties.PrincipalType)
				}
				p = &Principal{ID: pid, Type: ptype}
				byPrincipal[pid] = p
				order = append(order, pid)
			}
			r, known := roles[strings.ToLower(internal.Deref(a.Properties.RoleDefinitionID))]
			if known && (r.elevates || r.constrained) {
				entry := r.name + " at " + internal.Deref(a.Properties.Scope)
				if !r.elevates || internal.Deref(a.Properties.Condition) != "" {
					p.ConstrainedRoles = append(p.ConstrainedRoles, entry)
				} else {
					p.ElevatingRoles = append(p.ElevatingRoles, entry)
				}
			}
		}
	}
	principals := make([]Principal, 0, len(order))
	for _, id := range order {
		principals = append(principals, *byPrincipal[id])
	}
	resolveNames(ctx, s, principals)
	return principals, nil
}

// resolveNames fills Principal.Name from Microsoft Graph. It is best effort: the
// check is evaluated from ARM data alone, so a principal that cannot be read
// (no Entra access, deleted object) keeps its object ID as its only label.
func resolveNames(ctx context.Context, s internal.Session, principals []Principal) {
	g, err := internal.NewGraph(s)
	if err != nil {
		return
	}
	for i := range principals {
		name, err := internal.DirectoryObjectName(ctx, g, principals[i].ID)
		if err != nil {
			logger.Logger.Debug("Unable to resolve the name of a role assignment principal", "id", principals[i].ID, "error", err.Error())
			if !internal.IsNotFound(err) {
				return // no Entra access: don't repeat the failing call for every principal
			}
			continue
		}
		principals[i].Name = name
	}
}
