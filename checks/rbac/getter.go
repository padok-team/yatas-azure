package rbac

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/padok-team/yatas-azure/internal"
)

// ElevationAction is the ARM permission that lets a principal grant itself (or
// anyone) more rights, i.e. elevate.
const ElevationAction = "Microsoft.Authorization/roleAssignments/write"

// Permission is one Actions / NotActions block of a role definition.
type Permission struct {
	Actions    []string
	NotActions []string
}

// Principal is an identity holding role assignments at subscription scope or
// above, and the roles through which it can elevate rights (if any).
type Principal struct {
	ID             string
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
// ElevationAction (Actions matches it and NotActions doesn't carve it out).
func CanElevate(permissions []Permission) bool {
	for _, p := range permissions {
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

// GetPrincipals lists the identities that hold a role assignment at subscription
// scope or above, flagging the ones able to elevate rights.
func GetPrincipals(s internal.Session) ([]Principal, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	ctx := context.TODO()
	sub := s.Target.SubscriptionID

	defClient, err := armauthorization.NewRoleDefinitionsClient(s.Credential, nil)
	if err != nil {
		return nil, err
	}
	type role struct {
		name     string
		elevates bool
	}
	roles := map[string]role{}
	defPager := defClient.NewListPager(internal.SubscriptionScope(sub), nil)
	for defPager.More() {
		page, err := defPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, d := range page.Value {
			if d.ID == nil || d.Properties == nil {
				continue
			}
			var perms []Permission
			for _, p := range d.Properties.Permissions {
				var perm Permission
				for _, a := range p.Actions {
					perm.Actions = append(perm.Actions, internal.Deref(a))
				}
				for _, n := range p.NotActions {
					perm.NotActions = append(perm.NotActions, internal.Deref(n))
				}
				perms = append(perms, perm)
			}
			roles[strings.ToLower(*d.ID)] = role{name: internal.Deref(d.Properties.RoleName), elevates: CanElevate(perms)}
		}
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
			if known && r.elevates {
				entry := r.name + " at " + internal.Deref(a.Properties.Scope)
				if internal.Deref(a.Properties.Condition) != "" {
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
	return principals, nil
}
