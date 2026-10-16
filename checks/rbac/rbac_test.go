package rbac

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_CanElevate(t *testing.T) {
	cases := []struct {
		name  string
		perms []Permission
		want  bool
	}{
		{"owner", []Permission{{Actions: []string{"*"}}}, true},
		{"user access administrator", []Permission{{Actions: []string{"*/read", "Microsoft.Authorization/*"}}}, true},
		{"exact action", []Permission{{Actions: []string{"Microsoft.Authorization/roleAssignments/write"}}}, true},
		{"contributor", []Permission{{Actions: []string{"*"}, NotActions: []string{"Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/elevateAccess/Action"}}}, false},
		{"reader", []Permission{{Actions: []string{"*/read"}}}, false},
		{"unrelated", []Permission{{Actions: []string{"Microsoft.Storage/*"}}}, false},
		{"case insensitive", []Permission{{Actions: []string{"microsoft.authorization/ROLEASSIGNMENTS/WRITE"}}}, true},
	}
	for _, c := range cases {
		if got := CanElevate(c.perms); got != c.want {
			t.Errorf("%s: CanElevate = %v, want %v", c.name, got, c.want)
		}
	}
}

func Test_isBroadScope(t *testing.T) {
	if !isBroadScope("/subscriptions/ABC", "abc") || !isBroadScope("/", "abc") {
		t.Error("subscription and root scopes are broad")
	}
	if isBroadScope("/subscriptions/abc/resourceGroups/rg", "abc") {
		t.Error("resource group scope is not broad")
	}
}

func Test_checkIfCannotElevateRights(t *testing.T) {
	run := func(in internal.Fetched[Principal], want string) {
		t.Helper()
		check := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfCannotElevateRights(cfg, in, "test") })
		if check.Status != want {
			t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
		}
		if check.Categories[len(check.Categories)-1] != "HDS" {
			t.Errorf("not tagged HDS: %v", check.Categories)
		}
	}
	run(internal.Fetched[Principal]{Items: []Principal{{ID: "p", Type: "User"}}}, "OK")
	run(internal.Fetched[Principal]{Items: []Principal{{ID: "p", Type: "User", ElevatingRoles: []string{"Owner at /subscriptions/x"}}}}, "FAIL")
	run(internal.Fetched[Principal]{Items: []Principal{{ID: "p", Type: "ServicePrincipal", ConstrainedRoles: []string{"RBAC Administrator at /subscriptions/x"}}}}, "OK")
	run(internal.Fetched[Principal]{Err: errors.New("403")}, "FAIL")
}
