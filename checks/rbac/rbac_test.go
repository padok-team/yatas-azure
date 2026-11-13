package rbac

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

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
		{"conditional block only", []Permission{{Actions: []string{"Microsoft.Authorization/roleAssignments/write"}, Condition: "@Request[...]"}}, false},
		{"case insensitive", []Permission{{Actions: []string{"microsoft.authorization/ROLEASSIGNMENTS/WRITE"}}}, true},
	}
	for _, c := range cases {
		if got := CanElevate(c.perms); got != c.want {
			t.Errorf("%s: CanElevate = %v, want %v", c.name, got, c.want)
		}
	}
}

func Test_CanElevateUnderCondition(t *testing.T) {
	conditional := []Permission{{Actions: []string{"Microsoft.Authorization/roleAssignments/write"}, Condition: "@Request[...]"}}
	if !CanElevateUnderCondition(conditional) || CanElevate(conditional) {
		t.Error("a conditional grant is constrained, not unconditional")
	}
	if CanElevateUnderCondition([]Permission{{Actions: []string{"*"}}}) {
		t.Error("an unconditional grant is not constrained")
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

func Test_principalLabel(t *testing.T) {
	if got := (Principal{ID: "id"}).label(); got != "id" {
		t.Errorf("label without name = %q", got)
	}
	if got := (Principal{ID: "id", Name: "Admins"}).label(); got != "Admins (id)" {
		t.Errorf("label with name = %q", got)
	}
}

type fakeCredential struct{}

func (fakeCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "tok", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func Test_DirectoryObjectNameUsedForLabels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directoryObjects/user":
			fmt.Fprint(w, `{"displayName":"Jane","userPrincipalName":"jane@x.com"}`)
		case "/directoryObjects/group":
			fmt.Fprint(w, `{"displayName":"Admins"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	old := internal.GraphBaseURL
	internal.GraphBaseURL = srv.URL
	defer func() { internal.GraphBaseURL = old }()

	g := &internal.Graph{Credential: fakeCredential{}, HTTP: srv.Client()}
	for id, want := range map[string]string{"user": "jane@x.com", "group": "Admins"} {
		if got, err := internal.DirectoryObjectName(context.TODO(), g, id); err != nil || got != want {
			t.Errorf("%s: got %q, %v, want %q", id, got, err, want)
		}
	}
	if _, err := internal.DirectoryObjectName(context.TODO(), g, "gone"); !internal.IsNotFound(err) {
		t.Errorf("a deleted object must surface as not found, got %v", err)
	}
}
