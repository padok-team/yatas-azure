package aks

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_checkIfPrivateOrRestricted(t *testing.T) {
	run := func(in internal.Fetched[Cluster], want string) {
		t.Helper()
		check := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfPrivateOrRestricted(cfg, in, "test") })
		if check.Status != want {
			t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
		}
		if check.Categories[len(check.Categories)-1] != "HDS" {
			t.Errorf("not tagged HDS: %v", check.Categories)
		}
	}
	one := func(c Cluster) internal.Fetched[Cluster] { return internal.Fetched[Cluster]{Items: []Cluster{c}} }
	run(one(Cluster{Name: "c", Private: true}), "OK")
	run(one(Cluster{Name: "c", AuthorizedIPRanges: []string{"203.0.113.0/24"}}), "OK")
	run(one(Cluster{Name: "c"}), "FAIL")
	run(one(Cluster{Name: "c", AuthorizedIPRanges: []string{"0.0.0.0/0"}}), "FAIL")
	run(internal.Fetched[Cluster]{Err: errors.New("403")}, "FAIL")
}
