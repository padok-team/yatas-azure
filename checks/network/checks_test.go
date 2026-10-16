package network

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func fetched(v ...VNet) internal.Fetched[VNet] { return internal.Fetched[VNet]{Items: v} }

func run(t *testing.T, fn func(commons.CheckConfig, internal.Fetched[VNet], string), in internal.Fetched[VNet], want string) {
	t.Helper()
	check := internal.RunCheck(func(cfg commons.CheckConfig) { fn(cfg, in, "test") })
	if check.Status != want {
		t.Errorf("status = %s, want %s (results: %+v)", check.Status, want, check.Results)
	}
	hds := false
	for _, c := range check.Categories {
		hds = hds || c == "HDS"
	}
	if !hds {
		t.Errorf("check is not tagged HDS: %v", check.Categories)
	}
}

func Test_checkIfSingleVNetPerRegion(t *testing.T) {
	run(t, checkIfSingleVNetPerRegion, fetched(VNet{Name: "a", Location: "francecentral"}, VNet{Name: "b", Location: "westeurope"}), "OK")
	run(t, checkIfSingleVNetPerRegion, fetched(VNet{Name: "a", Location: "francecentral"}, VNet{Name: "b", Location: "francecentral"}), "FAIL")
}

func Test_checkIfPrivateAndPublicSubnets(t *testing.T) {
	run(t, checkIfPrivateAndPublicSubnets, fetched(VNet{Name: "a", Subnets: []Subnet{{Public: true}, {Public: false}}}), "OK")
	run(t, checkIfPrivateAndPublicSubnets, fetched(VNet{Name: "a", Subnets: []Subnet{{Public: false}, {Public: false}}}), "FAIL")
	run(t, checkIfPrivateAndPublicSubnets, fetched(VNet{Name: "a", Subnets: []Subnet{{Public: true}}}), "FAIL")
}

func Test_checkIfAtLeastTwoSubnets(t *testing.T) {
	run(t, checkIfAtLeastTwoSubnets, fetched(VNet{Name: "a", Subnets: []Subnet{{}, {}}}), "OK")
	run(t, checkIfAtLeastTwoSubnets, fetched(VNet{Name: "a", Subnets: []Subnet{{}}}), "FAIL")
}

func Test_checkIfZoneRedundant(t *testing.T) {
	run(t, checkIfZoneRedundant, fetched(VNet{Name: "a", VMCount: 3, VMZones: []string{"1", "2"}}), "OK")
	run(t, checkIfZoneRedundant, fetched(VNet{Name: "a", VMCount: 1}), "OK")
	run(t, checkIfZoneRedundant, fetched(VNet{Name: "a", VMCount: 3, VMZones: []string{"1"}}), "FAIL")
}

func Test_checkIfFlowLogsEnabled(t *testing.T) {
	run(t, checkIfFlowLogsEnabled, fetched(VNet{Name: "a", FlowLogged: true}), "OK")
	run(t, checkIfFlowLogsEnabled, fetched(VNet{Name: "a", FlowLogged: false}), "FAIL")
}

// A fetch error must never be reported as compliant.
func Test_fetchErrorFails(t *testing.T) {
	failed := internal.Fetched[VNet]{Err: errors.New("403 forbidden")}
	for _, fn := range []func(commons.CheckConfig, internal.Fetched[VNet], string){
		checkIfSingleVNetPerRegion, checkIfPrivateAndPublicSubnets, checkIfAtLeastTwoSubnets, checkIfZoneRedundant, checkIfFlowLogsEnabled,
	} {
		run(t, fn, failed, "FAIL")
	}
}
