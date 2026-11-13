package main

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

// hdsChecks is the phase-1 scope: the HDS checks mapped from yatas-aws (see
// PLAN.md §3). The list is explicit so adding or tagging a check is a conscious
// decision ("don't over-tag").
var hdsChecks = []string{
	"AZURE_NET_001", "AZURE_NET_002", "AZURE_NET_003", "AZURE_NET_004", "AZURE_NET_005",
	"AZURE_STO_001",
	"AZURE_DSK_001", "AZURE_DSK_002",
	"AZURE_BCK_001",
	"AZURE_SQL_001", "AZURE_SQL_002", "AZURE_SQL_003", "AZURE_SQL_004", "AZURE_SQL_005",
	"AZURE_DEF_001", "AZURE_DEF_002",
	"AZURE_AKS_001",
	"AZURE_COS_001", "AZURE_COS_002",
	"AZURE_CDN_001",
	"AZURE_RBAC_001",
	"AZURE_ENT_001", "AZURE_ENT_003", "AZURE_ENT_004",
}

// phase2Checks are the breadth checks (PLAN.md §4). They must never carry the HDS tag.
var phase2Checks = []string{
	"AZURE_ACT_001",
	"AZURE_STO_002", "AZURE_STO_003", "AZURE_STO_004", "AZURE_STO_005", "AZURE_STO_006", "AZURE_STO_007",
	"AZURE_DSK_003", "AZURE_DSK_004", "AZURE_DSK_005",
	"AZURE_AKS_002",
	"AZURE_DEF_003",
	"AZURE_NET_006", "AZURE_NET_007",
	"AZURE_SQL_006", "AZURE_SQL_007",
	"AZURE_COS_003",
	"AZURE_CDN_002", "AZURE_CDN_003", "AZURE_CDN_004",
	"AZURE_VM_001", "AZURE_VM_002",
	"AZURE_VMSS_001",
	"AZURE_ACR_001", "AZURE_ACR_002", "AZURE_ACR_003", "AZURE_ACR_004",
	"AZURE_APIM_001", "AZURE_APIM_002",
	"AZURE_SB_001",
	"AZURE_FUNC_001", "AZURE_FUNC_002",
	"AZURE_KVC_001", "AZURE_KVC_002",
	"AZURE_BAS_001",
	"AZURE_LB_001",
}

// With no usable credential every category must still emit all of its checks,
// each FAIL (an auth failure is never reported as compliant), and carry the HDS
// tag if and only if it is in the phase-1 list.
func TestAllHDSChecksRegisteredAndFailOnAuthError(t *testing.T) {
	logger.Logger = hclog.NewNullLogger()
	session := internal.Session{Target: internal.Target{Name: "test", SubscriptionID: "sub"}, CredentialErr: errors.New("no credential")}

	tests := initTest(session, &commons.Config{}, session.Target)

	got := map[string]commons.Check{}
	for _, c := range tests.Checks {
		if _, dup := got[c.Id]; dup {
			t.Errorf("duplicate check ID %s", c.Id)
		}
		got[c.Id] = c
		if !strings.HasPrefix(c.Id, "AZURE_") {
			t.Errorf("check ID %s must start with AZURE_", c.Id)
		}
		if c.Status != "FAIL" {
			t.Errorf("%s: status %s on auth failure, want FAIL", c.Id, c.Status)
		}
		hds := false
		for _, cat := range c.Categories {
			hds = hds || cat == "HDS"
		}
		if want := slices.Contains(hdsChecks, c.Id); hds != want {
			t.Errorf("%s: HDS tag = %v, want %v", c.Id, hds, want)
		}
	}
	for _, id := range append(slices.Clone(hdsChecks), phase2Checks...) {
		if _, ok := got[id]; !ok {
			t.Errorf("check %s is not registered", id)
		}
	}
	if want := len(hdsChecks) + len(phase2Checks); len(got) != want {
		t.Errorf("%d checks registered, want %d", len(got), want)
	}
}
