package main

import (
	"errors"
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

// With no usable credential every category must still emit all of its checks,
// each tagged HDS and each FAIL: an auth failure is never reported as compliant.
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
		if !hds {
			t.Errorf("%s is not tagged HDS", c.Id)
		}
	}
	for _, id := range hdsChecks {
		if _, ok := got[id]; !ok {
			t.Errorf("HDS check %s is not registered", id)
		}
	}
	if len(got) != len(hdsChecks) {
		t.Errorf("%d checks registered, want %d (phase 1 = HDS only)", len(got), len(hdsChecks))
	}
}
