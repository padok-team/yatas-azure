package acr

import (
	"testing"

	"github.com/padok-team/yatas-azure/checks/defender"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func status(fn func(commons.CheckConfig, string)) string {
	return internal.RunCheck(func(cfg commons.CheckConfig) { fn(cfg, "t") }).Status
}

func reg(r Registry) internal.Fetched[Registry] {
	return internal.Fetched[Registry]{Items: []Registry{r}}
}

func bind(f func(commons.CheckConfig, internal.Fetched[Registry], string), r Registry) func(commons.CheckConfig, string) {
	return func(cfg commons.CheckConfig, id string) { f(cfg, reg(r), id) }
}

func Test_checks(t *testing.T) {
	cases := []struct {
		name   string
		f      func(commons.CheckConfig, internal.Fetched[Registry], string)
		ok, ko Registry
	}{
		{"encrypted", checkIfEncrypted, Registry{CustomerKey: true}, Registry{}},
		{"retention", checkIfRetention, Registry{RetentionPolicy: true}, Registry{}},
		{"admin", checkIfAdminDisabled, Registry{}, Registry{AdminUserEnabled: true}},
	}
	for _, c := range cases {
		if status(bind(c.f, c.ok)) != "OK" || status(bind(c.f, c.ko)) != "FAIL" {
			t.Errorf("%s", c.name)
		}
	}
	on := internal.Fetched[defender.Plan]{Items: []defender.Plan{{Name: "Containers", Standard: true}}}
	off := internal.Fetched[defender.Plan]{Items: []defender.Plan{{Name: "Containers"}}}
	if status(checkIfScanning(reg(Registry{}), on)) != "OK" || status(checkIfScanning(reg(Registry{}), off)) != "FAIL" {
		t.Error("scanning")
	}
}
