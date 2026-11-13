package vm

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

type fn = func(commons.CheckConfig, internal.Fetched[Machine], string)

func status(f fn, in internal.Fetched[Machine]) string {
	return internal.RunCheck(func(cfg commons.CheckConfig) { f(cfg, in, "t") }).Status
}

func one(m Machine) internal.Fetched[Machine] { return internal.Fetched[Machine]{Items: []Machine{m}} }

func Test_checks(t *testing.T) {
	if status(checkIfNoPublicIP, one(Machine{})) != "OK" || status(checkIfNoPublicIP, one(Machine{PublicIP: true})) != "FAIL" {
		t.Error("public ip")
	}
	if status(checkIfBootDiagnostics, one(Machine{BootDiag: true})) != "OK" || status(checkIfBootDiagnostics, one(Machine{})) != "FAIL" {
		t.Error("boot diagnostics")
	}
	for _, f := range []fn{checkIfNoPublicIP, checkIfBootDiagnostics} {
		if status(f, internal.Fetched[Machine]{Err: errors.New("403")}) != "FAIL" {
			t.Error("fetch error must fail")
		}
	}
}
