package functions

import (
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func status(f func(commons.CheckConfig, internal.Fetched[App], string), a App) string {
	in := internal.Fetched[App]{Items: []App{a}}
	return internal.RunCheck(func(cfg commons.CheckConfig) { f(cfg, in, "t") }).Status
}

func Test_checks(t *testing.T) {
	if status(checkIfPrivate, App{VNet: true}) != "OK" || status(checkIfPrivate, App{PublicOff: true}) != "OK" || status(checkIfPrivate, App{}) != "FAIL" {
		t.Error("private")
	}
	if status(checkIfHTTPSOnly, App{HTTPSOnly: true}) != "OK" || status(checkIfHTTPSOnly, App{}) != "FAIL" {
		t.Error("https")
	}
}
