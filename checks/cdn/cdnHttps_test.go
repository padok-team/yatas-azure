package cdn

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_checkIfHTTPSOnly(t *testing.T) {
	run := func(in internal.Fetched[Entrypoint], want string) {
		t.Helper()
		check := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfHTTPSOnly(cfg, in, "test") })
		if check.Status != want {
			t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
		}
		if check.Categories[len(check.Categories)-1] != "HDS" {
			t.Errorf("not tagged HDS: %v", check.Categories)
		}
	}
	one := func(e Entrypoint) internal.Fetched[Entrypoint] {
		return internal.Fetched[Entrypoint]{Items: []Entrypoint{e}}
	}
	run(one(Entrypoint{Name: "e", HTTPSOnly: true}), "OK")
	run(one(Entrypoint{Name: "e"}), "FAIL")
	run(internal.Fetched[Entrypoint]{Err: errors.New("403")}, "FAIL")
}
