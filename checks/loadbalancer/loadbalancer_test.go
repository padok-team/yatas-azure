package loadbalancer

import (
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_checkIfAccessLogs(t *testing.T) {
	for logs, want := range map[bool]string{true: "OK", false: "FAIL"} {
		in := internal.Fetched[Gateway]{Items: []Gateway{{Name: "g", AccessLogs: logs}}}
		if got := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfAccessLogs(cfg, in, "t") }); got.Status != want {
			t.Errorf("logs=%v: %s want %s", logs, got.Status, want)
		}
	}
}
