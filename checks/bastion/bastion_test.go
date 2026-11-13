package bastion

import (
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_checkIfLogs(t *testing.T) {
	for logs, want := range map[bool]string{true: "OK", false: "FAIL"} {
		in := internal.Fetched[Host]{Items: []Host{{Name: "b", Logs: logs}}}
		if got := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfLogs(cfg, in, "t") }); got.Status != want {
			t.Errorf("logs=%v: %s want %s", logs, got.Status, want)
		}
	}
}
