package keyvaultcerts

import (
	"testing"
	"time"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func status(f func(commons.CheckConfig, internal.Fetched[Certificate], string), c Certificate) string {
	in := internal.Fetched[Certificate]{Items: []Certificate{c}}
	return internal.RunCheck(func(cfg commons.CheckConfig) { f(cfg, in, "t") }).Status
}

func Test_checkIfNotExpiring(t *testing.T) {
	day := 24 * time.Hour
	cases := map[string]struct {
		c    Certificate
		want string
	}{
		"far":      {Certificate{Expires: time.Now().Add(90 * day)}, "OK"},
		"soon":     {Certificate{Expires: time.Now().Add(10 * day)}, "FAIL"},
		"expired":  {Certificate{Expires: time.Now().Add(-day)}, "FAIL"},
		"no vault": {Certificate{Err: "403"}, "FAIL"},
	}
	for name, c := range cases {
		if got := status(checkIfNotExpiring, c.c); got != c.want {
			t.Errorf("%s: %s want %s", name, got, c.want)
		}
	}
}

func Test_checkIfValid(t *testing.T) {
	if status(checkIfValid, Certificate{Enabled: true}) != "OK" || status(checkIfValid, Certificate{}) != "FAIL" ||
		status(checkIfValid, Certificate{Enabled: true, NotBefore: time.Now().Add(time.Hour)}) != "FAIL" {
		t.Error("valid")
	}
}
