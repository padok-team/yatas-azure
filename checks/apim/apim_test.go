package apim

import (
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func status(f func(commons.CheckConfig, internal.Fetched[Service], string), s Service) string {
	in := internal.Fetched[Service]{Items: []Service{s}}
	return internal.RunCheck(func(cfg commons.CheckConfig) { f(cfg, in, "t") }).Status
}

func Test_checks(t *testing.T) {
	if status(checkIfLogs, Service{GatewayLogs: true}) != "OK" || status(checkIfLogs, Service{}) != "FAIL" {
		t.Error("logs")
	}
	if status(checkIfNetworkRestricted, Service{InVNet: true}) != "OK" || status(checkIfNetworkRestricted, Service{PublicOff: true}) != "OK" ||
		status(checkIfNetworkRestricted, Service{}) != "FAIL" {
		t.Error("network")
	}
}
