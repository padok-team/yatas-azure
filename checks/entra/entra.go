package entra

import (
	"sync"
	"time"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	logger.Logger.Debug("ENT - Checks started")
	var checkConfig commons.CheckConfig
	checkConfig.Init(c)
	var checks []commons.Check

	spList, err := GetServicePrincipals(s)
	sps := internal.Fetch("Entra service principals", spList, err)
	userList, err := GetUsers(s)
	users := internal.Fetch("Entra users and MFA registrations", userList, err)
	policyList, err := GetPasswordPolicy(s)
	policy := internal.Fetch("Entra password policy", policyList, err)
	appList, err := GetApplications(s)
	apps := internal.Fetch("Entra app registrations", appList, err)

	go commons.CheckTest(checkConfig.Wg, c, NoInteractiveSignInID, checkIfNoInteractiveSignIn)(checkConfig, sps, NoInteractiveSignInID)
	go commons.CheckTest(checkConfig.Wg, c, MFAID, checkIfMFA)(checkConfig, users, MFAID)
	go commons.CheckTest(checkConfig.Wg, c, PasswordPolicyID, checkIfPasswordPolicy)(checkConfig, policy, PasswordPolicyID)
	go commons.CheckTest(checkConfig.Wg, c, CredentialAgeID, checkCredentialAgeNow)(checkConfig, apps, CredentialAgeID)

	go func() {
		for t := range checkConfig.Queue {
			t.EndCheck()
			checks = append(checks, t)
			checkConfig.Wg.Done()
		}
	}()

	checkConfig.Wg.Wait()

	queue <- checks
	logger.Logger.Debug("ENT - Checks done")
}

// checkCredentialAgeNow binds the real clock to the check so it fits commons.CheckTest.
func checkCredentialAgeNow(checkConfig commons.CheckConfig, apps internal.Fetched[Application], testName string) {
	checkIfCredentialsYoungerThan90Days(checkConfig, apps, testName, time.Now)
}
