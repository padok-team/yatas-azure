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

	// Scope: only the identities with a role assignment on the subscription.
	assigneeList, err := internal.GetAssignees(s)
	assignees := internal.Fetch("subscription role assignees", assigneeList, err)

	sps := derive(assignees, "Entra service principals", func(a []internal.Assignee) ([]ServicePrincipal, error) { return GetServicePrincipals(s, a) })
	members := derive(assignees, "Entra users", func(a []internal.Assignee) ([]User, error) { return GetUsers(s, a) })
	mfa := MFAInput{Users: members}
	if members.Err == nil {
		mfa.Evidence = GetMFAEvidence(s, members.Items)
	}
	policy := derive(members, "Entra password policy", func(u []User) ([]PasswordPolicy, error) { return GetPasswordPolicy(s, u) })
	apps := derive(sps, "Entra app registrations", func(p []ServicePrincipal) ([]Application, error) { return GetApplications(s, p) })

	go commons.CheckTest(checkConfig.Wg, c, NoInteractiveSignInID, checkIfNoInteractiveSignIn)(checkConfig, sps, NoInteractiveSignInID)
	go commons.CheckTest(checkConfig.Wg, c, MFAID, checkIfMFA)(checkConfig, mfa, MFAID)
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

// derive fetches B from the result of a previous fetch, propagating its error so
// a failure upstream is reported by every check that depends on it.
func derive[A, B any](from internal.Fetched[A], what string, fn func([]A) ([]B, error)) internal.Fetched[B] {
	if from.Err != nil {
		return internal.Fetched[B]{Err: from.Err}
	}
	items, err := fn(from.Items)
	return internal.Fetch(what, items, err)
}
