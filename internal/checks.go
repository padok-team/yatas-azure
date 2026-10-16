package internal

import (
	"fmt"

	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

// HDSCategories are the categories carried by every HDS-tagged check. The literal
// "HDS" string is what `yatas --hds` filters on.
var HDSCategories = []string{"Security", "Good Practice", "HDS"}

// Fetched is what a getter returns: the resources, or the error that prevented
// listing them. Carrying the error to the check (instead of returning an empty
// list) stops an auth/permission failure from being reported as "compliant".
type Fetched[T any] struct {
	Items []T
	Err   error
}

// Fetch wraps a getter's outcome and logs the error once.
func Fetch[T any](what string, items []T, err error) Fetched[T] {
	if err != nil {
		logger.Logger.Error("Unable to fetch "+what, "error", err.Error())
	}
	return Fetched[T]{Items: items, Err: err}
}

// Failed adds a FAIL result to the check when the resources could not be
// fetched, and reports whether the caller should stop.
func (f Fetched[T]) Failed(check *commons.Check, what string) bool {
	if f.Err == nil {
		return false
	}
	check.AddResult(commons.Result{
		Status:  "FAIL",
		Message: fmt.Sprintf("Unable to evaluate: could not fetch %s: %v", what, f.Err),
	})
	return true
}

// NewHDSCheck initialises a check carrying the HDS tag.
func NewHDSCheck(name, description, id string) commons.Check {
	var check commons.Check
	check.InitCheck(name, description, id, HDSCategories)
	return check
}

// Pass / Fail add an OK / FAIL result for one resource.
func Pass(check *commons.Check, resourceID, message string) {
	check.AddResult(commons.Result{Status: "OK", Message: message, ResourceID: resourceID})
}

func Fail(check *commons.Check, resourceID, message string) {
	check.AddResult(commons.Result{Status: "FAIL", Message: message, ResourceID: resourceID})
}
