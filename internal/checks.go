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

// NewCheck initialises a check that is not part of the HDS scope.
func NewCheck(name, description, id string, categories ...string) commons.Check {
	if len(categories) == 0 {
		categories = []string{"Security", "Good Practice"}
	}
	var check commons.Check
	check.InitCheck(name, description, id, categories)
	return check
}

// Verdict is the outcome of a check for one resource.
type Verdict struct {
	ID  string
	OK  bool
	Msg string
}

// Evaluate adds one result per resource using fn and pushes the check on the
// queue. A nil verdict skips the resource (the check does not apply to it). A
// fetch error becomes a FAIL instead of an empty, compliant check.
func Evaluate[T any](cfg commons.CheckConfig, check commons.Check, f Fetched[T], what string, fn func(T) *Verdict) {
	if !f.Failed(&check, what) {
		for _, item := range f.Items {
			v := fn(item)
			if v == nil {
				continue
			}
			if v.OK {
				Pass(&check, v.ID, v.Msg)
			} else {
				Fail(&check, v.ID, v.Msg)
			}
		}
	}
	cfg.Queue <- check
}

// Yes / No build a passing / failing verdict.
func Yes(id, msg string) *Verdict { return &Verdict{ID: id, OK: true, Msg: msg} }
func No(id, msg string) *Verdict  { return &Verdict{ID: id, OK: false, Msg: msg} }
