package internal

import (
	"sync"

	"github.com/padok-team/yatas/plugins/commons"
)

// RunCheck runs a check function that pushes exactly one Check on the queue and
// returns that check. Used by the unit tests of every category.
func RunCheck(fn func(commons.CheckConfig)) commons.Check {
	cfg := commons.CheckConfig{Wg: &sync.WaitGroup{}, Queue: make(chan commons.Check, 1)}
	fn(cfg)
	return <-cfg.Queue
}
