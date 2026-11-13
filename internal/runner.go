package internal

import (
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

// Entry is one check registered in a category.
type Entry struct {
	ID  string
	Run func(cfg commons.CheckConfig, id string)
}

// Bind pairs a check with the resources it evaluates.
func Bind[T any](id string, f Fetched[T], fn func(commons.CheckConfig, Fetched[T], string)) Entry {
	return Entry{ID: id, Run: func(cfg commons.CheckConfig, id string) { fn(cfg, f, id) }}
}

// RunCategory runs the checks of a category concurrently, honouring the
// include/exclude lists of the YATAS config, and pushes the finished checks on
// the queue. tag is only used for debug logs.
func RunCategory(tag string, c *commons.Config, queue chan []commons.Check, entries ...Entry) {
	logger.Logger.Debug(tag + " - Checks started")
	var cfg commons.CheckConfig
	cfg.Init(c)
	var checks []commons.Check

	for _, e := range entries {
		go commons.CheckTest(cfg.Wg, c, e.ID, e.Run2())(cfg, 0, e.ID)
	}

	go func() {
		for t := range cfg.Queue {
			t.EndCheck()
			checks = append(checks, t)
			cfg.Wg.Done()
		}
	}()

	cfg.Wg.Wait()

	queue <- checks
	logger.Logger.Debug(tag + " - Checks done")
}

// Run2 adapts the entry to the signature commons.CheckTest expects.
func (e Entry) Run2() func(commons.CheckConfig, int, string) {
	return func(cfg commons.CheckConfig, _ int, id string) { e.Run(cfg, id) }
}
