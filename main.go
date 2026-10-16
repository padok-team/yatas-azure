package main

import (
	"encoding/gob"
	"os"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/padok-team/yatas-azure/checks/aks"
	"github.com/padok-team/yatas-azure/checks/backup"
	"github.com/padok-team/yatas-azure/checks/cdn"
	"github.com/padok-team/yatas-azure/checks/cosmosdb"
	"github.com/padok-team/yatas-azure/checks/defender"
	"github.com/padok-team/yatas-azure/checks/disks"
	"github.com/padok-team/yatas-azure/checks/entra"
	"github.com/padok-team/yatas-azure/checks/network"
	"github.com/padok-team/yatas-azure/checks/rbac"
	"github.com/padok-team/yatas-azure/checks/sql"
	"github.com/padok-team/yatas-azure/checks/storage"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

type YatasPlugin struct {
	logger hclog.Logger
}

// Don't remove this function.
// This function is called by YATAS through the RPC.
// This is the entrypoint of the plugin.
//
// It receives as argument the YATAS config of the user and returns the results
// of all the checks executed.
func (g *YatasPlugin) Run(c *commons.Config) []commons.Tests {
	// Set the global logger to the one used by the plugin
	logger.Logger = g.logger

	// Read the configuration sent by YATAS to retrieve a common account
	// configuration that you can use in your checks to make API calls to a
	// cloud provider for example
	targets, err := internal.UnmarshalConfig(c)
	if err != nil {
		logger.Logger.Error("Error unmarshaling config", "error", err)
		return nil
	}

	return run(c, targets)
}

// run audits every target concurrently. A queue + wait group collect the results
// so targets never block one another.
func run(c *commons.Config, targets []internal.Target) []commons.Tests {
	var wg sync.WaitGroup
	queue := make(chan commons.Tests, 10)
	var checks []commons.Tests

	wg.Add(len(targets))
	for _, target := range targets {
		go runTestsForTarget(target, c, queue)
	}

	go func() {
		for t := range queue {
			checks = append(checks, t)
			wg.Done()
		}
	}()

	wg.Wait()
	return checks
}

func runTestsForTarget(target internal.Target, c *commons.Config, queue chan commons.Tests) {
	session := initSession(target)
	queue <- initTest(session, c, target)
}

// initSession builds the Azure credential shared by every getter of the target
// (≈ yatas-aws's initAuth). DefaultAzureCredential covers environment variables
// (AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID), workload identity,
// managed identity and a local `az login`, so no bespoke auth code is needed.
//
// A credential failure is kept in the session instead of aborting: every check
// then reports it as FAIL rather than silently reporting nothing.
func initSession(target internal.Target) internal.Session {
	logger.Logger.Debug("Init session", "target", target.Name)
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{TenantID: target.TenantID})
	if err != nil {
		logger.Logger.Error("Unable to build the Azure credential", "target", target.Name, "error", err.Error())
		return internal.Session{Target: target, CredentialErr: err}
	}
	return internal.Session{Target: target, Credential: cred}
}

// initTest runs every check category for one target and aggregates their checks.
// Add one `go commons.CheckMacroTest(...)` line per category you create under
// checks/ (this is the only place to register a category).
func initTest(s internal.Session, c *commons.Config, target internal.Target) commons.Tests {
	var checks commons.Tests
	checks.Account = target.Name

	var wg sync.WaitGroup
	queue := make(chan []commons.Check, 100)

	go commons.CheckMacroTest(&wg, c, network.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, storage.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, disks.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, backup.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, sql.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, defender.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, aks.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, cosmosdb.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, cdn.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, rbac.RunChecks)(&wg, s, c, queue)
	go commons.CheckMacroTest(&wg, c, entra.RunChecks)(&wg, s, c, queue)

	go func() {
		for t := range queue {
			checks.Checks = append(checks.Checks, t...)
			wg.Done()
		}
	}()

	wg.Wait()
	return checks
}

// handshakeConfigs are used to just do a basic handshake between
// a plugin and host. If the handshake fails, a user friendly error is shown.
// This prevents users from executing bad plugins or executing a plugin
// directory. It is a UX feature, not a security feature.
var handshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  2,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "hello",
}

// You do not need to change this function.
// This is the main entrypoint for the program, which launches the plugin RPC
// server.
func main() {
	// Register the types that will be used serialized and deserialized
	// and used in the RPC communication
	gob.Register([]interface{}{})
	gob.Register(map[string]interface{}{})

	// Here we setup the logger that will be used by the plugin and whose
	// output will be transmitted via RPC to YATAS
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Trace,
		Output:     os.Stderr,
		JSONFormat: true,
	})

	// Create an instance of YatasPlugin, which implements the Plugin interface
	// from hashicorp/go-plugin.
	yatasPlugin := &YatasPlugin{
		logger: logger,
	}

	// `pluginMap` is the map of plugins we can dispense.
	// Just this plugin in our case.
	var pluginMap = map[string]plugin.Plugin{
		internal.PluginName: &commons.YatasPlugin{Impl: yatasPlugin},
	}

	// Launch the plugin RPC server
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins:         pluginMap,
	})
}
