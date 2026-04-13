package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"open-democracy/internal/tui"
)

type cli struct {
	stdout        io.Writer
	stderr        io.Writer
	runTUI        func() error
	showStatus    func(io.Writer) error
	demoStart     func(io.Writer) error
	demoStop      func(io.Writer) error
	nodeBootstrap func(io.Writer, tui.BootstrapOptions) error
	nodeStart     func(io.Writer) error
	nodeStop      func(io.Writer) error
	networkStart  func(io.Writer, tui.NetworkStartOptions) error
	networkStop   func(io.Writer, tui.NetworkStopOptions) error
	stopAll       func(io.Writer) error
	configureNode func(tui.SetupValues) (tui.ProjectState, error)
}

func newCLI(stdout, stderr io.Writer) cli {
	return cli{
		stdout:        stdout,
		stderr:        stderr,
		runTUI:        tui.Run,
		showStatus:    tui.Status,
		demoStart:     tui.QuickStart,
		demoStop:      tui.StopDemo,
		nodeBootstrap: tui.BootstrapNode,
		nodeStart:     tui.StartNode,
		nodeStop:      tui.StopNode,
		networkStart:  tui.StartNetwork,
		networkStop:   tui.StopNetwork,
		stopAll:       tui.StopAll,
		configureNode: tui.ConfigureNode,
	}
}

func (c cli) run(args []string) int {
	if len(args) == 0 {
		return c.runTUICommand()
	}

	if isHelpArg(args[0]) {
		c.printRootHelp(c.stdout)
		return 0
	}

	switch args[0] {
	case "tui":
		return c.runLeaf(args[1:], c.printTUIHelp, func(io.Writer) error {
			return c.runTUI()
		})
	case "status":
		return c.runLeaf(args[1:], c.printStatusHelp, c.showStatus)
	case "stop":
		return c.runLeaf(args[1:], c.printStopHelp, c.stopAll)
	case "demo":
		return c.runDemo(args[1:])
	case "node":
		return c.runNode(args[1:])
	case "network":
		return c.runNetwork(args[1:])
	default:
		return c.usageError(fmt.Sprintf("unknown command %q", args[0]), c.printRootHelp)
	}
}

func (c cli) runDemo(args []string) int {
	if len(args) == 0 || isHelpArg(args[0]) {
		c.printDemoHelp(c.stdout)
		return 0
	}

	switch args[0] {
	case "start":
		return c.runLeaf(args[1:], c.printDemoHelp, c.demoStart)
	case "stop":
		return c.runLeaf(args[1:], c.printDemoHelp, c.demoStop)
	default:
		return c.usageError(fmt.Sprintf("unknown demo command %q", args[0]), c.printDemoHelp)
	}
}

func (c cli) runNode(args []string) int {
	if len(args) == 0 || isHelpArg(args[0]) {
		c.printNodeHelp(c.stdout)
		return 0
	}

	switch args[0] {
	case "setup":
		return c.runNodeSetup(args[1:])
	case "bootstrap":
		return c.runNodeBootstrap(args[1:])
	case "start":
		return c.runLeaf(args[1:], c.printNodeHelp, c.nodeStart)
	case "stop":
		return c.runLeaf(args[1:], c.printNodeHelp, c.nodeStop)
	default:
		return c.usageError(fmt.Sprintf("unknown node command %q", args[0]), c.printNodeHelp)
	}
}

func (c cli) runNetwork(args []string) int {
	if len(args) == 0 || isHelpArg(args[0]) {
		c.printNetworkHelp(c.stdout)
		return 0
	}

	switch args[0] {
	case "start":
		return c.runNetworkStart(args[1:])
	case "stop":
		return c.runNetworkStop(args[1:])
	default:
		return c.usageError(fmt.Sprintf("unknown network command %q", args[0]), c.printNetworkHelp)
	}
}

func (c cli) runNodeSetup(args []string) int {
	fs := flag.NewFlagSet("odctl node setup", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		c.printNodeSetupHelp(c.stderr)
	}

	orgName := fs.String("org-name", "", "Organization slug written to democracy.toml")
	displayName := fs.String("display-name", "", "Human-readable organization name")
	scopePrefix := fs.String("scope-prefix", "", "Root scope hierarchy prefix")
	domain := fs.String("domain", "", "Organization domain injected into the node stack")
	gatewayPort := fs.String("gateway-port", "", "Gateway listen port")
	gatewayUser := fs.String("gateway-user", "", "Default dashboard participant ID when X-User is omitted")
	caAdminUser := fs.String("ca-admin-user", "", "Fabric CA registrar username")
	caAdminPass := fs.String("ca-admin-pass", "", "Fabric CA registrar password")
	persistEnv := fs.Bool("persist-env", false, "Also write a legacy federation/.env file")
	envOut := fs.String("env-out", "", "Custom path for the legacy .env export")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if len(fs.Args()) > 0 {
		return c.usageError(fmt.Sprintf("unexpected arguments: %s", strings.Join(fs.Args(), " ")), c.printNodeSetupHelp)
	}

	state, err := c.configureNode(tui.SetupValues{
		OrgName:            *orgName,
		OrgDisplay:         *displayName,
		ScopePrefix:        *scopePrefix,
		Domain:             *domain,
		GatewayPort:        *gatewayPort,
		GatewayDefaultUser: *gatewayUser,
		CAAdminUser:        *caAdminUser,
		CAAdminPass:        *caAdminPass,
		PersistLegacyEnv:   *persistEnv || strings.TrimSpace(*envOut) != "",
		LegacyEnvPath:      strings.TrimSpace(*envOut),
	})
	if err != nil {
		return c.commandError(err)
	}

	if _, err := fmt.Fprintf(c.stdout, "Configuration saved to %s\n", filepath.Join(state.FedDir, "democracy.toml")); err != nil {
		return c.commandError(err)
	}
	if *persistEnv || strings.TrimSpace(*envOut) != "" {
		outPath := strings.TrimSpace(*envOut)
		if outPath == "" {
			outPath = filepath.Join(state.FedDir, ".env")
		}
		if _, err := fmt.Fprintf(c.stdout, "Legacy env exported to %s\n", outPath); err != nil {
			return c.commandError(err)
		}
	}
	if _, err := fmt.Fprintf(c.stdout, "Organization: %s\n", state.OrgName); err != nil {
		return c.commandError(err)
	}
	if state.ScopePrefix != "" {
		if _, err := fmt.Fprintf(c.stdout, "Scope prefix: %s\n", state.ScopePrefix); err != nil {
			return c.commandError(err)
		}
	}
	if _, err := fmt.Fprintf(c.stdout, "MSP ID: %s\n", state.MspID); err != nil {
		return c.commandError(err)
	}
	if _, err := fmt.Fprintf(c.stdout, "Domain: %s\n", state.Domain); err != nil {
		return c.commandError(err)
	}
	if _, err := fmt.Fprintf(c.stdout, "Dashboard: http://localhost:%s/\n", state.GatewayPort); err != nil {
		return c.commandError(err)
	}

	return 0
}

func (c cli) runNodeBootstrap(args []string) int {
	fs := flag.NewFlagSet("odctl node bootstrap", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		c.printNodeBootstrapHelp(c.stderr)
	}

	persistProfile := fs.Bool("persist-connection-profile", false, "Also write federation/connection-profile.yaml")
	profileOut := fs.String("connection-profile-out", "", "Custom path for the connection profile export")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if len(fs.Args()) > 0 {
		return c.usageError(fmt.Sprintf("unexpected arguments: %s", strings.Join(fs.Args(), " ")), c.printNodeBootstrapHelp)
	}

	if err := c.nodeBootstrap(c.stdout, tui.BootstrapOptions{
		PersistConnectionProfile: *persistProfile || strings.TrimSpace(*profileOut) != "",
		ConnectionProfilePath:    strings.TrimSpace(*profileOut),
	}); err != nil {
		return c.commandError(err)
	}
	return 0
}

func (c cli) runNetworkStart(args []string) int {
	fs := flag.NewFlagSet("odctl network start", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		c.printNetworkStartHelp(c.stderr)
	}

	instance := fs.String("instance", "", "Optional explicit instance name; omit to create an isolated run automatically")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if len(fs.Args()) > 0 {
		return c.usageError(fmt.Sprintf("unexpected arguments: %s", strings.Join(fs.Args(), " ")), c.printNetworkStartHelp)
	}
	if err := c.networkStart(c.stdout, tui.NetworkStartOptions{
		Instance: strings.TrimSpace(*instance),
	}); err != nil {
		return c.commandError(err)
	}
	return 0
}

func (c cli) runNetworkStop(args []string) int {
	fs := flag.NewFlagSet("odctl network stop", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		c.printNetworkStopHelp(c.stderr)
	}

	instance := fs.String("instance", "", "Founding network instance to stop")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if len(fs.Args()) > 0 {
		return c.usageError(fmt.Sprintf("unexpected arguments: %s", strings.Join(fs.Args(), " ")), c.printNetworkStopHelp)
	}
	if strings.TrimSpace(*instance) == "" {
		return c.usageError("network stop requires --instance", c.printNetworkStopHelp)
	}
	if err := c.networkStop(c.stdout, tui.NetworkStopOptions{
		Instance: strings.TrimSpace(*instance),
	}); err != nil {
		return c.commandError(err)
	}
	return 0
}

func (c cli) runLeaf(args []string, help func(io.Writer), run func(io.Writer) error) int {
	if len(args) > 0 {
		if isHelpArg(args[0]) {
			help(c.stdout)
			return 0
		}
		return c.usageError(fmt.Sprintf("unexpected arguments: %s", strings.Join(args, " ")), help)
	}

	if err := run(c.stdout); err != nil {
		return c.commandError(err)
	}
	return 0
}

func (c cli) runTUICommand() int {
	if err := c.runTUI(); err != nil {
		return c.commandError(err)
	}
	return 0
}

func (c cli) commandError(err error) int {
	_, _ = fmt.Fprintf(c.stderr, "Error: %v\n", err)
	return 1
}

func (c cli) usageError(message string, help func(io.Writer)) int {
	_, _ = fmt.Fprintf(c.stderr, "Error: %s\n\n", message)
	help(c.stderr)
	return 2
}

func (c cli) printRootHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `odctl controls the local Open Democracy demo stack and federation node workflows.

Usage:
  odctl                 Launch the interactive TUI
  odctl tui             Launch the interactive TUI
  odctl status          Show demo and node status
  odctl stop            Stop demo and federation node services
  odctl demo <command>  Manage the demo dashboard stack
  odctl node <command>  Manage federation node configuration and lifecycle
  odctl network <command>  Manage founding-network generation and lifecycle

Demo commands:
  odctl demo start      Build and start the demo dashboard stack
  odctl demo stop       Stop the demo dashboard stack

Node commands:
  odctl node setup      Write federation/democracy.toml from flags
  odctl node bootstrap  Generate node crypto material
  odctl node start      Build and start the federation node stack
  odctl node stop       Stop the federation node stack

Network commands:
  odctl network start   Generate and start an isolated founding network
  odctl network stop    Stop an isolated founding network

Examples:
  odctl
  odctl status
  odctl demo start
  odctl node setup --org-name city-porto-alegre --display-name "City of Porto Alegre" --scope-prefix GOV:CITY_PORTO_ALEGRE --domain porto-alegre.gov.local
  odctl node bootstrap --persist-connection-profile
  odctl node start
  odctl network start
`)
}

func (c cli) printDemoHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl demo start
  odctl demo stop

Commands:
  start   Build and start the root demo dashboard stack
  stop    Stop the root demo dashboard stack
`)
}

func (c cli) printNodeHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl node setup [flags]
  odctl node bootstrap [flags]
  odctl node start
  odctl node stop

Commands:
  setup      Write federation/democracy.toml from CLI flags
  bootstrap  Generate crypto material; optionally export a connection profile
  start      Build and start the federation node stack
  stop       Stop the federation node stack
`)
}

func (c cli) printNetworkHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl network start [flags]
  odctl network stop --instance NAME

Commands:
  start   Generate and start an isolated founding network from democracy.toml
  stop    Stop a previously generated founding-network instance
`)
}

func (c cli) printNodeSetupHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl node setup --org-name NAME [--display-name NAME] [--scope-prefix PREFIX] [--domain DOMAIN] [--gateway-port PORT] [--gateway-user ID] [--ca-admin-user NAME] [--ca-admin-pass PASS] [--persist-env]

Flags:
  --org-name      Organization slug written to democracy.toml
  --display-name  Human-readable organization name
  --scope-prefix  Root scope hierarchy prefix
  --domain        Organization domain injected into docker compose
  --gateway-port  Gateway listen port
  --gateway-user  Default participant ID for dashboard actions without X-User
  --ca-admin-user Fabric CA registrar username
  --ca-admin-pass Fabric CA registrar password
  --persist-env   Also export a legacy federation/.env file
  --env-out       Custom path for the legacy .env export
`)
}

func (c cli) printNodeBootstrapHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl node bootstrap [--persist-connection-profile] [--connection-profile-out PATH]

Flags:
  --persist-connection-profile  Also export federation/connection-profile.yaml
  --connection-profile-out      Custom path for the connection profile export
`)
}

func (c cli) printNetworkStartHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl network start [--instance NAME]

Flags:
  --instance  Explicit isolated run name. When omitted, odctl generates a unique instance name.
`)
}

func (c cli) printNetworkStopHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl network stop --instance NAME

Flags:
  --instance  Founding-network instance to stop.
`)
}

func (c cli) printStatusHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl status

Show the current demo stack, federation node stack, and local configuration summary.
`)
}

func (c cli) printStopHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl stop

Stop both the demo dashboard stack and the federation node stack.
`)
}

func (c cli) printTUIHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage:
  odctl
  odctl tui

Launch the interactive TUI.
`)
}

func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "help"
}
