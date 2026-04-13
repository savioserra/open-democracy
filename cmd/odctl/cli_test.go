package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"open-democracy/internal/tui"
)

func TestCLIUsesTUIByDefault(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false

	c := cli{
		stdout: &stdout,
		stderr: &stderr,
		runTUI: func() error {
			called = true
			return nil
		},
	}

	if code := c.run(nil); code != 0 {
		t.Fatalf("run() returned %d, want 0", code)
	}
	if !called {
		t.Fatal("expected TUI to launch by default")
	}
}

func TestCLIShowsRootHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	c := newStubCLI(&stdout, &stderr)

	if code := c.run([]string{"--help"}); code != 0 {
		t.Fatalf("run(--help) returned %d, want 0", code)
	}
	text := stdout.String()
	for _, want := range []string{"odctl demo start", "odctl network start"} {
		if !strings.Contains(text, want) {
			t.Fatalf("root help missing %q:\n%s", want, text)
		}
	}
}

func TestCLIRoutesNodeSetup(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var got tui.SetupValues
	c := newStubCLI(&stdout, &stderr)
	c.configureNode = func(values tui.SetupValues) (tui.ProjectState, error) {
		got = values
		return tui.ProjectState{
			FedDir:      "/repo/federation",
			OrgName:     values.OrgName,
			ScopePrefix: values.ScopePrefix,
			GatewayPort: values.GatewayPort,
			MspID:       "CityPortoAlegreMSP",
			Domain:      "city-porto-alegre.od.example.com",
		}, nil
	}

	code := c.run([]string{
		"node", "setup",
		"--org-name", "city-porto-alegre",
		"--display-name", "City of Porto Alegre",
		"--scope-prefix", "GOV:CITY_PORTO_ALEGRE",
		"--domain", "porto-alegre.gov.local",
		"--gateway-port", "8081",
		"--gateway-user", "savio",
		"--ca-admin-user", "registrar",
		"--ca-admin-pass", "secretpw",
	})
	if code != 0 {
		t.Fatalf("run(node setup) returned %d, want 0; stderr=%s", code, stderr.String())
	}
	if got.OrgName != "city-porto-alegre" ||
		got.OrgDisplay != "City of Porto Alegre" ||
		got.ScopePrefix != "GOV:CITY_PORTO_ALEGRE" ||
		got.Domain != "porto-alegre.gov.local" ||
		got.GatewayPort != "8081" ||
		got.GatewayDefaultUser != "savio" ||
		got.CAAdminUser != "registrar" ||
		got.CAAdminPass != "secretpw" {
		t.Fatalf("unexpected setup values: %#v", got)
	}
	if !strings.Contains(stdout.String(), "Configuration saved to /repo/federation/democracy.toml") {
		t.Fatalf("setup output missing save confirmation:\n%s", stdout.String())
	}
}

func TestCLINodeSetupExportsLegacyEnv(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var got tui.SetupValues
	c := newStubCLI(&stdout, &stderr)
	c.configureNode = func(values tui.SetupValues) (tui.ProjectState, error) {
		got = values
		return tui.ProjectState{
			FedDir:      "/repo/federation",
			OrgName:     values.OrgName,
			ScopePrefix: values.ScopePrefix,
			GatewayPort: "8080",
			MspID:       "ShyylolMSP",
			Domain:      "shyylol.od.local",
		}, nil
	}

	code := c.run([]string{
		"node", "setup",
		"--org-name", "shyylol",
		"--env-out", "/tmp/node.env",
	})
	if code != 0 {
		t.Fatalf("run(node setup --env-out) returned %d, want 0; stderr=%s", code, stderr.String())
	}
	if !got.PersistLegacyEnv {
		t.Fatalf("expected PersistLegacyEnv to be true, got %#v", got)
	}
	if got.LegacyEnvPath != "/tmp/node.env" {
		t.Fatalf("LegacyEnvPath = %q, want %q", got.LegacyEnvPath, "/tmp/node.env")
	}
	if !strings.Contains(stdout.String(), "Legacy env exported to /tmp/node.env") {
		t.Fatalf("setup output missing env export confirmation:\n%s", stdout.String())
	}
}

func TestCLIPassesBootstrapExportFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var got tui.BootstrapOptions
	c := newStubCLI(&stdout, &stderr)
	c.nodeBootstrap = func(_ io.Writer, opts tui.BootstrapOptions) error {
		got = opts
		return nil
	}

	code := c.run([]string{
		"node", "bootstrap",
		"--persist-connection-profile",
		"--connection-profile-out", "/tmp/connection-profile.yaml",
	})
	if code != 0 {
		t.Fatalf("run(node bootstrap) returned %d, want 0; stderr=%s", code, stderr.String())
	}
	if !got.PersistConnectionProfile || got.ConnectionProfilePath != "/tmp/connection-profile.yaml" {
		t.Fatalf("unexpected bootstrap options: %#v", got)
	}
}

func TestCLIPassesNetworkStartInstance(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var got tui.NetworkStartOptions
	c := newStubCLI(&stdout, &stderr)
	c.networkStart = func(_ io.Writer, opts tui.NetworkStartOptions) error {
		got = opts
		return nil
	}

	code := c.run([]string{"network", "start", "--instance", "alpha"})
	if code != 0 {
		t.Fatalf("run(network start) returned %d, want 0; stderr=%s", code, stderr.String())
	}
	if got.Instance != "alpha" {
		t.Fatalf("network start options = %#v, want instance alpha", got)
	}
}

func TestCLIRequiresNetworkStopInstance(t *testing.T) {
	var stdout, stderr bytes.Buffer
	c := newStubCLI(&stdout, &stderr)

	if code := c.run([]string{"network", "stop"}); code != 2 {
		t.Fatalf("run(network stop) returned %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "network stop requires --instance") {
		t.Fatalf("stderr missing required instance error:\n%s", stderr.String())
	}
}

func TestCLIPassesNetworkStopInstance(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var got tui.NetworkStopOptions
	c := newStubCLI(&stdout, &stderr)
	c.networkStop = func(_ io.Writer, opts tui.NetworkStopOptions) error {
		got = opts
		return nil
	}

	code := c.run([]string{"network", "stop", "--instance", "alpha"})
	if code != 0 {
		t.Fatalf("run(network stop) returned %d, want 0; stderr=%s", code, stderr.String())
	}
	if got.Instance != "alpha" {
		t.Fatalf("network stop options = %#v, want instance alpha", got)
	}
}

func TestCLIRoutesLeafCommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "tui command", args: []string{"tui"}, want: "tui"},
		{name: "status command", args: []string{"status"}, want: "status"},
		{name: "stop command", args: []string{"stop"}, want: "stop"},
		{name: "demo start", args: []string{"demo", "start"}, want: "demo-start"},
		{name: "demo stop", args: []string{"demo", "stop"}, want: "demo-stop"},
		{name: "node start", args: []string{"node", "start"}, want: "node-start"},
		{name: "node stop", args: []string{"node", "stop"}, want: "node-stop"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			called := ""
			c := newStubCLI(&stdout, &stderr)
			c.runTUI = func() error {
				called = "tui"
				return nil
			}
			c.showStatus = func(io.Writer) error {
				called = "status"
				return nil
			}
			c.stopAll = func(io.Writer) error {
				called = "stop"
				return nil
			}
			c.demoStart = func(io.Writer) error {
				called = "demo-start"
				return nil
			}
			c.demoStop = func(io.Writer) error {
				called = "demo-stop"
				return nil
			}
			c.nodeStart = func(io.Writer) error {
				called = "node-start"
				return nil
			}
			c.nodeStop = func(io.Writer) error {
				called = "node-stop"
				return nil
			}

			if code := c.run(tc.args); code != 0 {
				t.Fatalf("run(%v) returned %d, want 0; stderr=%s", tc.args, code, stderr.String())
			}
			if called != tc.want {
				t.Fatalf("run(%v) called %q, want %q", tc.args, called, tc.want)
			}
		})
	}
}

func TestCLIShowsNodeSetupHelpWithExtendedFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	c := newStubCLI(&stdout, &stderr)

	if code := c.run([]string{"node", "setup", "--help"}); code != 0 {
		t.Fatalf("run(node setup --help) returned %d, want 0", code)
	}

	text := stdout.String() + stderr.String()
	for _, want := range []string{
		"--domain",
		"--gateway-user",
		"--ca-admin-user",
		"--ca-admin-pass",
		"--env-out",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("node setup help missing %q:\n%s", want, text)
		}
	}
}

func TestCLIShowsNetworkHelpWithInstanceFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	c := newStubCLI(&stdout, &stderr)

	if code := c.run([]string{"network", "start", "--help"}); code != 0 {
		t.Fatalf("run(network start --help) returned %d, want 0", code)
	}

	text := stdout.String() + stderr.String()
	if !strings.Contains(text, "--instance") {
		t.Fatalf("network start help missing --instance:\n%s", text)
	}
}

func TestCLIRejectsUnknownSubcommands(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "unknown demo command", args: []string{"demo", "wat"}, wantErr: `unknown demo command "wat"`},
		{name: "unknown node command", args: []string{"node", "wat"}, wantErr: `unknown node command "wat"`},
		{name: "unknown network command", args: []string{"network", "wat"}, wantErr: `unknown network command "wat"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			c := newStubCLI(&stdout, &stderr)

			if code := c.run(tc.args); code != 2 {
				t.Fatalf("run(%v) returned %d, want 2", tc.args, code)
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Fatalf("stderr missing %q:\n%s", tc.wantErr, stderr.String())
			}
		})
	}
}

func TestCLIRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	c := newStubCLI(&stdout, &stderr)

	if code := c.run([]string{"wat"}); code != 2 {
		t.Fatalf("run(wat) returned %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "wat"`) {
		t.Fatalf("stderr missing unknown command message:\n%s", stderr.String())
	}
}

func newStubCLI(stdout, stderr *bytes.Buffer) cli {
	return cli{
		stdout:        stdout,
		stderr:        stderr,
		runTUI:        func() error { return nil },
		showStatus:    func(io.Writer) error { return nil },
		demoStart:     func(io.Writer) error { return nil },
		demoStop:      func(io.Writer) error { return nil },
		nodeBootstrap: func(io.Writer, tui.BootstrapOptions) error { return nil },
		nodeStart:     func(io.Writer) error { return nil },
		nodeStop:      func(io.Writer) error { return nil },
		networkStart:  func(io.Writer, tui.NetworkStartOptions) error { return nil },
		networkStop:   func(io.Writer, tui.NetworkStopOptions) error { return nil },
		stopAll:       func(io.Writer) error { return nil },
		configureNode: func(values tui.SetupValues) (tui.ProjectState, error) {
			return tui.ProjectState{FedDir: "/repo/federation", OrgName: values.OrgName, GatewayPort: "8080"}, nil
		},
	}
}
