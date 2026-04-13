package tui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// SetupValues holds the configurable fields for federation/democracy.toml.
type SetupValues struct {
	OrgName            string
	OrgDisplay         string
	ScopePrefix        string
	Domain             string
	GatewayPort        string
	GatewayDefaultUser string
	CAAdminUser        string
	CAAdminPass        string
	PersistLegacyEnv   bool
	LegacyEnvPath      string
}

// BootstrapOptions controls optional bootstrap exports.
type BootstrapOptions struct {
	PersistConnectionProfile bool
	ConnectionProfilePath    string
}

// Run launches the interactive odctl TUI.
func Run() error {
	p := tea.NewProgram(New(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ConfigureNode writes federation/democracy.toml using the current project state plus the
// provided overrides.
func ConfigureNode(values SetupValues) (ProjectState, error) {
	return saveNodeConfig(DetectState(), values)
}

// QuickStart launches the demo dashboard stack from the repository root.
func QuickStart(out io.Writer) error {
	state := DetectState()
	if !state.HasDocker {
		return fmt.Errorf("docker not found")
	}
	return runTaskList(out, "Quick Start - Demo Dashboard", demoTasks(state), state)
}

// BootstrapNode generates the crypto material needed for a federation node.
func BootstrapNode(out io.Writer, opts BootstrapOptions) error {
	state := DetectState()
	if !state.ConfigConfigured {
		return missingConfigError(state)
	}
	if !state.HasOpenSSL {
		return fmt.Errorf("openssl not found")
	}
	return runTaskList(out, "Bootstrap Node - Generating Certificates", bootstrapTasks(state, opts), state)
}

// StartNode starts the federation node containers.
func StartNode(out io.Writer) error {
	state := DetectState()
	if !state.HasDocker {
		return fmt.Errorf("docker not found")
	}
	if !state.ConfigConfigured {
		return missingConfigError(state)
	}
	return runTaskList(out, "Start Federation Node", startNodeTasks(state), state)
}

// StopDemo stops the root demo dashboard stack.
func StopDemo(out io.Writer) error {
	state := DetectState()
	if !state.HasDocker {
		return fmt.Errorf("docker not found")
	}
	return runTaskList(out, "Stop Demo Services", stopDemoTasks(state), state)
}

// StopNode stops the federation node containers.
func StopNode(out io.Writer) error {
	state := DetectState()
	if !state.HasDocker {
		return fmt.Errorf("docker not found")
	}
	return runTaskList(out, "Stop Federation Node", stopNodeTasks(state), state)
}

// StopAll stops both demo and federation node services.
func StopAll(out io.Writer) error {
	state := DetectState()
	if !state.HasDocker {
		return fmt.Errorf("docker not found")
	}
	return runTaskList(out, "Stop Services", stopTasks(state), state)
}

// Status prints a concise summary of the current project state.
func Status(out io.Writer) error {
	state := DetectState()
	return writeStatus(out, state)
}

// ExportLegacyEnv writes a legacy .env file from democracy.toml.
func ExportLegacyEnv(out io.Writer, outPath string) error {
	state := DetectState()
	if !state.ConfigConfigured {
		return missingConfigError(state)
	}
	if outPath == "" {
		outPath = filepath.Join(state.FedDir, legacyEnvFileName)
	}
	if err := writeLegacyEnv(outPath, state.Config); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "Legacy env exported to %s\n", outPath)
	return err
}

// ExportConnectionProfile writes a connection profile derived from democracy.toml.
func ExportConnectionProfile(out io.Writer, outPath string) error {
	state := DetectState()
	if !state.ConfigConfigured {
		return missingConfigError(state)
	}
	if outPath == "" {
		outPath = filepath.Join(state.FedDir, connectionProfileFileName)
	}
	data, err := state.Config.ConnectionProfileYAML()
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Connection profile exported to %s\n", outPath)
	return err
}

func saveNodeConfig(state ProjectState, values SetupValues) (ProjectState, error) {
	cfg := defaultNodeConfig()
	if state.ConfigConfigured {
		cfg = state.Config
	}
	cfg = cfg.withDefaults()

	name := firstNonEmpty(values.OrgName, cfg.Organization.Name, state.OrgName)
	name = strings.TrimSpace(name)
	if name == "" {
		return state, fmt.Errorf("organization name is required")
	}

	display := strings.TrimSpace(firstNonEmpty(values.OrgDisplay, cfg.Organization.DisplayName, state.OrgDisplay))
	scope := strings.TrimSpace(firstNonEmpty(values.ScopePrefix, cfg.Organization.ScopePrefix, state.ScopePrefix))
	domain := strings.TrimSpace(firstNonEmpty(values.Domain, cfg.Organization.Domain))
	portInput := firstNonEmpty(values.GatewayPort, strconv.Itoa(cfg.Gateway.Port), state.GatewayPort)
	port, err := normalizeGatewayPort(portInput)
	if err != nil {
		return state, fmt.Errorf("gateway port %q is invalid: %w", portInput, err)
	}
	gatewayDefaultUser := strings.TrimSpace(firstNonEmpty(values.GatewayDefaultUser, cfg.Gateway.DefaultUser))
	caAdminUser := strings.TrimSpace(firstNonEmpty(values.CAAdminUser, cfg.CA.AdminUser))
	caAdminPass := strings.TrimSpace(firstNonEmpty(values.CAAdminPass, cfg.CA.AdminPass))

	cfg.Organization.Name = name
	cfg.Organization.DisplayName = display
	cfg.Organization.ScopePrefix = scope
	cfg.Organization.Domain = domain
	cfg.Gateway.Port, _ = strconv.Atoi(port)
	cfg.Gateway.DefaultUser = gatewayDefaultUser
	cfg.CA.AdminUser = caAdminUser
	cfg.CA.AdminPass = caAdminPass

	configPath := filepath.Join(state.FedDir, nodeConfigFileName)
	if err := writeNodeConfig(configPath, cfg); err != nil {
		return state, err
	}

	if values.PersistLegacyEnv || strings.TrimSpace(values.LegacyEnvPath) != "" {
		envPath := values.LegacyEnvPath
		if envPath == "" {
			envPath = filepath.Join(state.FedDir, legacyEnvFileName)
		}
		if err := writeLegacyEnv(envPath, cfg); err != nil {
			return state, err
		}
	}

	return DetectState(), nil
}

func runTaskList(out io.Writer, title string, tasks []task, state ProjectState) error {
	if out == nil {
		out = io.Discard
	}

	if _, err := fmt.Fprintln(out, title); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}

	for _, t := range tasks {
		if _, err := fmt.Fprintf(out, "==> %s\n", t.label); err != nil {
			return err
		}

		result, err := t.fn(state)
		result = strings.TrimRight(result, "\n")
		if result == "" {
			if _, writeErr := fmt.Fprintln(out, "ok"); writeErr != nil {
				return writeErr
			}
		} else {
			if _, writeErr := fmt.Fprintln(out, result); writeErr != nil {
				return writeErr
			}
		}
		if _, writeErr := fmt.Fprintln(out); writeErr != nil {
			return writeErr
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func writeStatus(out io.Writer, state ProjectState) error {
	if out == nil {
		out = io.Discard
	}

	var sb strings.Builder
	sb.WriteString("Open Democracy status\n\n")
	sb.WriteString(fmt.Sprintf("Docker: %s\n", availabilityLabel(state.HasDocker)))
	sb.WriteString(fmt.Sprintf("OpenSSL: %s\n", availabilityLabel(state.HasOpenSSL)))
	if state.ConfigError != "" {
		sb.WriteString("Configuration: invalid\n")
		sb.WriteString(fmt.Sprintf("Config file: %s\n", displayPath(state.RepoRoot, state.ConfigPath)))
		sb.WriteString(fmt.Sprintf("Config error: %s\n", state.ConfigError))
	} else if state.ConfigConfigured {
		sb.WriteString(fmt.Sprintf("Configuration: %s\n", state.ConfigSource))
		sb.WriteString(fmt.Sprintf("Config file: %s\n", displayPath(state.RepoRoot, state.ConfigPath)))
		sb.WriteString(fmt.Sprintf("Organization: %s\n", state.OrgName))
		if state.OrgDisplay != "" {
			sb.WriteString(fmt.Sprintf("Display name: %s\n", state.OrgDisplay))
		}
		if state.ScopePrefix != "" {
			sb.WriteString(fmt.Sprintf("Scope prefix: %s\n", state.ScopePrefix))
		}
	} else {
		sb.WriteString("Configuration: not configured\n")
		sb.WriteString(fmt.Sprintf("Config file: %s\n", displayPath(state.RepoRoot, state.ConfigPath)))
	}

	sb.WriteString(fmt.Sprintf("Gateway port: %s\n", gatewayPortLabel(state.GatewayPort)))
	sb.WriteString(fmt.Sprintf("Participants: %d\n\n", len(state.Participants)))

	sb.WriteString(containerSection("Demo stack", state.DemoContainers, defaultGatewayPort))
	sb.WriteString("\n")

	nodePort, err := normalizeGatewayPort(state.GatewayPort)
	if err != nil {
		nodePort = ""
	}
	sb.WriteString(containerSection("Node stack", state.NodeContainers, nodePort))

	_, err = io.WriteString(out, sb.String())
	return err
}

func containerSection(title string, containers []Container, port string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s: %d running / %d detected\n", title, runningCount(containers), len(containers)))
	for _, c := range containers {
		line := fmt.Sprintf("  - %s (%s)", c.Name, c.State)
		if c.Ports != "" {
			line += " " + c.Ports
		}
		sb.WriteString(line + "\n")
	}
	if len(containers) == 0 {
		sb.WriteString("  - none\n")
	}
	if port != "" {
		sb.WriteString(fmt.Sprintf("  URL: http://localhost:%s/\n", port))
	}
	return sb.String()
}

func availabilityLabel(ok bool) string {
	if ok {
		return "available"
	}
	return "missing"
}

func gatewayPortLabel(port string) string {
	value, err := normalizeGatewayPort(port)
	if err != nil {
		return fmt.Sprintf("invalid (%s)", strings.TrimSpace(port))
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func missingConfigError(state ProjectState) error {
	if state.ConfigError != "" {
		return fmt.Errorf("invalid configuration in %s: %s", displayPath(state.RepoRoot, state.ConfigPath), state.ConfigError)
	}
	return fmt.Errorf("missing configuration: run `odctl node setup` to create %s", displayPath(state.RepoRoot, state.ConfigPath))
}

func displayPath(root, path string) string {
	if path == "" {
		return ""
	}
	rel, err := filepath.Rel(root, path)
	if err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return path
}
