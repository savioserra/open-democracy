package tui

import (
	"fmt"
	"os"
	"path/filepath"
)

// --- Quick Start (demo) ----------------------------------------------------

func demoTasks(st ProjectState) []task {
	return []task{
		{
			label: "Build and start demo containers",
			fn: func(s ProjectState) (string, error) {
				return shellRun(s.RepoRoot, "docker", "compose", "up", "--build", "-d")
			},
		},
		{
			label: "Wait for health check",
			fn: func(s ProjectState) (string, error) {
				out, err := shellRun(s.RepoRoot, "docker", "compose", "ps")
				if err != nil {
					return out, err
				}
				return out + "\nDashboard ready at http://localhost:" + defaultGatewayPort + "/\n", nil
			},
		},
	}
}

// --- Bootstrap node --------------------------------------------------------

func bootstrapTasks(st ProjectState, opts BootstrapOptions) []task {
	tasks := []task{
		{
			label: "Create directory structure",
			fn: func(s ProjectState) (string, error) {
				if err := ensureNodeCryptoDirs(s.FedDir); err != nil {
					return "", err
				}
				return "Created directory structure under federation/crypto/", nil
			},
		},
		{
			label: "Generate CA certificate",
			fn: func(s ProjectState) (string, error) {
				return generateCACertificate(s)
			},
		},
		{
			label: "Generate CA TLS certificate",
			fn: func(s ProjectState) (string, error) {
				return generateCATLSCertificate(s)
			},
		},
		{
			label: "Generate organization admin MSP",
			fn: func(s ProjectState) (string, error) {
				return generateAdminMSP(s)
			},
		},
		{
			label: "Generate peer MSP certificate",
			fn: func(s ProjectState) (string, error) {
				return generatePeerMSP(s)
			},
		},
		{
			label: "Generate peer TLS key and certificate",
			fn: func(s ProjectState) (string, error) {
				return generatePeerTLSCertificate(s)
			},
		},
	}

	if opts.PersistConnectionProfile {
		outPath := opts.ConnectionProfilePath
		if outPath == "" {
			outPath = filepath.Join(st.FedDir, connectionProfileFileName)
		}
		tasks = append(tasks, task{
			label: "Export connection profile",
			fn: func(s ProjectState) (string, error) {
				data, err := s.Config.ConnectionProfileYAML()
				if err != nil {
					return "", err
				}
				if err := os.WriteFile(outPath, data, 0600); err != nil {
					return "", err
				}
				return "Connection profile: " + outPath, nil
			},
		})
	}

	return tasks
}

// --- Start federation node -------------------------------------------------

func startNodeTasks(st ProjectState) []task {
	return []task{
		{
			label: "Validate node configuration",
			fn: func(s ProjectState) (string, error) {
				if err := s.Config.Validate(); err != nil {
					return "", fmt.Errorf("node configuration is invalid: %w", err)
				}
				return "Gateway port: " + s.GatewayPort + "\nMSP ID: " + s.MspID + "\nDomain: " + s.Domain, nil
			},
		},
		{
			label: "Start federation node containers",
			fn: func(s ProjectState) (string, error) {
				return shellRunWithEnv(s.FedDir, nodeComposeEnv(s), "docker", "compose",
					"-f", "docker-compose.node.yml",
					"up", "-d", "--build")
			},
		},
		{
			label: "Check container status",
			fn: func(s ProjectState) (string, error) {
				out, err := shellRunWithEnv(s.FedDir, nodeComposeEnv(s), "docker", "compose",
					"-f", "docker-compose.node.yml", "ps")
				if err != nil {
					return out, err
				}
				port, _ := normalizeGatewayPort(s.GatewayPort)
				return out + "\nDashboard: http://localhost:" + port + "/\n", nil
			},
		},
	}
}

// --- Stop services ---------------------------------------------------------

func stopTasks(st ProjectState) []task {
	return append(stopDemoTasks(st), stopNodeTasks(st)...)
}

func stopDemoTasks(st ProjectState) []task {
	return []task{
		{
			label: "Stop demo containers",
			fn: func(s ProjectState) (string, error) {
				out, _ := shellRun(s.RepoRoot, "docker", "compose", "down")
				return out, nil // don't fail if nothing running
			},
		},
	}
}

func stopNodeTasks(st ProjectState) []task {
	return []task{
		{
			label: "Stop federation node containers",
			fn: func(s ProjectState) (string, error) {
				compose := filepath.Join(s.FedDir, "docker-compose.node.yml")
				if _, err := os.Stat(compose); err != nil {
					return "No federation compose file, skipping.", nil
				}
				out, _ := shellRunWithEnv(s.FedDir, nodeComposeEnv(s), "docker", "compose",
					"-f", "docker-compose.node.yml", "down")
				return out, nil
			},
		},
	}
}

func nodeComposeEnv(state ProjectState) map[string]string {
	if state.ConfigConfigured {
		return state.Config.ComposeEnv()
	}
	return nil
}
