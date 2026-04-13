package tui

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type NetworkStartOptions struct {
	Instance string
}

type NetworkStopOptions struct {
	Instance string
}

func StartNetwork(out io.Writer, opts NetworkStartOptions) error {
	state := DetectState()
	if !state.HasDocker {
		return fmt.Errorf("docker not found")
	}
	if !state.ConfigConfigured {
		return missingConfigError(state)
	}
	return runTaskList(out, "Start Founding Network", startNetworkTasks(state, opts), state)
}

func StopNetwork(out io.Writer, opts NetworkStopOptions) error {
	state := DetectState()
	if !state.HasDocker {
		return fmt.Errorf("docker not found")
	}
	if _, err := foundingRunPaths(state.FedDir, opts.Instance); err != nil {
		return err
	}
	return runTaskList(out, "Stop Founding Network", stopNetworkTasks(state, opts), state)
}

func startNetworkTasks(st ProjectState, opts NetworkStartOptions) []task {
	var run foundingRun
	return []task{
		{
			label: "Validate founding configuration",
			fn: func(s ProjectState) (string, error) {
				if err := s.Config.Founding.Validate(); err != nil {
					return "", fmt.Errorf("founding configuration is invalid: %w", err)
				}
				return fmt.Sprintf("Founders: %d orgs\nOrderers: %d\nChannel: %s",
					len(s.Config.Founding.withDefaults().Organizations),
					len(s.Config.Founding.withDefaults().Orderers),
					s.Config.withDefaults().Network.ChannelName,
				), nil
			},
		},
		{
			label: "Generate isolated network files",
			fn: func(s ProjectState) (string, error) {
				var err error
				run, err = generateFoundingArtifacts(s.FedDir, s.Config, opts.Instance)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("Instance: %s\nRun directory: %s\nCompose file: %s\nConfigtx: %s\nCrypto config: %s",
					run.Instance,
					displayPath(s.RepoRoot, run.RunDir),
					displayPath(s.RepoRoot, run.ComposePath),
					displayPath(s.RepoRoot, run.ConfigTxPath),
					displayPath(s.RepoRoot, run.CryptoConfigPath),
				), nil
			},
		},
		{
			label: "Bootstrap crypto and channel artifacts",
			fn: func(s ProjectState) (string, error) {
				return shellRunWithEnv(s.FedDir, foundingBootstrapEnv(run), "bash", "./scripts/bootstrap-network.sh")
			},
		},
		{
			label: "Start founding network containers",
			fn: func(s ProjectState) (string, error) {
				return shellRun(s.FedDir, "docker", "compose",
					"-p", run.ProjectName,
					"-f", run.ComposePath,
					"up", "-d", "--build")
			},
		},
		{
			label: "Check container status",
			fn: func(s ProjectState) (string, error) {
				out, err := shellRun(s.FedDir, "docker", "compose",
					"-p", run.ProjectName,
					"-f", run.ComposePath,
					"ps")
				if err != nil {
					return out, err
				}
				return out + "\nRun env: " + displayPath(s.RepoRoot, run.RunEnvPath) + "\n", nil
			},
		},
	}
}

func stopNetworkTasks(st ProjectState, opts NetworkStopOptions) []task {
	run, _ := foundingRunPaths(st.FedDir, opts.Instance)
	return []task{
		{
			label: "Stop founding network containers",
			fn: func(s ProjectState) (string, error) {
				if _, err := os.Stat(run.ComposePath); err != nil {
					return "", fmt.Errorf("founding run %q not found at %s", run.Instance, displayPath(s.RepoRoot, run.ComposePath))
				}
				out, err := shellRun(s.FedDir, "docker", "compose",
					"-p", run.ProjectName,
					"-f", run.ComposePath,
					"down")
				if err != nil {
					return out, err
				}
				return out + "\nRemoved run: " + displayPath(s.RepoRoot, run.RunDir) + "\n", nil
			},
		},
	}
}

func foundingBootstrapEnv(run foundingRun) map[string]string {
	orgMSPs := make([]string, 0, len(run.Organizations))
	for _, org := range run.Organizations {
		orgMSPs = append(orgMSPs, org.MSPID)
	}
	return map[string]string{
		"NETWORK_DIR":          run.RunDir,
		"CONFIG_DIR":           run.ConfigDir,
		"CRYPTO_DIR":           run.CryptoDir,
		"ARTIFACTS_DIR":        run.ArtifactsDir,
		"COMPOSE_FILE":         run.ComposePath,
		"COMPOSE_PROJECT_NAME": run.ProjectName,
		"CHANNEL_NAME":         run.ChannelName,
		"FOUNDING_ORG_MSPS":    strings.Join(orgMSPs, ","),
	}
}
