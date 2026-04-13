package tui

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ProjectState holds detected state of the project for the TUI.
type ProjectState struct {
	RepoRoot         string
	FedDir           string
	ConfigConfigured bool
	ConfigPath       string
	ConfigSource     string
	ConfigError      string
	Config           NodeConfig
	CryptoGenerated  bool
	HasDocker        bool
	HasOpenSSL       bool
	OrgName          string
	OrgDisplay       string
	ScopePrefix      string
	GatewayPort      string
	MspID            string
	Domain           string
	Containers       []Container
	DemoContainers   []Container
	NodeContainers   []Container
	Participants     []ParticipantEntry
}

// Container represents a Docker container.
type Container struct {
	Name  string
	State string
	Ports string
}

// ParticipantEntry from participants.csv.
type ParticipantEntry struct {
	ID      string
	Display string
	Scopes  string
}

// DetectState scans the filesystem and docker for project state.
func DetectState() ProjectState {
	root := findRepoRoot()
	fedDir := filepath.Join(root, "federation")

	st := ProjectState{
		RepoRoot:    root,
		FedDir:      fedDir,
		ConfigPath:  filepath.Join(fedDir, nodeConfigFileName),
		GatewayPort: defaultGatewayPort,
		HasDocker:   commandExists("docker"),
		HasOpenSSL:  commandExists("openssl"),
	}

	cfg, path, source, err := loadNodeConfig(fedDir)
	if err != nil {
		st.ConfigPath = path
		st.ConfigSource = source
		st.ConfigError = err.Error()
	} else if source != "" {
		st.ConfigConfigured = true
		st.ConfigPath = path
		st.ConfigSource = source
		st.Config = cfg
		st.OrgName = strings.TrimSpace(cfg.Organization.Name)
		st.OrgDisplay = strings.TrimSpace(cfg.Organization.DisplayName)
		st.ScopePrefix = strings.TrimSpace(cfg.Organization.ScopePrefix)
		st.GatewayPort = cfg.GatewayPort()
		st.MspID = cfg.MSPID()
		st.Domain = cfg.Domain()
	}

	if _, err := os.Stat(filepath.Join(fedDir, "crypto", "ca", "ca-cert.pem")); err == nil {
		st.CryptoGenerated = true
	}

	st.DemoContainers = detectComposeContainers(root, nil)
	var nodeEnv map[string]string
	if st.ConfigConfigured {
		nodeEnv = st.Config.ComposeEnv()
	}
	st.NodeContainers = detectComposeContainers(fedDir, nodeEnv, "-f", "docker-compose.node.yml")
	st.Containers = append(append([]Container{}, st.DemoContainers...), st.NodeContainers...)
	st.Participants = readParticipantsCSV(filepath.Join(fedDir, "participants.csv"))
	return st
}

// RunningCount returns the number of running containers.
func (s ProjectState) RunningCount() int {
	return runningCount(s.Containers)
}

// DemoRunningCount returns the number of running demo stack containers.
func (s ProjectState) DemoRunningCount() int {
	return runningCount(s.DemoContainers)
}

// NodeRunningCount returns the number of running federation node containers.
func (s ProjectState) NodeRunningCount() int {
	return runningCount(s.NodeContainers)
}

// --- helpers ----------------------------------------------------------------

func findRepoRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	wd, _ := os.Getwd()
	return wd
}

func readEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	env := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		env[strings.TrimSpace(k)] = v
	}
	return env, sc.Err()
}

func runningCount(containers []Container) int {
	n := 0
	for _, c := range containers {
		low := strings.ToLower(c.State)
		if strings.Contains(low, "running") || strings.Contains(low, "up") {
			n++
		}
	}
	return n
}

func detectComposeContainers(dir string, env map[string]string, composeArgs ...string) []Container {
	args := []string{"compose"}
	args = append(args, composeArgs...)
	args = append(args, "ps", "--format", "{{.Name}}\t{{.State}}\t{{.Ports}}")
	out, err := commandOutputWithEnv(dir, env, "docker", args...)
	if err != nil {
		return nil
	}
	var cs []Container
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		c := Container{Name: parts[0]}
		if len(parts) > 1 {
			c.State = parts[1]
		}
		if len(parts) > 2 {
			c.Ports = parts[2]
		}
		cs = append(cs, c)
	}
	return cs
}

func readParticipantsCSV(path string) []ParticipantEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []ParticipantEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		parts := csvSplit(line)
		if len(parts) >= 3 {
			entries = append(entries, ParticipantEntry{
				ID:      parts[0],
				Display: parts[1],
				Scopes:  parts[2],
			})
		}
	}
	return entries
}

// csvSplit handles simple CSV with optional double-quotes.
func csvSplit(line string) []string {
	var fields []string
	var cur strings.Builder
	inQ := false
	for _, r := range line {
		switch {
		case r == '"':
			inQ = !inQ
		case r == ',' && !inQ:
			fields = append(fields, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	fields = append(fields, strings.TrimSpace(cur.String()))
	return fields
}
