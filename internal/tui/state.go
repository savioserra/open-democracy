package tui

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ProjectState holds detected state of the project for the TUI.
type ProjectState struct {
	RepoRoot        string
	FedDir          string
	EnvConfigured   bool
	CryptoGenerated bool
	HasDocker       bool
	HasOpenSSL      bool
	OrgName         string
	OrgDisplay      string
	ScopePrefix     string
	GatewayPort     string
	MspID           string
	Domain          string
	Containers      []Container
	Participants    []ParticipantEntry
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
		GatewayPort: "8080",
		HasDocker:   commandExists("docker"),
		HasOpenSSL:  commandExists("openssl"),
	}

	envPath := filepath.Join(fedDir, ".env")
	if env, err := readEnv(envPath); err == nil && env["ORG_NAME"] != "" {
		st.EnvConfigured = true
		st.OrgName = env["ORG_NAME"]
		st.OrgDisplay = env["ORG_DISPLAY"]
		st.ScopePrefix = env["SCOPE_PREFIX"]
		if p := env["GATEWAY_PORT"]; p != "" {
			st.GatewayPort = p
		}
		st.MspID = env["ORG_MSP_ID"]
		st.Domain = env["ORG_DOMAIN"]
	}

	if _, err := os.Stat(filepath.Join(fedDir, "crypto", "ca", "ca-cert.pem")); err == nil {
		st.CryptoGenerated = true
	}

	st.Containers = detectContainers(root)
	st.Participants = readParticipantsCSV(filepath.Join(fedDir, "participants.csv"))
	return st
}

// RunningCount returns the number of running containers.
func (s ProjectState) RunningCount() int {
	n := 0
	for _, c := range s.Containers {
		low := strings.ToLower(c.State)
		if strings.Contains(low, "running") || strings.Contains(low, "up") {
			n++
		}
	}
	return n
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

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
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

func writeEnv(path string, vals map[string]string) error {
	// Try to read existing template to preserve comments.
	tmplPath := filepath.Join(filepath.Dir(path), "config", "org-template.env")
	tmpl, err := os.ReadFile(tmplPath)
	if err != nil {
		// No template — write minimal file.
		var sb strings.Builder
		for k, v := range vals {
			sb.WriteString(k + "=" + v + "\n")
		}
		return os.WriteFile(path, []byte(sb.String()), 0644)
	}

	lines := strings.Split(string(tmpl), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		k, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if v, found := vals[k]; found {
			lines[i] = k + "=" + v
		}
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

func detectContainers(repoRoot string) []Container {
	cmd := exec.Command("docker", "compose", "ps", "--format", "{{.Name}}\t{{.State}}\t{{.Ports}}")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
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
