package tui

import (
	"os"
	"os/exec"
	"sort"
	"strings"
)

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func shellRun(dir string, name string, args ...string) (string, error) {
	return shellRunWithEnv(dir, nil, name, args...)
}

func shellRunWithEnv(dir string, extra map[string]string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if len(extra) > 0 {
		cmd.Env = mergedEnv(extra)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func commandOutputWithEnv(dir string, extra map[string]string, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if len(extra) > 0 {
		cmd.Env = mergedEnv(extra)
	}
	return cmd.Output()
}

func mergedEnv(extra map[string]string) []string {
	values := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		values[key] = value
	}
	for key, value := range extra {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}
