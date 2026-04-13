package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAndReadNodeConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, nodeConfigFileName)

	cfg := defaultNodeConfig()
	cfg.Organization.Name = "city-porto-alegre"
	cfg.Organization.DisplayName = "City of Porto Alegre"
	cfg.Organization.ScopePrefix = "GOV:CITY_PORTO_ALEGRE"
	cfg.Gateway.Port = 8081

	if err := writeNodeConfig(path, cfg); err != nil {
		t.Fatalf("writeNodeConfig() error = %v", err)
	}

	got, err := readNodeConfig(path)
	if err != nil {
		t.Fatalf("readNodeConfig() error = %v", err)
	}

	if got.Organization.Name != cfg.Organization.Name {
		t.Fatalf("Organization.Name = %q, want %q", got.Organization.Name, cfg.Organization.Name)
	}
	if got.MSPID() != "CityPortoAlegreMSP" {
		t.Fatalf("MSPID() = %q, want %q", got.MSPID(), "CityPortoAlegreMSP")
	}
	if got.Domain() != "city-porto-alegre.od.example.com" {
		t.Fatalf("Domain() = %q, want %q", got.Domain(), "city-porto-alegre.od.example.com")
	}
	if got.GatewayPort() != "8081" {
		t.Fatalf("GatewayPort() = %q, want %q", got.GatewayPort(), "8081")
	}
}

func TestLoadNodeConfigFallsBackToLegacyEnv(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, legacyEnvFileName)
	if err := os.WriteFile(envPath, []byte(strings.Join([]string{
		"ORG_NAME=city-porto-alegre",
		`ORG_DISPLAY="City of Porto Alegre"`,
		"SCOPE_PREFIX=GOV:CITY_PORTO_ALEGRE",
		"GATEWAY_PORT=8082",
		"",
	}, "\n")), 0600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	cfg, path, source, err := loadNodeConfig(dir)
	if err != nil {
		t.Fatalf("loadNodeConfig() error = %v", err)
	}

	if source != "legacy .env" {
		t.Fatalf("source = %q, want %q", source, "legacy .env")
	}
	if path != envPath {
		t.Fatalf("path = %q, want %q", path, envPath)
	}
	if cfg.GatewayPort() != "8082" {
		t.Fatalf("GatewayPort() = %q, want %q", cfg.GatewayPort(), "8082")
	}
}

func TestConnectionProfileYAMLUsesDerivedNames(t *testing.T) {
	cfg := defaultNodeConfig()
	cfg.Organization.Name = "shyylol"
	cfg.Organization.DisplayName = "OpenCorp"

	data, err := cfg.ConnectionProfileYAML()
	if err != nil {
		t.Fatalf("ConnectionProfileYAML() error = %v", err)
	}

	text := string(data)
	for _, want := range []string{
		"peer0.shyylol.od.example.com",
		"ca.shyylol.od.example.com",
		"ShyylolMSP",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("connection profile missing %q:\n%s", want, text)
		}
	}
}

func TestWriteLegacyEnvFromConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, legacyEnvFileName)

	cfg := defaultNodeConfig()
	cfg.Organization.Name = "my-org"
	cfg.Organization.DisplayName = "My Org"
	cfg.Organization.ScopePrefix = "ORG:MY_ORG"

	if err := writeLegacyEnv(path, cfg); err != nil {
		t.Fatalf("writeLegacyEnv() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(.env) error = %v", err)
	}

	text := string(data)
	if !strings.Contains(text, `ORG_DISPLAY="My Org"`) {
		t.Fatalf("legacy env missing quoted display name:\n%s", text)
	}
	if !strings.Contains(text, "ORG_MSP_ID=MyOrgMSP") {
		t.Fatalf("legacy env missing MSP ID:\n%s", text)
	}
}

func TestComposeEnvLeavesCouchDBUnsetWhenDisabled(t *testing.T) {
	cfg := defaultNodeConfig()
	cfg.Organization.Name = "my-org"

	env := cfg.ComposeEnv()
	if got := env["USE_COUCHDB"]; got != "" {
		t.Fatalf("USE_COUCHDB = %q, want empty string when disabled", got)
	}

	cfg.CouchDB.Enabled = true
	env = cfg.ComposeEnv()
	if got := env["USE_COUCHDB"]; got != "true" {
		t.Fatalf("USE_COUCHDB = %q, want %q when enabled", got, "true")
	}
}

func TestFoundingConfigRejectsDuplicateOrganizations(t *testing.T) {
	cfg := defaultFoundingConfig()
	cfg.Organizations = append(cfg.Organizations, cfg.Organizations[0])

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want duplicate organization error")
	}
}

func TestGenerateFoundingArtifactsCreatesIsolatedRun(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultNodeConfig()

	run, err := generateFoundingArtifacts(dir, cfg, "alpha")
	if err != nil {
		t.Fatalf("generateFoundingArtifacts() error = %v", err)
	}

	if got, want := filepath.Base(run.RunDir), "alpha"; got != want {
		t.Fatalf("run dir base = %q, want %q", got, want)
	}
	if got, want := run.ProjectName, "odf-alpha"; got != want {
		t.Fatalf("project name = %q, want %q", got, want)
	}

	composeData, err := os.ReadFile(run.ComposePath)
	if err != nil {
		t.Fatalf("ReadFile(compose) error = %v", err)
	}
	compose := string(composeData)
	for _, want := range []string{
		"context: ../..",
		"CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE: odf-alpha_od-network",
		"gateway.opendemocracy:",
		"peer1.opendemocracy.od.example.com:",
	} {
		if !strings.Contains(compose, want) {
			t.Fatalf("compose missing %q:\n%s", want, compose)
		}
	}
	if strings.Contains(compose, "container_name:") {
		t.Fatalf("compose should not pin container_name values:\n%s", compose)
	}

	configtxData, err := os.ReadFile(run.ConfigTxPath)
	if err != nil {
		t.Fatalf("ReadFile(configtx) error = %v", err)
	}
	configtx := string(configtxData)
	for _, want := range []string{
		"Consortiums:",
		"FederationConsortium:",
		"OrdererEndpoints:",
		"peer0.examplegov.od.example.com",
	} {
		if !strings.Contains(configtx, want) {
			t.Fatalf("configtx missing %q:\n%s", want, configtx)
		}
	}

	runEnvData, err := os.ReadFile(run.RunEnvPath)
	if err != nil {
		t.Fatalf("ReadFile(run env) error = %v", err)
	}
	runEnv := string(runEnvData)
	for _, want := range []string{
		"INSTANCE=alpha",
		"CONFIG_DIR=" + filepath.Join(run.RunDir, "config"),
		"CRYPTO_DIR=" + filepath.Join(run.RunDir, "crypto"),
		"ARTIFACTS_DIR=" + filepath.Join(run.RunDir, "channel-artifacts"),
		"COMPOSE_PROJECT_NAME=odf-alpha",
		"CHANNEL_NAME=governance",
		"ORDERER_ADDR=orderer1.od.example.com:7050",
	} {
		if !strings.Contains(runEnv, want) {
			t.Fatalf("run env missing %q:\n%s", want, runEnv)
		}
	}
}
