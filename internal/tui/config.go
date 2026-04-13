package tui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml"
	"gopkg.in/yaml.v3"
)

const (
	nodeConfigFileName          = "democracy.toml"
	legacyEnvFileName           = ".env"
	connectionProfileFileName   = "connection-profile.yaml"
	defaultPeerPort             = 7051
	defaultCAPort               = 7054
	defaultGatewayPortValue     = 8080
	defaultCouchDBPort          = 5984
	defaultOrdererAddress       = "orderer1.od.example.com:7050"
	defaultSecondaryOrdererAddr = "orderer2.od.example.com:7050"
	defaultChannelName          = "governance"
	defaultChaincodeName        = "bill"
	defaultGatewayUser          = "savio"
	defaultCAAdminUser          = "admin"
	defaultCAAdminPass          = "adminpw"
	defaultCouchDBUser          = "admin"
	defaultCouchDBPass          = "adminpw"
	defaultFoundingBaseDomain   = "od.example.com"
	defaultFoundingInstance     = "founding"
)

type NodeConfig struct {
	Organization OrganizationConfig `toml:"organization"`
	Network      NetworkConfig      `toml:"network"`
	Peer         PeerConfig         `toml:"peer"`
	CA           CAConfig           `toml:"ca"`
	Gateway      GatewayConfig      `toml:"gateway"`
	CouchDB      CouchDBConfig      `toml:"couchdb"`
	Founding     FoundingConfig     `toml:"founding"`
}

type OrganizationConfig struct {
	Name        string `toml:"name"`
	DisplayName string `toml:"display_name"`
	ScopePrefix string `toml:"scope_prefix"`
	MSPID       string `toml:"msp_id,omitempty"`
	Domain      string `toml:"domain,omitempty"`
}

type NetworkConfig struct {
	OrdererAddresses []string `toml:"orderer_addresses"`
	ChannelName      string   `toml:"channel_name"`
	ChaincodeName    string   `toml:"chaincode_name"`
}

type PeerConfig struct {
	Count int `toml:"count"`
	Port  int `toml:"port"`
}

type CAConfig struct {
	AdminUser string `toml:"admin_user"`
	AdminPass string `toml:"admin_pass"`
	Port      int    `toml:"port"`
}

type GatewayConfig struct {
	Port        int    `toml:"port"`
	DefaultUser string `toml:"default_user"`
}

type CouchDBConfig struct {
	Enabled  bool   `toml:"enabled"`
	Port     int    `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
}

func defaultNodeConfig() NodeConfig {
	return NodeConfig{
		Network: NetworkConfig{
			OrdererAddresses: []string{defaultOrdererAddress, defaultSecondaryOrdererAddr},
			ChannelName:      defaultChannelName,
			ChaincodeName:    defaultChaincodeName,
		},
		Peer: PeerConfig{
			Count: 1,
			Port:  defaultPeerPort,
		},
		CA: CAConfig{
			AdminUser: defaultCAAdminUser,
			AdminPass: defaultCAAdminPass,
			Port:      defaultCAPort,
		},
		Gateway: GatewayConfig{
			Port:        defaultGatewayPortValue,
			DefaultUser: defaultGatewayUser,
		},
		CouchDB: CouchDBConfig{
			Enabled:  false,
			Port:     defaultCouchDBPort,
			User:     defaultCouchDBUser,
			Password: defaultCouchDBPass,
		},
		Founding: defaultFoundingConfig(),
	}
}

func (cfg NodeConfig) withDefaults() NodeConfig {
	defaults := defaultNodeConfig()

	if len(cfg.Network.OrdererAddresses) == 0 {
		cfg.Network.OrdererAddresses = append([]string(nil), defaults.Network.OrdererAddresses...)
	}
	if strings.TrimSpace(cfg.Network.ChannelName) == "" {
		cfg.Network.ChannelName = defaults.Network.ChannelName
	}
	if strings.TrimSpace(cfg.Network.ChaincodeName) == "" {
		cfg.Network.ChaincodeName = defaults.Network.ChaincodeName
	}
	if cfg.Peer.Count == 0 {
		cfg.Peer.Count = defaults.Peer.Count
	}
	if cfg.Peer.Port == 0 {
		cfg.Peer.Port = defaults.Peer.Port
	}
	if strings.TrimSpace(cfg.CA.AdminUser) == "" {
		cfg.CA.AdminUser = defaults.CA.AdminUser
	}
	if strings.TrimSpace(cfg.CA.AdminPass) == "" {
		cfg.CA.AdminPass = defaults.CA.AdminPass
	}
	if cfg.CA.Port == 0 {
		cfg.CA.Port = defaults.CA.Port
	}
	if cfg.Gateway.Port == 0 {
		cfg.Gateway.Port = defaults.Gateway.Port
	}
	if strings.TrimSpace(cfg.Gateway.DefaultUser) == "" {
		cfg.Gateway.DefaultUser = defaults.Gateway.DefaultUser
	}
	if cfg.CouchDB.Port == 0 {
		cfg.CouchDB.Port = defaults.CouchDB.Port
	}
	if strings.TrimSpace(cfg.CouchDB.User) == "" {
		cfg.CouchDB.User = defaults.CouchDB.User
	}
	if strings.TrimSpace(cfg.CouchDB.Password) == "" {
		cfg.CouchDB.Password = defaults.CouchDB.Password
	}
	cfg.Founding = cfg.Founding.withDefaults()

	return cfg
}

func (cfg NodeConfig) Validate() error {
	cfg = cfg.withDefaults()

	if strings.TrimSpace(cfg.Organization.Name) == "" {
		return fmt.Errorf("organization.name is required")
	}
	if cfg.Peer.Count < 1 {
		return fmt.Errorf("peer.count must be at least 1")
	}

	if _, err := validatedPortString(cfg.Peer.Port, "peer.port"); err != nil {
		return err
	}
	if _, err := validatedPortString(cfg.CA.Port, "ca.port"); err != nil {
		return err
	}
	if _, err := validatedPortString(cfg.Gateway.Port, "gateway.port"); err != nil {
		return err
	}
	if _, err := validatedPortString(cfg.CouchDB.Port, "couchdb.port"); err != nil {
		return err
	}

	for _, address := range cfg.Network.OrdererAddresses {
		if strings.TrimSpace(address) == "" {
			return fmt.Errorf("network.orderer_addresses must not contain empty entries")
		}
	}

	return nil
}

func (cfg NodeConfig) MSPID() string {
	if override := strings.TrimSpace(cfg.Organization.MSPID); override != "" {
		return override
	}
	return toPascalCase(cfg.Organization.Name) + "MSP"
}

func (cfg NodeConfig) Domain() string {
	if override := strings.TrimSpace(cfg.Organization.Domain); override != "" {
		return override
	}
	return strings.ReplaceAll(strings.TrimSpace(cfg.Organization.Name), " ", "") + ".od.example.com"
}

func (cfg NodeConfig) GatewayPort() string {
	cfg = cfg.withDefaults()
	return strconv.Itoa(cfg.Gateway.Port)
}

func (cfg NodeConfig) ComposeEnv() map[string]string {
	cfg = cfg.withDefaults()
	useCouchDB := ""
	if cfg.CouchDB.Enabled {
		useCouchDB = "true"
	}
	return map[string]string{
		"ORG_NAME":             strings.TrimSpace(cfg.Organization.Name),
		"ORG_DISPLAY":          strings.TrimSpace(cfg.Organization.DisplayName),
		"ORG_MSP_ID":           cfg.MSPID(),
		"ORG_DOMAIN":           cfg.Domain(),
		"SCOPE_PREFIX":         strings.TrimSpace(cfg.Organization.ScopePrefix),
		"ORDERER_ADDRESSES":    strings.Join(cfg.Network.OrdererAddresses, ","),
		"CHANNEL_NAME":         strings.TrimSpace(cfg.Network.ChannelName),
		"CHAINCODE_NAME":       strings.TrimSpace(cfg.Network.ChaincodeName),
		"PEER_COUNT":           strconv.Itoa(cfg.Peer.Count),
		"PEER_PORT":            strconv.Itoa(cfg.Peer.Port),
		"CA_ADMIN_USER":        strings.TrimSpace(cfg.CA.AdminUser),
		"CA_ADMIN_PASS":        cfg.CA.AdminPass,
		"CA_PORT":              strconv.Itoa(cfg.CA.Port),
		"GATEWAY_PORT":         strconv.Itoa(cfg.Gateway.Port),
		"GATEWAY_DEFAULT_USER": strings.TrimSpace(cfg.Gateway.DefaultUser),
		"USE_COUCHDB":          useCouchDB,
		"COUCHDB_PORT":         strconv.Itoa(cfg.CouchDB.Port),
		"COUCHDB_USER":         strings.TrimSpace(cfg.CouchDB.User),
		"COUCHDB_PASS":         cfg.CouchDB.Password,
	}
}

func (cfg NodeConfig) ConnectionProfileYAML() ([]byte, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ordererNames := make([]string, 0, len(cfg.Network.OrdererAddresses))
	orderers := make(map[string]any, len(cfg.Network.OrdererAddresses))
	for _, address := range cfg.Network.OrdererAddresses {
		name := hostFromAddress(address)
		ordererNames = append(ordererNames, name)
		orderers[name] = map[string]any{
			"url": "grpcs://" + strings.TrimSpace(address),
			"tlsCACerts": map[string]any{
				"path": "/etc/hyperledger/fabric/tls/orderer-ca.pem",
			},
			"grpcOptions": map[string]any{
				"ssl-target-name-override": name,
				"hostnameOverride":         name,
			},
		}
	}

	peerName := "peer0." + cfg.Domain()
	caName := "ca." + cfg.Domain()
	mspID := cfg.MSPID()

	document := map[string]any{
		"name":    "open-democracy-" + strings.TrimSpace(cfg.Organization.Name),
		"version": "1.0.0",
		"client": map[string]any{
			"organization": mspID,
			"connection": map[string]any{
				"timeout": map[string]any{
					"peer": map[string]string{
						"endorser": "300",
					},
					"orderer": "300",
				},
			},
		},
		"channels": map[string]any{
			cfg.Network.ChannelName: map[string]any{
				"orderers": ordererNames,
				"peers": map[string]any{
					peerName: map[string]bool{
						"endorsingPeer":  true,
						"chaincodeQuery": true,
						"ledgerQuery":    true,
						"eventSource":    true,
					},
				},
			},
		},
		"organizations": map[string]any{
			mspID: map[string]any{
				"mspid": mspID,
				"peers": []string{peerName},
				"certificateAuthorities": []string{
					caName,
				},
				"cryptoPath": "/etc/hyperledger/fabric/msp",
			},
		},
		"orderers": orderers,
		"peers": map[string]any{
			peerName: map[string]any{
				"url": "grpcs://" + peerName + ":" + strconv.Itoa(cfg.Peer.Port),
				"tlsCACerts": map[string]any{
					"path": "/etc/hyperledger/fabric/tls/peer-ca.pem",
				},
				"grpcOptions": map[string]any{
					"ssl-target-name-override": peerName,
					"hostnameOverride":         peerName,
				},
			},
		},
		"certificateAuthorities": map[string]any{
			caName: map[string]any{
				"url": "https://" + caName + ":" + strconv.Itoa(cfg.CA.Port),
				"tlsCACerts": map[string]any{
					"path": "/etc/hyperledger/fabric/tls/ca-cert.pem",
				},
				"registrar": map[string]any{
					"enrollId":     strings.TrimSpace(cfg.CA.AdminUser),
					"enrollSecret": cfg.CA.AdminPass,
				},
				"caName": "ca-" + strings.TrimSpace(cfg.Organization.Name),
			},
		},
	}

	data, err := yaml.Marshal(document)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func loadNodeConfig(fedDir string) (NodeConfig, string, string, error) {
	configPath := filepath.Join(fedDir, nodeConfigFileName)
	if _, err := os.Stat(configPath); err == nil {
		cfg, readErr := readNodeConfig(configPath)
		return cfg, configPath, nodeConfigFileName, readErr
	} else if !errors.Is(err, os.ErrNotExist) {
		return NodeConfig{}, configPath, nodeConfigFileName, err
	}

	envPath := filepath.Join(fedDir, legacyEnvFileName)
	env, err := readEnv(envPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NodeConfig{}, configPath, "", nil
		}
		return NodeConfig{}, envPath, "", err
	}
	if strings.TrimSpace(env["ORG_NAME"]) == "" {
		return NodeConfig{}, configPath, "", nil
	}

	cfg, err := legacyNodeConfig(env)
	return cfg, envPath, "legacy " + legacyEnvFileName, err
}

func readNodeConfig(path string) (NodeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return NodeConfig{}, err
	}

	cfg := defaultNodeConfig()
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return NodeConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return NodeConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func writeNodeConfig(path string, cfg NodeConfig) error {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return err
	}

	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	content := "# Open Democracy node configuration.\n# Source of truth for odctl-managed federation settings.\n\n" + string(data)
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0600)
}

func writeLegacyEnv(path string, cfg NodeConfig) error {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return err
	}

	env := cfg.ComposeEnv()
	order := []string{
		"ORG_NAME",
		"ORG_DISPLAY",
		"ORG_MSP_ID",
		"ORG_DOMAIN",
		"SCOPE_PREFIX",
		"ORDERER_ADDRESSES",
		"CHANNEL_NAME",
		"CHAINCODE_NAME",
		"PEER_COUNT",
		"PEER_PORT",
		"CA_ADMIN_USER",
		"CA_ADMIN_PASS",
		"CA_PORT",
		"GATEWAY_PORT",
		"GATEWAY_DEFAULT_USER",
		"USE_COUCHDB",
		"COUCHDB_PORT",
		"COUCHDB_USER",
		"COUCHDB_PASS",
	}

	var sb strings.Builder
	sb.WriteString("# Generated by odctl from federation/democracy.toml.\n")
	sb.WriteString("# Edit democracy.toml instead of this file.\n\n")
	for _, key := range order {
		value, ok := env[key]
		if !ok {
			continue
		}
		sb.WriteString(key)
		sb.WriteString("=")
		sb.WriteString(envLiteral(value))
		sb.WriteString("\n")
	}

	return os.WriteFile(path, []byte(sb.String()), 0600)
}

func legacyNodeConfig(env map[string]string) (NodeConfig, error) {
	cfg := defaultNodeConfig()
	cfg.Organization.Name = strings.TrimSpace(env["ORG_NAME"])
	cfg.Organization.DisplayName = strings.TrimSpace(env["ORG_DISPLAY"])
	cfg.Organization.ScopePrefix = strings.TrimSpace(env["SCOPE_PREFIX"])
	cfg.Organization.MSPID = strings.TrimSpace(env["ORG_MSP_ID"])
	cfg.Organization.Domain = strings.TrimSpace(env["ORG_DOMAIN"])

	if raw := strings.TrimSpace(env["ORDERER_ADDRESSES"]); raw != "" {
		parts := strings.Split(raw, ",")
		cfg.Network.OrdererAddresses = cfg.Network.OrdererAddresses[:0]
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				cfg.Network.OrdererAddresses = append(cfg.Network.OrdererAddresses, part)
			}
		}
	}
	if raw := strings.TrimSpace(env["CHANNEL_NAME"]); raw != "" {
		cfg.Network.ChannelName = raw
	}
	if raw := strings.TrimSpace(env["CHAINCODE_NAME"]); raw != "" {
		cfg.Network.ChaincodeName = raw
	}

	var err error
	if cfg.Peer.Count, err = envInt(env, "PEER_COUNT", cfg.Peer.Count); err != nil {
		return NodeConfig{}, err
	}
	if cfg.Peer.Port, err = envInt(env, "PEER_PORT", cfg.Peer.Port); err != nil {
		return NodeConfig{}, err
	}
	if raw := strings.TrimSpace(env["CA_ADMIN_USER"]); raw != "" {
		cfg.CA.AdminUser = raw
	}
	if raw := strings.TrimSpace(env["CA_ADMIN_PASS"]); raw != "" {
		cfg.CA.AdminPass = raw
	}
	if cfg.CA.Port, err = envInt(env, "CA_PORT", cfg.CA.Port); err != nil {
		return NodeConfig{}, err
	}
	if cfg.Gateway.Port, err = envInt(env, "GATEWAY_PORT", cfg.Gateway.Port); err != nil {
		return NodeConfig{}, err
	}
	if raw := strings.TrimSpace(env["GATEWAY_DEFAULT_USER"]); raw != "" {
		cfg.Gateway.DefaultUser = raw
	}
	if cfg.CouchDB.Enabled, err = envBool(env, "USE_COUCHDB", cfg.CouchDB.Enabled); err != nil {
		return NodeConfig{}, err
	}
	if cfg.CouchDB.Port, err = envInt(env, "COUCHDB_PORT", cfg.CouchDB.Port); err != nil {
		return NodeConfig{}, err
	}
	if raw := strings.TrimSpace(env["COUCHDB_USER"]); raw != "" {
		cfg.CouchDB.User = raw
	}
	if raw := strings.TrimSpace(env["COUCHDB_PASS"]); raw != "" {
		cfg.CouchDB.Password = raw
	}

	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return NodeConfig{}, err
	}
	return cfg, nil
}

func envInt(env map[string]string, key string, fallback int) (int, error) {
	raw := strings.TrimSpace(env[key])
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be numeric, got %q", key, raw)
	}
	return value, nil
}

func envBool(env map[string]string, key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(env[key])
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be boolean, got %q", key, raw)
	}
	return value, nil
}

func validatedPortString(port int, field string) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("%s must be between 1 and 65535", field)
	}
	return strconv.Itoa(port), nil
}

func envLiteral(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " #\"'") {
		return strconv.Quote(value)
	}
	return value
}

func hostFromAddress(address string) string {
	address = strings.TrimSpace(address)
	if idx := strings.LastIndex(address, ":"); idx > 0 {
		return address[:idx]
	}
	return address
}

func sortedEnvKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
