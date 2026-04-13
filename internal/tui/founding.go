package tui

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

const (
	foundingRunsDirName     = "runs"
	foundingComposeFileName = "docker-compose.fabric.yml"
	foundingConfigDirName   = "config"
	foundingCryptoFileName  = "crypto-config.yaml"
	foundingConfigTxName    = "configtx.yaml"
	foundingRunEnvFileName  = "run.env"
	foundingComposeNetKey   = "od-network"
	foundingProjectPrefix   = "odf"
)

type FoundingConfig struct {
	InstancePrefix string                       `toml:"instance_prefix"`
	BaseDomain     string                       `toml:"base_domain"`
	Orderers       []FoundingOrdererConfig      `toml:"orderers"`
	Organizations  []FoundingOrganizationConfig `toml:"organizations"`
}

type FoundingOrdererConfig struct {
	Name string `toml:"name"`
}

type FoundingOrganizationConfig struct {
	Name               string `toml:"name"`
	DisplayName        string `toml:"display_name"`
	MSPID              string `toml:"msp_id,omitempty"`
	Domain             string `toml:"domain,omitempty"`
	PeerCount          int    `toml:"peer_count"`
	UserCount          int    `toml:"user_count"`
	GatewayDefaultUser string `toml:"gateway_default_user,omitempty"`
}

type foundingRun struct {
	Instance         string
	ProjectName      string
	RunDir           string
	ConfigDir        string
	ComposePath      string
	CryptoConfigPath string
	ConfigTxPath     string
	RunEnvPath       string
	CryptoDir        string
	ArtifactsDir     string
	BaseDomain       string
	ChannelName      string
	ChaincodeName    string
	ComposeNetwork   string
	Orderers         []foundingOrderer
	Organizations    []foundingOrganization
}

type foundingOrderer struct {
	Name      string
	Host      string
	VolumeKey string
}

type foundingOrganization struct {
	Slug               string
	DisplayName        string
	MSPID              string
	Domain             string
	CryptoName         string
	AnchorName         string
	UserCount          int
	GatewayDefaultUser string
	GatewayVolumeKey   string
	Peers              []foundingPeer
}

type foundingPeer struct {
	Index            int
	Host             string
	Domain           string
	MSPID            string
	VolumeKey        string
	FirstOrdererHost string
}

func defaultFoundingConfig() FoundingConfig {
	return FoundingConfig{
		InstancePrefix: defaultFoundingInstance,
		BaseDomain:     defaultFoundingBaseDomain,
		Orderers: []FoundingOrdererConfig{
			{Name: "orderer1"},
			{Name: "orderer2"},
			{Name: "orderer3"},
		},
		Organizations: []FoundingOrganizationConfig{
			{
				Name:               "opendemocracy",
				DisplayName:        "Open Democracy Foundation",
				PeerCount:          2,
				UserCount:          5,
				GatewayDefaultUser: defaultGatewayUser,
			},
			{
				Name:               "examplegov",
				DisplayName:        "Example Government",
				PeerCount:          1,
				UserCount:          3,
				GatewayDefaultUser: defaultGatewayUser,
			},
		},
	}
}

func (cfg FoundingConfig) withDefaults() FoundingConfig {
	defaults := defaultFoundingConfig()
	if strings.TrimSpace(cfg.InstancePrefix) == "" {
		cfg.InstancePrefix = defaults.InstancePrefix
	}
	if strings.TrimSpace(cfg.BaseDomain) == "" {
		cfg.BaseDomain = defaults.BaseDomain
	}
	if len(cfg.Orderers) == 0 {
		cfg.Orderers = append([]FoundingOrdererConfig(nil), defaults.Orderers...)
	}
	if len(cfg.Organizations) == 0 {
		cfg.Organizations = append([]FoundingOrganizationConfig(nil), defaults.Organizations...)
	}
	for i := range cfg.Orderers {
		if strings.TrimSpace(cfg.Orderers[i].Name) == "" && i < len(defaults.Orderers) {
			cfg.Orderers[i].Name = defaults.Orderers[i].Name
		}
	}
	for i := range cfg.Organizations {
		cfg.Organizations[i] = cfg.Organizations[i].withDefaults(cfg.BaseDomain)
	}
	return cfg
}

func (cfg FoundingConfig) Validate() error {
	cfg = cfg.withDefaults()
	if normalizeSlug(cfg.InstancePrefix) == "" {
		return fmt.Errorf("founding.instance_prefix must include at least one letter or digit")
	}
	if strings.TrimSpace(cfg.BaseDomain) == "" {
		return fmt.Errorf("founding.base_domain is required")
	}
	if len(cfg.Orderers) == 0 {
		return fmt.Errorf("founding.orderers must contain at least one orderer")
	}
	if len(cfg.Organizations) == 0 {
		return fmt.Errorf("founding.organizations must contain at least one organization")
	}

	ordererNames := make(map[string]struct{}, len(cfg.Orderers))
	for i, orderer := range cfg.Orderers {
		name := normalizeSlug(orderer.Name)
		if name == "" {
			return fmt.Errorf("founding.orderers[%d].name is required", i)
		}
		if _, exists := ordererNames[name]; exists {
			return fmt.Errorf("founding.orderers contains duplicate name %q", orderer.Name)
		}
		ordererNames[name] = struct{}{}
	}

	orgNames := make(map[string]struct{}, len(cfg.Organizations))
	orgDomains := make(map[string]struct{}, len(cfg.Organizations))
	orgMSPs := make(map[string]struct{}, len(cfg.Organizations))
	for i, org := range cfg.Organizations {
		org = org.withDefaults(cfg.BaseDomain)
		name := normalizeSlug(org.Name)
		if name == "" {
			return fmt.Errorf("founding.organizations[%d].name is required", i)
		}
		if _, exists := orgNames[name]; exists {
			return fmt.Errorf("founding.organizations contains duplicate name %q", org.Name)
		}
		orgNames[name] = struct{}{}
		if org.PeerCount < 1 {
			return fmt.Errorf("founding.organizations[%d].peer_count must be at least 1", i)
		}
		if org.UserCount < 1 {
			return fmt.Errorf("founding.organizations[%d].user_count must be at least 1", i)
		}
		domain := strings.TrimSpace(org.Domain)
		if domain == "" {
			return fmt.Errorf("founding.organizations[%d].domain resolved to empty value", i)
		}
		if _, exists := orgDomains[domain]; exists {
			return fmt.Errorf("founding.organizations contains duplicate domain %q", domain)
		}
		orgDomains[domain] = struct{}{}
		mspID := strings.TrimSpace(org.MSPIDValue())
		if mspID == "" {
			return fmt.Errorf("founding.organizations[%d].msp_id resolved to empty value", i)
		}
		if _, exists := orgMSPs[mspID]; exists {
			return fmt.Errorf("founding.organizations contains duplicate MSP ID %q", mspID)
		}
		orgMSPs[mspID] = struct{}{}
	}

	return nil
}

func (cfg FoundingConfig) OrdererAddresses() []string {
	cfg = cfg.withDefaults()
	addresses := make([]string, 0, len(cfg.Orderers))
	for _, orderer := range cfg.Orderers {
		addresses = append(addresses, normalizeSlug(orderer.Name)+"."+strings.TrimSpace(cfg.BaseDomain)+":7050")
	}
	return addresses
}

func (org FoundingOrganizationConfig) withDefaults(baseDomain string) FoundingOrganizationConfig {
	if strings.TrimSpace(org.DisplayName) == "" {
		org.DisplayName = humanizeSlug(org.Name)
	}
	if strings.TrimSpace(org.Domain) == "" {
		org.Domain = normalizeSlug(org.Name) + "." + strings.TrimSpace(baseDomain)
	}
	if strings.TrimSpace(org.MSPID) == "" {
		org.MSPID = toPascalCase(normalizeSlug(org.Name)) + "MSP"
	}
	if org.PeerCount == 0 {
		org.PeerCount = 1
	}
	if org.UserCount == 0 {
		org.UserCount = 1
	}
	if strings.TrimSpace(org.GatewayDefaultUser) == "" {
		org.GatewayDefaultUser = defaultGatewayUser
	}
	return org
}

func (org FoundingOrganizationConfig) MSPIDValue() string {
	return strings.TrimSpace(org.MSPID)
}

func resolveFoundingRun(fedDir string, cfg NodeConfig, requestedInstance string) (foundingRun, error) {
	cfg = cfg.withDefaults()
	founding := cfg.Founding.withDefaults()
	if err := founding.Validate(); err != nil {
		return foundingRun{}, err
	}
	instance, err := resolveFoundingInstance(requestedInstance, founding.InstancePrefix)
	if err != nil {
		return foundingRun{}, err
	}
	run, err := foundingRunPaths(fedDir, instance)
	if err != nil {
		return foundingRun{}, err
	}

	orderers := make([]foundingOrderer, 0, len(founding.Orderers))
	for _, orderer := range founding.Orderers {
		name := normalizeSlug(orderer.Name)
		orderers = append(orderers, foundingOrderer{
			Name:      name,
			Host:      name + "." + founding.BaseDomain,
			VolumeKey: name + "-data",
		})
	}

	orgs := make([]foundingOrganization, 0, len(founding.Organizations))
	firstOrdererHost := orderers[0].Host
	for _, orgCfg := range founding.Organizations {
		orgCfg = orgCfg.withDefaults(founding.BaseDomain)
		slug := normalizeSlug(orgCfg.Name)
		org := foundingOrganization{
			Slug:               slug,
			DisplayName:        strings.TrimSpace(orgCfg.DisplayName),
			MSPID:              strings.TrimSpace(orgCfg.MSPIDValue()),
			Domain:             strings.TrimSpace(orgCfg.Domain),
			CryptoName:         strings.TrimSuffix(strings.TrimSpace(orgCfg.MSPIDValue()), "MSP"),
			AnchorName:         toPascalCase(strings.TrimSuffix(strings.TrimSpace(orgCfg.MSPIDValue()), "MSP")),
			UserCount:          orgCfg.UserCount,
			GatewayDefaultUser: strings.TrimSpace(orgCfg.GatewayDefaultUser),
			GatewayVolumeKey:   "gateway-" + slug + "-data",
		}
		for i := 0; i < orgCfg.PeerCount; i++ {
			org.Peers = append(org.Peers, foundingPeer{
				Index:            i,
				Host:             fmt.Sprintf("peer%d.%s", i, org.Domain),
				Domain:           org.Domain,
				MSPID:            org.MSPID,
				VolumeKey:        fmt.Sprintf("peer%d-%s-data", i, slug),
				FirstOrdererHost: firstOrdererHost,
			})
		}
		orgs = append(orgs, org)
	}

	run.BaseDomain = strings.TrimSpace(founding.BaseDomain)
	run.ChannelName = strings.TrimSpace(cfg.Network.ChannelName)
	run.ChaincodeName = strings.TrimSpace(cfg.Network.ChaincodeName)
	run.ComposeNetwork = run.ProjectName + "_" + foundingComposeNetKey
	run.Orderers = orderers
	run.Organizations = orgs
	return run, nil
}

func generateFoundingArtifacts(fedDir string, cfg NodeConfig, requestedInstance string) (foundingRun, error) {
	run, err := resolveFoundingRun(fedDir, cfg, requestedInstance)
	if err != nil {
		return foundingRun{}, err
	}
	if err := os.MkdirAll(run.ConfigDir, 0755); err != nil {
		return foundingRun{}, err
	}
	if err := os.WriteFile(run.ComposePath, []byte(renderFoundingCompose(run)), 0644); err != nil {
		return foundingRun{}, err
	}
	if err := os.WriteFile(run.CryptoConfigPath, []byte(renderFoundingCryptoConfig(run)), 0644); err != nil {
		return foundingRun{}, err
	}
	if err := os.WriteFile(run.ConfigTxPath, []byte(renderFoundingConfigTx(run)), 0644); err != nil {
		return foundingRun{}, err
	}
	if err := os.WriteFile(run.RunEnvPath, []byte(renderFoundingRunEnv(run)), 0644); err != nil {
		return foundingRun{}, err
	}
	return run, nil
}

func renderFoundingCompose(run foundingRun) string {
	return renderTemplate(foundingComposeTemplate, run)
}

func renderFoundingCryptoConfig(run foundingRun) string {
	return renderTemplate(foundingCryptoConfigTemplate, run)
}

func renderFoundingConfigTx(run foundingRun) string {
	return renderTemplate(foundingConfigTxTemplate, run)
}

func renderFoundingRunEnv(run foundingRun) string {
	var sb strings.Builder
	lines := []struct {
		key   string
		value string
	}{
		{"INSTANCE", run.Instance},
		{"NETWORK_DIR", run.RunDir},
		{"CONFIG_DIR", run.ConfigDir},
		{"CRYPTO_DIR", run.CryptoDir},
		{"ARTIFACTS_DIR", run.ArtifactsDir},
		{"COMPOSE_FILE", run.ComposePath},
		{"COMPOSE_PROJECT_NAME", run.ProjectName},
		{"CHANNEL_NAME", run.ChannelName},
		{"CHAINCODE_NAME", run.ChaincodeName},
		{"ORDERER_ADDR", run.Orderers[0].Host + ":7050"},
		{"ORDERER_CA", filepath.Join(run.CryptoDir, "ordererOrganizations", run.BaseDomain, "msp", "tlscacerts", "tlsca."+run.BaseDomain+"-cert.pem")},
	}
	sb.WriteString("# Generated by odctl for the founding network run.\n")
	for _, line := range lines {
		sb.WriteString(line.key)
		sb.WriteString("=")
		sb.WriteString(envLiteral(line.value))
		sb.WriteString("\n")
	}
	return sb.String()
}

func resolveFoundingInstance(requested, prefix string) (string, error) {
	if normalized := normalizeSlug(requested); normalized != "" {
		return normalized, nil
	}
	normalizedPrefix := normalizeSlug(prefix)
	if normalizedPrefix == "" {
		return "", fmt.Errorf("founding.instance_prefix must include at least one letter or digit")
	}
	return normalizedPrefix + "-" + time.Now().UTC().Format("20060102-150405-000000000"), nil
}

func foundingComposeProjectName(instance string) string {
	instance = normalizeSlug(instance)
	if instance == "" {
		instance = defaultFoundingInstance
	}
	return foundingProjectPrefix + "-" + instance
}

func foundingRunPaths(fedDir, instance string) (foundingRun, error) {
	instance = normalizeSlug(instance)
	if instance == "" {
		return foundingRun{}, fmt.Errorf("network instance must include at least one letter or digit")
	}
	runDir := filepath.Join(fedDir, foundingRunsDirName, instance)
	return foundingRun{
		Instance:         instance,
		ProjectName:      foundingComposeProjectName(instance),
		RunDir:           runDir,
		ConfigDir:        filepath.Join(runDir, foundingConfigDirName),
		ComposePath:      filepath.Join(runDir, foundingComposeFileName),
		CryptoConfigPath: filepath.Join(runDir, foundingConfigDirName, foundingCryptoFileName),
		ConfigTxPath:     filepath.Join(runDir, foundingConfigDirName, foundingConfigTxName),
		RunEnvPath:       filepath.Join(runDir, foundingRunEnvFileName),
		CryptoDir:        filepath.Join(runDir, "crypto"),
		ArtifactsDir:     filepath.Join(runDir, "channel-artifacts"),
	}, nil
}

func normalizeSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var sb strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			sb.WriteRune(r)
			lastDash = false
		case r == '-', r == '_', r == '.', r == ' ', r == '/':
			if sb.Len() == 0 || lastDash {
				continue
			}
			sb.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(sb.String(), "-")
}

func humanizeSlug(value string) string {
	parts := strings.FieldsFunc(normalizeSlug(value), func(r rune) bool {
		return r == '-'
	})
	for i, part := range parts {
		if len(part) == 0 {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func renderTemplate(text string, data any) string {
	tpl := template.Must(template.New("founding").Parse(text))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		panic(err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}

const foundingComposeTemplate = `x-fabric-peer-env: &fabric-peer-env
  FABRIC_LOGGING_SPEC: INFO
  CORE_PEER_TLS_ENABLED: "true"
  CORE_PEER_PROFILE_ENABLED: "false"
  CORE_PEER_ADDRESSAUTODETECT: "false"
  CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE: {{ .ComposeNetwork }}
  CORE_CHAINCODE_EXECUTETIMEOUT: 300s

x-fabric-orderer-env: &fabric-orderer-env
  FABRIC_LOGGING_SPEC: INFO
  ORDERER_GENERAL_LISTENADDRESS: 0.0.0.0
  ORDERER_GENERAL_LISTENPORT: "7050"
  ORDERER_GENERAL_LOCALMSPID: OrdererMSP
  ORDERER_GENERAL_TLS_ENABLED: "true"
  ORDERER_GENERAL_BOOTSTRAPMETHOD: file
  ORDERER_GENERAL_BOOTSTRAPFILE: /var/hyperledger/orderer/genesis.block

networks:
  ` + foundingComposeNetKey + `:

volumes:
{{- range .Orderers }}
  {{ .VolumeKey }}:
{{- end }}
{{- range .Organizations }}
{{- range .Peers }}
  {{ .VolumeKey }}:
{{- end }}
  {{ .GatewayVolumeKey }}:
{{- end }}

services:
{{- range .Orderers }}

  {{ .Host }}:
    image: hyperledger/fabric-orderer:2.5
    environment:
      <<: *fabric-orderer-env
      ORDERER_GENERAL_LOCALMSPDIR: /var/hyperledger/orderer/msp
      ORDERER_GENERAL_TLS_PRIVATEKEY: /var/hyperledger/orderer/tls/server.key
      ORDERER_GENERAL_TLS_CERTIFICATE: /var/hyperledger/orderer/tls/server.crt
      ORDERER_GENERAL_TLS_ROOTCAS: "[/var/hyperledger/orderer/tls/ca.crt]"
      ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE: /var/hyperledger/orderer/tls/server.crt
      ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY: /var/hyperledger/orderer/tls/server.key
      ORDERER_GENERAL_CLUSTER_ROOTCAS: "[/var/hyperledger/orderer/tls/ca.crt]"
    volumes:
      - ./crypto/ordererOrganizations/{{ $.BaseDomain }}/orderers/{{ .Host }}/msp:/var/hyperledger/orderer/msp
      - ./crypto/ordererOrganizations/{{ $.BaseDomain }}/orderers/{{ .Host }}/tls:/var/hyperledger/orderer/tls
      - ./channel-artifacts/genesis.block:/var/hyperledger/orderer/genesis.block
      - {{ .VolumeKey }}:/var/hyperledger/production/orderer
    ports:
      - "7050"
    networks:
      - ` + foundingComposeNetKey + `
    restart: unless-stopped
{{- end }}
{{- range .Organizations }}

  ca.{{ .Domain }}:
    image: hyperledger/fabric-ca:1.5
    environment:
      FABRIC_CA_HOME: /etc/hyperledger/fabric-ca-server
      FABRIC_CA_SERVER_CA_NAME: ca-{{ .Slug }}
      FABRIC_CA_SERVER_TLS_ENABLED: "true"
      FABRIC_CA_SERVER_PORT: "7054"
    ports:
      - "7054"
    volumes:
      - ./crypto/peerOrganizations/{{ .Domain }}/ca:/etc/hyperledger/fabric-ca-server
    networks:
      - ` + foundingComposeNetKey + `
    restart: unless-stopped
{{- range .Peers }}

  {{ .Host }}:
    image: hyperledger/fabric-peer:2.5
    environment:
      <<: *fabric-peer-env
      CORE_PEER_ID: {{ .Host }}
      CORE_PEER_ADDRESS: {{ .Host }}:7051
      CORE_PEER_LISTENADDRESS: 0.0.0.0:7051
      CORE_PEER_CHAINCODEADDRESS: {{ .Host }}:7052
      CORE_PEER_CHAINCODELISTENADDRESS: 0.0.0.0:7052
      CORE_PEER_GOSSIP_BOOTSTRAP: peer0.{{ .Domain }}:7051
      CORE_PEER_GOSSIP_EXTERNALENDPOINT: {{ .Host }}:7051
      CORE_PEER_LOCALMSPID: {{ .MSPID }}
      CORE_PEER_TLS_CERT_FILE: /etc/hyperledger/fabric/tls/server.crt
      CORE_PEER_TLS_KEY_FILE: /etc/hyperledger/fabric/tls/server.key
      CORE_PEER_TLS_ROOTCERT_FILE: /etc/hyperledger/fabric/tls/ca.crt
      CORE_PEER_MSPCONFIGPATH: /etc/hyperledger/fabric/msp
    volumes:
      - ./crypto/peerOrganizations/{{ .Domain }}/peers/{{ .Host }}/msp:/etc/hyperledger/fabric/msp
      - ./crypto/peerOrganizations/{{ .Domain }}/peers/{{ .Host }}/tls:/etc/hyperledger/fabric/tls
      - {{ .VolumeKey }}:/var/hyperledger/production
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - "7051"
    networks:
      - ` + foundingComposeNetKey + `
    depends_on:
      - {{ .FirstOrdererHost }}
    restart: unless-stopped
{{- end }}

  gateway.{{ .Slug }}:
    build:
      context: ../..
      dockerfile: Dockerfile
    image: open-democracy-gateway:latest
    environment:
      GATEWAY_ADDR: ":8080"
      GATEWAY_DATA: "/data"
      GATEWAY_USER: "{{ .GatewayDefaultUser }}"
    volumes:
      - {{ .GatewayVolumeKey }}:/data
    ports:
      - "8080"
    networks:
      - ` + foundingComposeNetKey + `
    depends_on:
      - peer0.{{ .Domain }}
    restart: unless-stopped
{{- end }}
`

const foundingCryptoConfigTemplate = `OrdererOrgs:
  - Name: Orderer
    Domain: {{ .BaseDomain }}
    EnableNodeOUs: true
    Specs:
{{- range .Orderers }}
      - Hostname: {{ .Name }}
        SANS:
          - localhost
          - 127.0.0.1
{{- end }}

PeerOrgs:
{{- range .Organizations }}
  - Name: {{ .CryptoName }}
    Domain: {{ .Domain }}
    EnableNodeOUs: true
    Template:
      Count: {{ len .Peers }}
      SANS:
        - localhost
        - 127.0.0.1
    Users:
      Count: {{ .UserCount }}
{{- end }}
`

const foundingConfigTxTemplate = `Organizations:
  - &OrdererOrg
    Name: OrdererOrg
    ID: OrdererMSP
    MSPDir: ../crypto/ordererOrganizations/{{ .BaseDomain }}/msp
    Policies:
      Readers:
        Type: Signature
        Rule: "OR('OrdererMSP.member')"
      Writers:
        Type: Signature
        Rule: "OR('OrdererMSP.member')"
      Admins:
        Type: Signature
        Rule: "OR('OrdererMSP.admin')"
    OrdererEndpoints:
{{- range .Orderers }}
      - {{ .Host }}:7050
{{- end }}
{{- range .Organizations }}

  - &{{ .AnchorName }}
    Name: {{ .MSPID }}
    ID: {{ .MSPID }}
    MSPDir: ../crypto/peerOrganizations/{{ .Domain }}/msp
    Policies:
      Readers:
        Type: Signature
        Rule: "OR('{{ .MSPID }}.admin', '{{ .MSPID }}.peer', '{{ .MSPID }}.client')"
      Writers:
        Type: Signature
        Rule: "OR('{{ .MSPID }}.admin', '{{ .MSPID }}.client')"
      Admins:
        Type: Signature
        Rule: "OR('{{ .MSPID }}.admin')"
      Endorsement:
        Type: Signature
        Rule: "OR('{{ .MSPID }}.peer')"
    AnchorPeers:
      - Host: peer0.{{ .Domain }}
        Port: 7051
{{- end }}

Capabilities:
  Channel: &ChannelCapabilities
    V2_0: true
  Orderer: &OrdererCapabilities
    V2_0: true
  Application: &ApplicationCapabilities
    V2_0: true

Application: &ApplicationDefaults
  Organizations:
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
    LifecycleEndorsement:
      Type: ImplicitMeta
      Rule: "MAJORITY Endorsement"
    Endorsement:
      Type: ImplicitMeta
      Rule: "MAJORITY Endorsement"
  Capabilities:
    <<: *ApplicationCapabilities

Orderer: &OrdererDefaults
  OrdererType: etcdraft
  BatchTimeout: 2s
  BatchSize:
    MaxMessageCount: 10
    AbsoluteMaxBytes: 99 MB
    PreferredMaxBytes: 512 KB
  EtcdRaft:
    Consenters:
{{- range .Orderers }}
      - Host: {{ .Host }}
        Port: 7050
        ClientTLSCert: ../crypto/ordererOrganizations/{{ $.BaseDomain }}/orderers/{{ .Host }}/tls/server.crt
        ServerTLSCert: ../crypto/ordererOrganizations/{{ $.BaseDomain }}/orderers/{{ .Host }}/tls/server.crt
{{- end }}
  Organizations:
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
    BlockValidation:
      Type: ImplicitMeta
      Rule: "ANY Writers"
  Capabilities:
    <<: *OrdererCapabilities

Channel: &ChannelDefaults
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
  Capabilities:
    <<: *ChannelCapabilities

Profiles:
  FederationGenesis:
    <<: *ChannelDefaults
    Orderer:
      <<: *OrdererDefaults
      Organizations:
        - *OrdererOrg
    Consortiums:
      FederationConsortium:
        Organizations:
{{- range .Organizations }}
          - *{{ .AnchorName }}
{{- end }}

  GovernanceChannel:
    <<: *ChannelDefaults
    Consortium: FederationConsortium
    Application:
      <<: *ApplicationDefaults
      Organizations:
{{- range .Organizations }}
        - *{{ .AnchorName }}
{{- end }}
`
