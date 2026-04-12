package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
				port := s.GatewayPort
				if port == "" {
					port = "8080"
				}
				return out + "\nDashboard ready at http://localhost:" + port + "/\n", nil
			},
		},
	}
}

// --- Bootstrap node --------------------------------------------------------

func bootstrapTasks(st ProjectState) []task {
	return []task{
		{
			label: "Create directory structure",
			fn: func(s ProjectState) (string, error) {
				dirs := []string{
					"crypto/ca",
					"crypto/peers/peer0/msp/admincerts",
					"crypto/peers/peer0/msp/cacerts",
					"crypto/peers/peer0/msp/keystore",
					"crypto/peers/peer0/msp/signcerts",
					"crypto/peers/peer0/msp/tlscacerts",
					"crypto/peers/peer0/tls",
					"crypto/msp/admincerts",
					"crypto/msp/cacerts",
					"crypto/msp/tlscacerts",
					"crypto/users",
				}
				for _, d := range dirs {
					p := filepath.Join(s.FedDir, d)
					if err := os.MkdirAll(p, 0755); err != nil {
						return "", fmt.Errorf("mkdir %s: %w", d, err)
					}
				}
				return "Created directory structure under federation/crypto/", nil
			},
		},
		{
			label: "Generate CA private key",
			fn: func(s ProjectState) (string, error) {
				keyPath := filepath.Join(s.FedDir, "crypto", "ca", "ca-key.pem")
				if _, err := os.Stat(keyPath); err == nil {
					return "CA key already exists, skipping.", nil
				}
				return shellRun(s.FedDir, "openssl", "ecparam",
					"-genkey", "-name", "prime256v1", "-noout",
					"-out", keyPath)
			},
		},
		{
			label: "Generate CA certificate",
			fn: func(s ProjectState) (string, error) {
				keyPath := filepath.Join(s.FedDir, "crypto", "ca", "ca-key.pem")
				certPath := filepath.Join(s.FedDir, "crypto", "ca", "ca-cert.pem")
				if _, err := os.Stat(certPath); err == nil {
					return "CA cert already exists, skipping.", nil
				}
				org := s.OrgDisplay
				if org == "" {
					org = s.OrgName
				}
				domain := s.Domain
				if domain == "" {
					domain = s.OrgName + ".od.example.com"
				}
				subj := fmt.Sprintf("/C=BR/ST=Federation/O=%s/CN=ca.%s", org, domain)
				out, err := shellRun(s.FedDir, "openssl", "req",
					"-new", "-x509",
					"-key", keyPath,
					"-out", certPath,
					"-days", "3650",
					"-subj", subj)
				if err != nil {
					return out, err
				}
				// Copy CA cert to MSP locations.
				cert, _ := os.ReadFile(certPath)
				_ = os.WriteFile(filepath.Join(s.FedDir, "crypto", "peers", "peer0", "msp", "cacerts", "ca-cert.pem"), cert, 0644)
				_ = os.WriteFile(filepath.Join(s.FedDir, "crypto", "msp", "cacerts", "ca-cert.pem"), cert, 0644)
				return "CA cert: " + certPath, nil
			},
		},
		{
			label: "Generate peer TLS key and certificate",
			fn: func(s ProjectState) (string, error) {
				tlsDir := filepath.Join(s.FedDir, "crypto", "peers", "peer0", "tls")
				keyPath := filepath.Join(tlsDir, "server.key")
				certPath := filepath.Join(tlsDir, "server.crt")
				if _, err := os.Stat(certPath); err == nil {
					return "Peer TLS cert already exists, skipping.", nil
				}

				org := s.OrgDisplay
				if org == "" {
					org = s.OrgName
				}
				domain := s.Domain
				if domain == "" {
					domain = s.OrgName + ".od.example.com"
				}

				// Generate key.
				if _, err := shellRun(s.FedDir, "openssl", "ecparam",
					"-genkey", "-name", "prime256v1", "-noout",
					"-out", keyPath); err != nil {
					return "", err
				}

				// Generate CSR.
				csrPath := filepath.Join(tlsDir, "server.csr")
				subj := fmt.Sprintf("/C=BR/ST=Federation/O=%s/CN=peer0.%s", org, domain)
				if _, err := shellRun(s.FedDir, "openssl", "req",
					"-new", "-key", keyPath,
					"-out", csrPath,
					"-subj", subj); err != nil {
					return "", err
				}

				// SAN config.
				sanPath := filepath.Join(tlsDir, "san.cnf")
				san := fmt.Sprintf("[v3_req]\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = peer0.%s\nDNS.2 = localhost\nIP.1 = 127.0.0.1\n", domain)
				_ = os.WriteFile(sanPath, []byte(san), 0644)

				// Sign with CA.
				caKey := filepath.Join(s.FedDir, "crypto", "ca", "ca-key.pem")
				caCert := filepath.Join(s.FedDir, "crypto", "ca", "ca-cert.pem")
				out, err := shellRun(s.FedDir, "openssl", "x509",
					"-req",
					"-in", csrPath,
					"-CA", caCert, "-CAkey", caKey, "-CAcreateserial",
					"-out", certPath,
					"-days", "3650",
					"-extensions", "v3_req", "-extfile", sanPath)
				if err != nil {
					return out, err
				}

				// Copy CA cert as TLS root.
				cert, _ := os.ReadFile(caCert)
				_ = os.WriteFile(filepath.Join(tlsDir, "ca.crt"), cert, 0644)
				_ = os.WriteFile(filepath.Join(s.FedDir, "crypto", "peers", "peer0", "msp", "tlscacerts", "ca-cert.pem"), cert, 0644)
				_ = os.WriteFile(filepath.Join(s.FedDir, "crypto", "msp", "tlscacerts", "ca-cert.pem"), cert, 0644)

				// Clean up temporaries.
				os.Remove(csrPath)
				os.Remove(sanPath)

				return "Peer TLS cert: " + certPath, nil
			},
		},
		{
			label: "Generate connection profile",
			fn: func(s ProjectState) (string, error) {
				tmplPath := filepath.Join(s.FedDir, "config", "connection-profile-template.yaml")
				outPath := filepath.Join(s.FedDir, "connection-profile.yaml")

				tmpl, err := os.ReadFile(tmplPath)
				if err != nil {
					return "", fmt.Errorf("template not found: %w", err)
				}

				replacements := map[string]string{
					"${ORG_NAME}":      s.OrgName,
					"${ORG_MSP_ID}":    s.MspID,
					"${ORG_DOMAIN}":    s.Domain,
					"${CHANNEL_NAME}":  "governance",
					"${PEER_PORT}":     "7051",
					"${CA_PORT}":       "7054",
					"${CA_ADMIN_USER}": "admin",
					"${CA_ADMIN_PASS}": "adminpw",
				}
				result := string(tmpl)
				for k, v := range replacements {
					if v == "" {
						v = k // leave placeholder if not configured
					}
					result = strings.ReplaceAll(result, k, v)
				}

				if err := os.WriteFile(outPath, []byte(result), 0644); err != nil {
					return "", err
				}
				return "Connection profile: " + outPath, nil
			},
		},
	}
}

// --- Start federation node -------------------------------------------------

func startNodeTasks(st ProjectState) []task {
	return []task{
		{
			label: "Start federation node containers",
			fn: func(s ProjectState) (string, error) {
				return shellRun(s.FedDir, "docker", "compose",
					"-f", "docker-compose.node.yml",
					"up", "-d", "--build")
			},
		},
		{
			label: "Check container status",
			fn: func(s ProjectState) (string, error) {
				out, err := shellRun(s.FedDir, "docker", "compose",
					"-f", "docker-compose.node.yml", "ps")
				if err != nil {
					return out, err
				}
				port := s.GatewayPort
				if port == "" {
					port = "8080"
				}
				return out + "\nDashboard: http://localhost:" + port + "/\n", nil
			},
		},
	}
}

// --- Stop services ---------------------------------------------------------

func stopTasks(st ProjectState) []task {
	return []task{
		{
			label: "Stop demo containers",
			fn: func(s ProjectState) (string, error) {
				out, _ := shellRun(s.RepoRoot, "docker", "compose", "down")
				return out, nil // don't fail if nothing running
			},
		},
		{
			label: "Stop federation node containers",
			fn: func(s ProjectState) (string, error) {
				compose := filepath.Join(s.FedDir, "docker-compose.node.yml")
				if _, err := os.Stat(compose); err != nil {
					return "No federation compose file, skipping.", nil
				}
				out, _ := shellRun(s.FedDir, "docker", "compose",
					"-f", "docker-compose.node.yml", "down")
				return out, nil
			},
		},
	}
}

// --- helpers ----------------------------------------------------------------

func shellRun(dir string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
