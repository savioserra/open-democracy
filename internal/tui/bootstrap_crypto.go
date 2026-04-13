package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const certificateValidityDays = "3650"

func ensureNodeCryptoDirs(fedDir string) error {
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
		"crypto/users/admin/msp/admincerts",
		"crypto/users/admin/msp/cacerts",
		"crypto/users/admin/msp/keystore",
		"crypto/users/admin/msp/signcerts",
		"crypto/users/admin/msp/tlscacerts",
	}
	for _, dir := range dirs {
		path := filepath.Join(fedDir, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	return nil
}

func generateCACertificate(state ProjectState) (string, error) {
	caDir := filepath.Join(state.FedDir, "crypto", "ca")
	keyPath := filepath.Join(caDir, "ca-key.pem")
	certPath := filepath.Join(caDir, "ca-cert.pem")
	if err := ensureECDSAKey(state.FedDir, keyPath); err != nil {
		return "", err
	}
	if fileExists(certPath) {
		if err := syncCAArtifacts(state.FedDir, certPath); err != nil {
			return "", err
		}
		return "CA cert already exists, synced MSP trust roots.", nil
	}

	org, domain := bootstrapOrgDetails(state)
	csrPath := filepath.Join(caDir, "ca.csr")
	extPath := filepath.Join(caDir, "ca-ext.cnf")
	defer removeQuietly(csrPath, extPath)

	if _, err := createCSR(state.FedDir, keyPath, csrPath, subjectString(org, "ca."+domain, "")); err != nil {
		return "", err
	}
	if err := os.WriteFile(extPath, []byte(caExtensions()), 0644); err != nil {
		return "", err
	}

	out, err := shellRun(state.FedDir, "openssl", "x509",
		"-req",
		"-in", csrPath,
		"-signkey", keyPath,
		"-out", certPath,
		"-days", certificateValidityDays,
		"-sha256",
		"-extensions", "v3_ca",
		"-extfile", extPath)
	if err != nil {
		return out, err
	}
	if err := syncCAArtifacts(state.FedDir, certPath); err != nil {
		return out, err
	}
	return "CA cert: " + certPath, nil
}

func generateCATLSCertificate(state ProjectState) (string, error) {
	caDir := filepath.Join(state.FedDir, "crypto", "ca")
	keyPath := filepath.Join(caDir, "tls-key.pem")
	certPath := filepath.Join(caDir, "tls-cert.pem")
	if err := ensureECDSAKey(state.FedDir, keyPath); err != nil {
		return "", err
	}
	if fileExists(certPath) {
		return "CA TLS cert already exists, skipping.", nil
	}

	org, domain := bootstrapOrgDetails(state)
	csrPath := filepath.Join(caDir, "tls.csr")
	extPath := filepath.Join(caDir, "tls-ext.cnf")
	defer removeQuietly(csrPath, extPath)

	if _, err := createCSR(state.FedDir, keyPath, csrPath, subjectString(org, "ca."+domain, "")); err != nil {
		return "", err
	}
	if err := os.WriteFile(extPath, []byte(tlsExtensions("v3_tls", "ca."+domain, "localhost", "127.0.0.1")), 0644); err != nil {
		return "", err
	}

	out, err := signCSRWithCA(
		state.FedDir,
		filepath.Join(caDir, "ca-cert.pem"),
		filepath.Join(caDir, "ca-key.pem"),
		csrPath,
		certPath,
		extPath,
		"v3_tls",
	)
	if err != nil {
		return out, err
	}
	return "CA TLS cert: " + certPath, nil
}

func generateAdminMSP(state ProjectState) (string, error) {
	baseDir := filepath.Join(state.FedDir, "crypto", "users", "admin", "msp")
	keyPath := filepath.Join(baseDir, "keystore", "key.pem")
	certPath := filepath.Join(baseDir, "signcerts", "cert.pem")
	if err := ensureECDSAKey(state.FedDir, keyPath); err != nil {
		return "", err
	}
	if !fileExists(certPath) {
		org, domain := bootstrapOrgDetails(state)
		csrPath := filepath.Join(baseDir, "admin.csr")
		extPath := filepath.Join(baseDir, "admin-ext.cnf")
		defer removeQuietly(csrPath, extPath)

		if _, err := createCSR(state.FedDir, keyPath, csrPath, subjectString(org, "admin@"+domain, "admin")); err != nil {
			return "", err
		}
		if err := os.WriteFile(extPath, []byte(identityExtensions("v3_admin")), 0644); err != nil {
			return "", err
		}

		out, err := signCSRWithCA(
			state.FedDir,
			filepath.Join(state.FedDir, "crypto", "ca", "ca-cert.pem"),
			filepath.Join(state.FedDir, "crypto", "ca", "ca-key.pem"),
			csrPath,
			certPath,
			extPath,
			"v3_admin",
		)
		if err != nil {
			return out, err
		}
	}

	if err := syncAdminCertificates(state.FedDir, certPath); err != nil {
		return "", err
	}
	return "Admin MSP cert: " + certPath, nil
}

func generatePeerMSP(state ProjectState) (string, error) {
	baseDir := filepath.Join(state.FedDir, "crypto", "peers", "peer0", "msp")
	keyPath := filepath.Join(baseDir, "keystore", "key.pem")
	certPath := filepath.Join(baseDir, "signcerts", "cert.pem")
	if err := ensureECDSAKey(state.FedDir, keyPath); err != nil {
		return "", err
	}
	if fileExists(certPath) {
		return "Peer MSP cert already exists, skipping.", nil
	}

	org, domain := bootstrapOrgDetails(state)
	csrPath := filepath.Join(baseDir, "peer.csr")
	extPath := filepath.Join(baseDir, "peer-ext.cnf")
	defer removeQuietly(csrPath, extPath)

	if _, err := createCSR(state.FedDir, keyPath, csrPath, subjectString(org, "peer0."+domain, "peer")); err != nil {
		return "", err
	}
	if err := os.WriteFile(extPath, []byte(identityExtensions("v3_peer")), 0644); err != nil {
		return "", err
	}

	out, err := signCSRWithCA(
		state.FedDir,
		filepath.Join(state.FedDir, "crypto", "ca", "ca-cert.pem"),
		filepath.Join(state.FedDir, "crypto", "ca", "ca-key.pem"),
		csrPath,
		certPath,
		extPath,
		"v3_peer",
	)
	if err != nil {
		return out, err
	}
	return "Peer MSP cert: " + certPath, nil
}

func generatePeerTLSCertificate(state ProjectState) (string, error) {
	tlsDir := filepath.Join(state.FedDir, "crypto", "peers", "peer0", "tls")
	keyPath := filepath.Join(tlsDir, "server.key")
	certPath := filepath.Join(tlsDir, "server.crt")
	if err := ensureECDSAKey(state.FedDir, keyPath); err != nil {
		return "", err
	}
	if fileExists(certPath) {
		return "Peer TLS cert already exists, skipping.", nil
	}

	org, domain := bootstrapOrgDetails(state)
	csrPath := filepath.Join(tlsDir, "server.csr")
	extPath := filepath.Join(tlsDir, "server-ext.cnf")
	defer removeQuietly(csrPath, extPath)

	if _, err := createCSR(state.FedDir, keyPath, csrPath, subjectString(org, "peer0."+domain, "")); err != nil {
		return "", err
	}
	if err := os.WriteFile(extPath, []byte(tlsExtensions("v3_peer_tls", "peer0."+domain, "localhost", "127.0.0.1")), 0644); err != nil {
		return "", err
	}

	out, err := signCSRWithCA(
		state.FedDir,
		filepath.Join(state.FedDir, "crypto", "ca", "ca-cert.pem"),
		filepath.Join(state.FedDir, "crypto", "ca", "ca-key.pem"),
		csrPath,
		certPath,
		extPath,
		"v3_peer_tls",
	)
	if err != nil {
		return out, err
	}

	cert, err := os.ReadFile(filepath.Join(state.FedDir, "crypto", "ca", "ca-cert.pem"))
	if err != nil {
		return out, err
	}
	if err := os.WriteFile(filepath.Join(tlsDir, "ca.crt"), cert, 0644); err != nil {
		return out, err
	}
	return "Peer TLS cert: " + certPath, nil
}

func syncCAArtifacts(fedDir, caCertPath string) error {
	cert, err := os.ReadFile(caCertPath)
	if err != nil {
		return err
	}
	paths := []string{
		filepath.Join(fedDir, "crypto", "peers", "peer0", "msp", "cacerts", "ca-cert.pem"),
		filepath.Join(fedDir, "crypto", "peers", "peer0", "msp", "tlscacerts", "ca-cert.pem"),
		filepath.Join(fedDir, "crypto", "msp", "cacerts", "ca-cert.pem"),
		filepath.Join(fedDir, "crypto", "msp", "tlscacerts", "ca-cert.pem"),
		filepath.Join(fedDir, "crypto", "users", "admin", "msp", "cacerts", "ca-cert.pem"),
		filepath.Join(fedDir, "crypto", "users", "admin", "msp", "tlscacerts", "ca-cert.pem"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, cert, 0644); err != nil {
			return err
		}
	}
	return writeMSPConfigs(fedDir)
}

func syncAdminCertificates(fedDir, adminCertPath string) error {
	cert, err := os.ReadFile(adminCertPath)
	if err != nil {
		return err
	}
	paths := []string{
		filepath.Join(fedDir, "crypto", "msp", "admincerts", "admin-cert.pem"),
		filepath.Join(fedDir, "crypto", "peers", "peer0", "msp", "admincerts", "admin-cert.pem"),
		filepath.Join(fedDir, "crypto", "users", "admin", "msp", "admincerts", "admin-cert.pem"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, cert, 0644); err != nil {
			return err
		}
	}
	return nil
}

func writeMSPConfigs(fedDir string) error {
	data := []byte(nodeOUsConfig())
	paths := []string{
		filepath.Join(fedDir, "crypto", "peers", "peer0", "msp", "config.yaml"),
		filepath.Join(fedDir, "crypto", "msp", "config.yaml"),
		filepath.Join(fedDir, "crypto", "users", "admin", "msp", "config.yaml"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func ensureECDSAKey(fedDir, keyPath string) error {
	if fileExists(keyPath) {
		return nil
	}
	_, err := shellRun(fedDir, "openssl", "ecparam",
		"-genkey",
		"-name", "prime256v1",
		"-noout",
		"-out", keyPath,
	)
	return err
}

func createCSR(fedDir, keyPath, csrPath, subject string) (string, error) {
	return shellRun(fedDir, "openssl", "req",
		"-new",
		"-key", keyPath,
		"-out", csrPath,
		"-subj", subject,
	)
}

func signCSRWithCA(fedDir, caCertPath, caKeyPath, csrPath, certPath, extPath, extSection string) (string, error) {
	serialPath := strings.TrimSuffix(caCertPath, filepath.Ext(caCertPath)) + ".srl"
	args := []string{
		"x509",
		"-req",
		"-in", csrPath,
		"-CA", caCertPath,
		"-CAkey", caKeyPath,
	}
	if fileExists(serialPath) {
		args = append(args, "-CAserial", serialPath)
	} else {
		args = append(args, "-CAcreateserial")
	}
	args = append(args,
		"-out", certPath,
		"-days", certificateValidityDays,
		"-sha256",
		"-extensions", extSection,
		"-extfile", extPath,
	)
	return shellRun(fedDir, "openssl", args...)
}

func bootstrapOrgDetails(state ProjectState) (string, string) {
	org := strings.TrimSpace(state.OrgDisplay)
	if org == "" {
		org = strings.TrimSpace(state.OrgName)
	}
	domain := strings.TrimSpace(state.Domain)
	if domain == "" {
		domain = strings.TrimSpace(state.OrgName) + ".od.example.com"
	}
	return org, domain
}

func subjectString(org, commonName, organizationalUnit string) string {
	parts := []string{"/C=BR", "/ST=Federation"}
	if org != "" {
		parts = append(parts, "/O="+org)
	}
	if organizationalUnit != "" {
		parts = append(parts, "/OU="+organizationalUnit)
	}
	parts = append(parts, "/CN="+commonName)
	return strings.Join(parts, "")
}

func caExtensions() string {
	return `[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
`
}

func identityExtensions(section string) string {
	return `[` + section + `]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
`
}

func tlsExtensions(section string, hosts ...string) string {
	lines := []string{
		"[" + section + "]",
		"basicConstraints = critical, CA:false",
		"keyUsage = critical, digitalSignature, keyEncipherment",
		"extendedKeyUsage = serverAuth, clientAuth",
		"subjectKeyIdentifier = hash",
		"authorityKeyIdentifier = keyid,issuer",
		"subjectAltName = @alt_names",
		"[alt_names]",
	}
	dnsIndex := 1
	ipIndex := 1
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if isIPAddress(host) {
			lines = append(lines, fmt.Sprintf("IP.%d = %s", ipIndex, host))
			ipIndex++
			continue
		}
		lines = append(lines, fmt.Sprintf("DNS.%d = %s", dnsIndex, host))
		dnsIndex++
	}
	return strings.Join(lines, "\n") + "\n"
}

func nodeOUsConfig() string {
	return `NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: orderer
`
}

func isIPAddress(host string) bool {
	for _, r := range host {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return strings.Count(host, ".") == 3
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func removeQuietly(paths ...string) {
	for _, path := range paths {
		_ = os.Remove(path)
	}
}
