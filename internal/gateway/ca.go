package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IdentityProvider manages participant identities at the infrastructure
// level. In demo mode it is a no-op (the registry + JSON store are the
// sole source of truth). In production it writes through to a Fabric CA
// so the participant gets a real X.509 certificate with scope attributes
// embedded — the same cert the chaincode's GetInvoker reads.
type IdentityProvider interface {
	// Register creates an identity in the CA with the given scope claims.
	// The CA will store the claims as the "scopes" X.509 attribute (CSV)
	// and the display name as "displayName", both marked for inclusion
	// in the enrollment certificate.
	Register(id, displayName string, claims []string) error

	// Revoke disables an identity in the CA. Already-issued certificates
	// are added to the revocation list.
	Revoke(id string) error

	// Available reports whether the provider is connected and operational.
	Available() bool
}

// CAConfig holds the connection details for a Fabric CA server. When all
// fields are empty the gateway runs in demo mode (LocalProvider).
type CAConfig struct {
	URL       string // https://ca.myorg.od.example.com:7054
	Name      string // CA name (e.g., ca-myorg)
	AdminUser string // enrollment ID for the CA admin
	AdminPass string // enrollment secret for the CA admin
	TLSCert   string // path to CA TLS root cert (empty to skip TLS verify)
	MSPDir    string // base directory for enrolled user MSPs
}

// Configured returns true if the minimum fields for CA integration are set.
func (c CAConfig) Configured() bool {
	return c.URL != "" && c.AdminUser != "" && c.AdminPass != ""
}

// --- LocalProvider ----------------------------------------------------------
// No-op: the registry is the sole source of truth.

// LocalProvider is used when no CA is configured (demo / development).
type LocalProvider struct{}

func (LocalProvider) Register(id, displayName string, claims []string) error { return nil }
func (LocalProvider) Revoke(id string) error                                 { return nil }
func (LocalProvider) Available() bool                                        { return false }

// --- FabricCAProvider -------------------------------------------------------
// Shells out to fabric-ca-client, which handles all the crypto (CSR
// generation, TLS, token auth). This avoids pulling in the end-of-life
// fabric-sdk-go as a Go dependency while reusing the official tooling
// that the federation Docker stack already includes.

// FabricCAProvider registers and revokes identities in a Fabric CA server.
type FabricCAProvider struct {
	cfg     CAConfig
	homeDir string // FABRIC_CA_CLIENT_HOME for admin operations
}

// NewFabricCAProvider creates a provider and enrolls the CA admin to
// validate the connection. Returns an error if fabric-ca-client is not
// installed or the admin enrollment fails.
func NewFabricCAProvider(cfg CAConfig) (*FabricCAProvider, error) {
	if _, err := exec.LookPath("fabric-ca-client"); err != nil {
		return nil, fmt.Errorf("fabric-ca-client not found in PATH: %w", err)
	}

	homeDir := filepath.Join(cfg.MSPDir, "ca-admin")
	if err := os.MkdirAll(homeDir, 0700); err != nil {
		return nil, fmt.Errorf("create CA admin home: %w", err)
	}

	p := &FabricCAProvider{cfg: cfg, homeDir: homeDir}

	// Enroll admin to validate the connection and cache credentials.
	if err := p.enrollAdmin(); err != nil {
		return nil, fmt.Errorf("CA admin enrollment failed: %w", err)
	}
	log.Printf("ca: enrolled admin %q at %s", cfg.AdminUser, cfg.URL)
	return p, nil
}

func (p *FabricCAProvider) Available() bool { return true }

// Register creates an identity in the CA with scope claims as X.509
// attributes, then enrolls it to generate the signed certificate.
func (p *FabricCAProvider) Register(id, displayName string, claims []string) error {
	secret, err := randomHex(16)
	if err != nil {
		return fmt.Errorf("generate secret: %w", err)
	}

	scopeCSV := strings.Join(claims, ",")

	// Register the identity.
	args := []string{
		"register",
		"--caname", p.caName(),
		"--id.name", id,
		"--id.secret", secret,
		"--id.type", "client",
		"--id.attrs", fmt.Sprintf("scopes=%s:ecert,displayName=%s:ecert", scopeCSV, displayName),
		"-u", p.cfg.URL,
		"-H", p.homeDir,
	}
	args = append(args, p.tlsFlags()...)
	if out, err := p.run(args...); err != nil {
		// Tolerate "already registered" — the dashboard may re-save a
		// participant to update their display name or claims.
		if !strings.Contains(out, "already registered") {
			return fmt.Errorf("register %s: %s", id, firstLine(out))
		}
	}

	// Enroll to generate their certificate.
	userMSP := filepath.Join(p.cfg.MSPDir, "users", id, "msp")
	if err := os.MkdirAll(userMSP, 0700); err != nil {
		return fmt.Errorf("create user MSP dir: %w", err)
	}
	enrollArgs := []string{
		"enroll",
		"-u", p.enrollURL(id, secret),
		"--caname", p.caName(),
		"-M", userMSP,
		"--enrollment.attrs", "scopes,displayName",
	}
	enrollArgs = append(enrollArgs, p.tlsFlags()...)
	if out, err := p.run(enrollArgs...); err != nil {
		return fmt.Errorf("enroll %s: %s", id, firstLine(out))
	}

	log.Printf("ca: registered and enrolled %s (scopes: %s)", id, scopeCSV)
	return nil
}

// Revoke disables an identity in the CA.
func (p *FabricCAProvider) Revoke(id string) error {
	args := []string{
		"revoke",
		"-e", id,
		"--caname", p.caName(),
		"-u", p.cfg.URL,
		"-H", p.homeDir,
	}
	args = append(args, p.tlsFlags()...)
	if out, err := p.run(args...); err != nil {
		return fmt.Errorf("revoke %s: %s", id, firstLine(out))
	}
	log.Printf("ca: revoked %s", id)
	return nil
}

// --- internal helpers -------------------------------------------------------

func (p *FabricCAProvider) enrollAdmin() error {
	// Skip if already enrolled.
	if _, err := os.Stat(filepath.Join(p.homeDir, "msp", "signcerts")); err == nil {
		return nil
	}

	args := []string{
		"enroll",
		"-u", p.enrollURL(p.cfg.AdminUser, p.cfg.AdminPass),
		"--caname", p.caName(),
		"-M", filepath.Join(p.homeDir, "msp"),
	}
	args = append(args, p.tlsFlags()...)
	if out, err := p.run(args...); err != nil {
		return fmt.Errorf("%s", firstLine(out))
	}
	return nil
}

func (p *FabricCAProvider) caName() string {
	if p.cfg.Name != "" {
		return p.cfg.Name
	}
	return "ca"
}

func (p *FabricCAProvider) enrollURL(user, secret string) string {
	// Strip scheme for the user:pass@host format.
	base := strings.TrimPrefix(p.cfg.URL, "https://")
	base = strings.TrimPrefix(base, "http://")
	scheme := "https"
	if strings.HasPrefix(p.cfg.URL, "http://") {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%s@%s", scheme, user, secret, base)
}

func (p *FabricCAProvider) tlsFlags() []string {
	if p.cfg.TLSCert != "" {
		return []string{"--tls.certfiles", p.cfg.TLSCert}
	}
	return nil
}

func (p *FabricCAProvider) run(args ...string) (string, error) {
	cmd := exec.Command("fabric-ca-client", args...)
	cmd.Env = append(os.Environ(), "FABRIC_CA_CLIENT_HOME="+p.homeDir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
