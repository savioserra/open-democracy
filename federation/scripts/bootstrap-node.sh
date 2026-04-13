#!/usr/bin/env bash
# bootstrap-node.sh — Prepare a new organization's node to join the
# open-democracy federation.
#
# Legacy script path:
#   odctl now uses federation/democracy.toml as the source of truth.
#   Export a compatibility .env with:
#     ./bin/odctl node setup --persist-env
#
# This script:
#   1. Reads the org configuration from .env
#   2. Generates crypto material (CA bootstrap + peer TLS)
#   3. Creates the directory structure expected by docker-compose.node.yml
#   4. Generates a connection profile from the template
#   5. Prints next steps for joining the federation
#
# Prerequisites:
#   - .env file configured (for example via `./bin/odctl node setup --persist-env`)
#   - Docker installed (for Fabric CA container)
#   - openssl available
#
# Usage:
#   ./bin/odctl node setup --persist-env
#   ./federation/scripts/bootstrap-node.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FED_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Load configuration ───────────────────────────────────────────────────

ENV_FILE="$FED_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: .env file not found at $ENV_FILE"
    echo ""
    echo "Export a compatibility env from odctl:"
    echo "  ./bin/odctl node setup --persist-env"
    exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

# ── Validate required variables ──────────────────────────────────────────

for var in ORG_NAME ORG_DISPLAY ORG_MSP_ID ORG_DOMAIN SCOPE_PREFIX; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is not set in .env"
        exit 1
    fi
done

# ── Helpers ──────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "WARNING: $*" >&2; }

CRYPTO_DIR="$FED_DIR/crypto"

# ── Main ─────────────────────────────────────────────────────────────────

info "Open Democracy Federation — Node Bootstrap"
echo ""
echo "  Organization:  $ORG_DISPLAY"
echo "  MSP ID:        $ORG_MSP_ID"
echo "  Domain:        $ORG_DOMAIN"
echo "  Scope prefix:  $SCOPE_PREFIX"
echo ""

# Step 1: Create directory structure.
info "Step 1/4: Creating directory structure..."
mkdir -p "$CRYPTO_DIR/ca"
mkdir -p "$CRYPTO_DIR/peers/peer0/msp/admincerts"
mkdir -p "$CRYPTO_DIR/peers/peer0/msp/cacerts"
mkdir -p "$CRYPTO_DIR/peers/peer0/msp/keystore"
mkdir -p "$CRYPTO_DIR/peers/peer0/msp/signcerts"
mkdir -p "$CRYPTO_DIR/peers/peer0/msp/tlscacerts"
mkdir -p "$CRYPTO_DIR/peers/peer0/tls"
mkdir -p "$CRYPTO_DIR/msp/admincerts"
mkdir -p "$CRYPTO_DIR/msp/cacerts"
mkdir -p "$CRYPTO_DIR/msp/tlscacerts"
mkdir -p "$CRYPTO_DIR/users"

# Step 2: Generate self-signed CA certificate (for development/testing).
# In production, use fabric-ca-server init with proper PKI.
info "Step 2/4: Generating CA certificates..."

if [ ! -f "$CRYPTO_DIR/ca/ca-cert.pem" ]; then
    openssl ecparam -genkey -name prime256v1 -noout \
        -out "$CRYPTO_DIR/ca/ca-key.pem" 2>/dev/null

    openssl req -new -x509 -key "$CRYPTO_DIR/ca/ca-key.pem" \
        -out "$CRYPTO_DIR/ca/ca-cert.pem" \
        -days 3650 \
        -subj "/C=BR/ST=Federation/O=$ORG_DISPLAY/CN=ca.$ORG_DOMAIN" 2>/dev/null

    # Copy CA cert to MSP locations.
    cp "$CRYPTO_DIR/ca/ca-cert.pem" "$CRYPTO_DIR/peers/peer0/msp/cacerts/"
    cp "$CRYPTO_DIR/ca/ca-cert.pem" "$CRYPTO_DIR/msp/cacerts/"
    info "  CA cert: $CRYPTO_DIR/ca/ca-cert.pem"
else
    info "  CA cert already exists, skipping."
fi

# Step 3: Generate peer TLS certificate.
info "Step 3/4: Generating peer TLS certificates..."

if [ ! -f "$CRYPTO_DIR/peers/peer0/tls/server.crt" ]; then
    openssl ecparam -genkey -name prime256v1 -noout \
        -out "$CRYPTO_DIR/peers/peer0/tls/server.key" 2>/dev/null

    openssl req -new -key "$CRYPTO_DIR/peers/peer0/tls/server.key" \
        -out "$CRYPTO_DIR/peers/peer0/tls/server.csr" \
        -subj "/C=BR/ST=Federation/O=$ORG_DISPLAY/CN=peer0.$ORG_DOMAIN" 2>/dev/null

    # Create a SAN extension file for the TLS cert.
    cat > "$CRYPTO_DIR/peers/peer0/tls/san.cnf" <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = peer0.$ORG_DOMAIN
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

    openssl x509 -req \
        -in "$CRYPTO_DIR/peers/peer0/tls/server.csr" \
        -CA "$CRYPTO_DIR/ca/ca-cert.pem" \
        -CAkey "$CRYPTO_DIR/ca/ca-key.pem" \
        -CAcreateserial \
        -out "$CRYPTO_DIR/peers/peer0/tls/server.crt" \
        -days 3650 \
        -extensions v3_req \
        -extfile "$CRYPTO_DIR/peers/peer0/tls/san.cnf" 2>/dev/null

    cp "$CRYPTO_DIR/ca/ca-cert.pem" "$CRYPTO_DIR/peers/peer0/tls/ca.crt"
    cp "$CRYPTO_DIR/ca/ca-cert.pem" "$CRYPTO_DIR/peers/peer0/msp/tlscacerts/"
    cp "$CRYPTO_DIR/ca/ca-cert.pem" "$CRYPTO_DIR/msp/tlscacerts/"

    # Clean up CSR and temp files.
    rm -f "$CRYPTO_DIR/peers/peer0/tls/server.csr" "$CRYPTO_DIR/peers/peer0/tls/san.cnf"

    info "  TLS cert: $CRYPTO_DIR/peers/peer0/tls/server.crt"
else
    info "  TLS cert already exists, skipping."
fi

# Step 4: Generate connection profile.
info "Step 4/4: Generating connection profile..."

PROFILE_OUT="$FED_DIR/connection-profile.yaml"
sed \
    -e "s/\${ORG_NAME}/$ORG_NAME/g" \
    -e "s/\${ORG_MSP_ID}/$ORG_MSP_ID/g" \
    -e "s/\${ORG_DOMAIN}/$ORG_DOMAIN/g" \
    -e "s/\${CHANNEL_NAME}/${CHANNEL_NAME:-governance}/g" \
    -e "s/\${PEER_PORT}/${PEER_PORT:-7051}/g" \
    -e "s/\${CA_PORT}/${CA_PORT:-7054}/g" \
    -e "s/\${CA_ADMIN_USER}/${CA_ADMIN_USER:-admin}/g" \
    -e "s/\${CA_ADMIN_PASS}/${CA_ADMIN_PASS:-adminpw}/g" \
    "$FED_DIR/config/connection-profile-template.yaml" > "$PROFILE_OUT"

info "  Connection profile: $PROFILE_OUT"

# ── Summary ──────────────────────────────────────────────────────────────

echo ""
echo "================================================================"
echo "  Node bootstrap complete for: $ORG_DISPLAY"
echo "================================================================"
echo ""
echo "Directory structure:"
echo "  $CRYPTO_DIR/"
echo "  ├── ca/            CA certificate and key"
echo "  ├── peers/peer0/   Peer MSP and TLS material"
echo "  ├── msp/           Organization-level MSP"
echo "  └── users/         (populated by register-participants.sh)"
echo ""
echo "Next steps:"
echo ""
echo "  1. Start your node:"
echo "       docker compose -f docker-compose.node.yml up -d"
echo ""
echo "  2. Request federation membership:"
echo "       Share your MSP directory ($CRYPTO_DIR/msp/) with an existing"
echo "       federation admin. They will run:"
echo "         ./scripts/add-organization.sh \\"
echo "             --org-name $ORG_NAME \\"
echo "             --org-msp-id $ORG_MSP_ID \\"
echo "             --org-msp-dir <path-to-your-msp>"
echo ""
echo "  3. Once approved, join the channel:"
echo "       peer channel fetch 0 governance.block \\"
echo "           -o \${ORDERER_ADDRESS} -c governance --tls --cafile <orderer-ca>"
echo "       peer channel join -b governance.block"
echo ""
echo "  4. Install the chaincode:"
echo "       peer lifecycle chaincode install bill.tar.gz"
echo ""
echo "  5. Register your participants:"
echo "       ./scripts/register-participants.sh participants.csv"
echo ""
echo "  Example participants.csv for scope prefix '$SCOPE_PREFIX':"
echo "    admin,\"$ORG_DISPLAY Admin\",$SCOPE_PREFIX:ADMIN"
echo "    proposer,\"Proposer\",$SCOPE_PREFIX:PROPOSER"
echo "    voter1,\"Voter 1\",$SCOPE_PREFIX:VOTER"
echo ""
