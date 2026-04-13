#!/usr/bin/env bash
# register-participants.sh — Register users with scope-attributed X.509
# certificates on a Fabric CA.
#
# This script enrolls the CA admin, then registers and enrolls participants
# with the correct scope attributes so that open-democracy's Invoker can
# parse their authority from the certificate.
#
# Prerequisites:
#   - Fabric CA client (fabric-ca-client) in PATH
#   - The organization's CA is running
#   - The .env file is exported from odctl (use `./bin/odctl node setup --persist-env`)
#
# Usage:
#   # Export and source your org's environment
#   ./bin/odctl node setup --persist-env
#   source .env
#
#   # Register participants from a CSV file:
#   ./scripts/register-participants.sh participants.csv
#
# CSV format (no header):
#   user_id,display_name,scope_claims
#   mayor,"Mayor João",GOV:CITY:ADMIN
#   health_dir,"Dr. Maria",GOV:CITY:HEALTH:ADMIN
#   nurse_ana,"Ana (nurse)",GOV:CITY:HEALTH:VOTER
#
# Multiple scope claims are separated by semicolons:
#   alice,"Alice",OPENDEMOCRACY:CORE:PROPOSER;OPENDEMOCRACY:COMMUNITY:ADMIN

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Configuration from environment ───────────────────────────────────────

CA_URL="${CA_URL:-https://localhost:${CA_PORT:-7054}}"
CA_NAME="${CA_NAME:-ca-${ORG_NAME:-my-org}}"
CA_ADMIN_USER="${CA_ADMIN_USER:-admin}"
CA_ADMIN_PASS="${CA_ADMIN_PASS:-adminpw}"
CA_TLS_CERTFILE="${CA_TLS_CERTFILE:-}"
MSP_DIR="${MSP_DIR:-./msp}"

# ── Helpers ──────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "WARNING: $*" >&2; }
fatal() { echo "FATAL: $*" >&2; exit 1; }

TLS_FLAG=""
if [ -n "$CA_TLS_CERTFILE" ]; then
    TLS_FLAG="--tls.certfiles $CA_TLS_CERTFILE"
fi

# ── Enroll CA admin ──────────────────────────────────────────────────────

enroll_admin() {
    info "Enrolling CA admin ($CA_ADMIN_USER)..."

    export FABRIC_CA_CLIENT_HOME="$MSP_DIR/admin"
    mkdir -p "$FABRIC_CA_CLIENT_HOME"

    fabric-ca-client enroll \
        -u "https://${CA_ADMIN_USER}:${CA_ADMIN_PASS}@${CA_URL#https://}" \
        --caname "$CA_NAME" \
        $TLS_FLAG \
        -M "$FABRIC_CA_CLIENT_HOME/msp" 2>&1 || fatal "Failed to enroll CA admin"

    info "CA admin enrolled at $FABRIC_CA_CLIENT_HOME/msp"
}

# ── Register and enroll a single participant ─────────────────────────────

register_participant() {
    local user_id="$1"
    local display_name="$2"
    local scope_claims="$3"  # semicolon-separated

    info "Registering $user_id ($display_name)..."

    # Convert semicolons to commas for the X.509 scopes attribute.
    # The Invoker reads the "scopes" attribute as CSV.
    local scopes_csv
    scopes_csv="$(echo "$scope_claims" | tr ';' ',')"

    # Generate a random enrollment secret.
    local secret
    secret="$(openssl rand -hex 16)"

    export FABRIC_CA_CLIENT_HOME="$MSP_DIR/admin"

    # Register the user with scope attributes.
    # The --id.attrs flag sets X.509 certificate attributes that the
    # chaincode's GetInvoker() reads via cid.GetAttributeValue().
    fabric-ca-client register \
        --caname "$CA_NAME" \
        --id.name "$user_id" \
        --id.secret "$secret" \
        --id.type client \
        --id.attrs "scopes=$scopes_csv:ecert,displayName=$display_name:ecert" \
        $TLS_FLAG \
        -M "$FABRIC_CA_CLIENT_HOME/msp" 2>&1 || {
            warn "Registration failed for $user_id (may already exist)"
            return 0
        }

    # Enroll the user to generate their certificate.
    local user_msp="$MSP_DIR/users/$user_id"
    mkdir -p "$user_msp"

    fabric-ca-client enroll \
        -u "https://${user_id}:${secret}@${CA_URL#https://}" \
        --caname "$CA_NAME" \
        $TLS_FLAG \
        -M "$user_msp/msp" \
        --enrollment.attrs "scopes,displayName" 2>&1 || {
            warn "Enrollment failed for $user_id"
            return 0
        }

    info "  Enrolled $user_id → $user_msp/msp"
    info "  Scope claims: $scopes_csv"
}

# ── Process CSV file ─────────────────────────────────────────────────────

process_csv() {
    local csv_file="$1"

    if [ ! -f "$csv_file" ]; then
        fatal "CSV file not found: $csv_file"
    fi

    local count=0
    while IFS=',' read -r user_id display_name scope_claims; do
        # Skip empty lines and comments.
        [[ -z "$user_id" || "$user_id" == \#* ]] && continue

        # Strip surrounding quotes.
        user_id="$(echo "$user_id" | tr -d '"' | xargs)"
        display_name="$(echo "$display_name" | tr -d '"' | xargs)"
        scope_claims="$(echo "$scope_claims" | tr -d '"' | xargs)"

        register_participant "$user_id" "$display_name" "$scope_claims"
        ((count++))
    done < "$csv_file"

    info "Registered $count participants from $csv_file"
}

# ── Interactive mode (no CSV) ────────────────────────────────────────────

interactive_register() {
    echo ""
    echo "Interactive participant registration"
    echo "Enter 'done' for user_id to finish."
    echo ""

    while true; do
        read -rp "User ID: " user_id
        [[ "$user_id" == "done" || -z "$user_id" ]] && break

        read -rp "Display name: " display_name
        read -rp "Scope claims (semicolon-separated, e.g., GOV:CITY:ADMIN;GOV:CITY:VOTER): " scope_claims

        register_participant "$user_id" "$display_name" "$scope_claims"
        echo ""
    done
}

# ── Main ─────────────────────────────────────────────────────────────────

main() {
    info "Open Democracy — Participant Registration"
    echo ""

    if ! command -v fabric-ca-client &>/dev/null; then
        fatal "fabric-ca-client not found. Install Fabric CA client:
  curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
  chmod +x install-fabric.sh
  ./install-fabric.sh --fabric-version 2.5.0 ca"
    fi

    enroll_admin

    if [ $# -ge 1 ] && [ -f "$1" ]; then
        process_csv "$1"
    else
        echo ""
        echo "Usage: $0 <participants.csv>"
        echo ""
        echo "CSV format (no header):"
        echo "  user_id,\"Display Name\",SCOPE1:ROLE;SCOPE2:ROLE"
        echo ""
        echo "Example participants.csv:"
        echo "  mayor,\"Mayor João\",GOV:CITY:ADMIN"
        echo "  health_dir,\"Dr. Maria\",GOV:CITY:HEALTH:ADMIN"
        echo "  nurse_ana,\"Ana (nurse)\",GOV:CITY:HEALTH:VOTER"
        echo "  teacher_carlos,\"Carlos\",UNION:TEACHERS:SP:VOTER;UNION:TEACHERS:SP:PROPOSER"
        echo ""

        read -rp "No CSV provided. Start interactive registration? [y/N] " answer
        if [[ "$answer" =~ ^[Yy] ]]; then
            interactive_register
        fi
    fi
}

main "$@"
