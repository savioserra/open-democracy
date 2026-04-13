#!/usr/bin/env bash
# bootstrap-network.sh — Initialize a new open-democracy Fabric network.
#
# This script generates crypto material, creates the genesis block and
# channel transaction, and prepares everything needed to bring up the
# multi-org federation with docker compose.
#
# Prerequisites:
#   - Hyperledger Fabric binaries (cryptogen, configtxgen) in PATH
#     or set FABRIC_BIN to the directory containing them.
#   - Docker and Docker Compose installed.
#
# Usage:
#   ./bin/odctl network start
#
# Direct invocation (advanced):
#   NETWORK_DIR=./federation/runs/<instance> ./federation/scripts/bootstrap-network.sh
#
# Optional overrides: NETWORK_DIR, CONFIG_DIR, CRYPTO_DIR, ARTIFACTS_DIR,
# COMPOSE_FILE, COMPOSE_PROJECT_NAME, FOUNDING_ORG_MSPS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FED_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NETWORK_DIR="${NETWORK_DIR:-$FED_DIR}"
CONFIG_DIR="${CONFIG_DIR:-$NETWORK_DIR/config}"
CRYPTO_DIR="${CRYPTO_DIR:-$NETWORK_DIR/crypto}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$NETWORK_DIR/channel-artifacts}"
COMPOSE_FILE="${COMPOSE_FILE:-$NETWORK_DIR/docker-compose.fabric.yml}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-}"

# Fabric binary location — override with FABRIC_BIN env var.
FABRIC_BIN="${FABRIC_BIN:-$(command -v cryptogen >/dev/null 2>&1 && dirname "$(command -v cryptogen)" || echo "")}"

CHANNEL_NAME="${CHANNEL_NAME:-governance}"
FOUNDING_ORG_MSPS="${FOUNDING_ORG_MSPS:-}"

# ── Helpers ──────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "WARNING: $*" >&2; }
fatal() { echo "FATAL: $*" >&2; exit 1; }

check_prereqs() {
    local missing=()

    for bin in cryptogen configtxgen; do
        if [ -n "$FABRIC_BIN" ]; then
            if [ ! -x "$FABRIC_BIN/$bin" ]; then
                missing+=("$bin")
            fi
        else
            if ! command -v "$bin" &>/dev/null; then
                missing+=("$bin")
            fi
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        fatal "Missing Fabric binaries: ${missing[*]}
Install Fabric binaries:
  curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
  chmod +x install-fabric.sh
  ./install-fabric.sh --fabric-version 2.5.0 binary
Then either add them to PATH or set FABRIC_BIN=/path/to/fabric-samples/bin"
    fi

    if ! command -v docker &>/dev/null; then
        fatal "Docker is required but not found."
    fi
}

check_generated_files() {
    local missing=()
    for path in \
        "$CONFIG_DIR/crypto-config.yaml" \
        "$CONFIG_DIR/configtx.yaml" \
        "$COMPOSE_FILE"; do
        if [ ! -f "$path" ]; then
            missing+=("$path")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        fatal "Missing generated founding-network files:
  ${missing[*]}

Run './bin/odctl network start' to generate an isolated run, or set NETWORK_DIR
to an existing federation/runs/<instance> directory before invoking this script."
    fi
}

fabric_cmd() {
    local cmd="$1"; shift
    if [ -n "$FABRIC_BIN" ]; then
        "$FABRIC_BIN/$cmd" "$@"
    else
        "$cmd" "$@"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────

main() {
    info "Open Democracy Federation — Network Bootstrap"
    echo ""

    check_prereqs
    check_generated_files

    # Clean previous artifacts.
    if [ -d "$CRYPTO_DIR" ]; then
        warn "Removing existing crypto material at $CRYPTO_DIR"
        rm -rf "$CRYPTO_DIR"
    fi
    if [ -d "$ARTIFACTS_DIR" ]; then
        rm -rf "$ARTIFACTS_DIR"
    fi
    mkdir -p "$ARTIFACTS_DIR"

    # 1. Generate crypto material.
    info "Generating crypto material (cryptogen)..."
    fabric_cmd cryptogen generate \
        --config="$CONFIG_DIR/crypto-config.yaml" \
        --output="$CRYPTO_DIR"

    info "Crypto material generated at $CRYPTO_DIR"

    # 2. Generate genesis block.
    info "Generating genesis block..."
    export FABRIC_CFG_PATH="$CONFIG_DIR"
    fabric_cmd configtxgen \
        -profile FederationGenesis \
        -channelID system-channel \
        -outputBlock "$ARTIFACTS_DIR/genesis.block"

    # 3. Generate channel creation transaction.
    info "Generating channel transaction for '$CHANNEL_NAME'..."
    fabric_cmd configtxgen \
        -profile GovernanceChannel \
        -outputCreateChannelTx "$ARTIFACTS_DIR/${CHANNEL_NAME}.tx" \
        -channelID "$CHANNEL_NAME"

    # 4. Generate anchor peer updates for each org.
    local founding_orgs=()
    if [ -n "$FOUNDING_ORG_MSPS" ]; then
        IFS=',' read -r -a founding_orgs <<< "$FOUNDING_ORG_MSPS"
    else
        founding_orgs=(OpenDemocracyMSP ExampleGovMSP)
    fi
    for org in "${founding_orgs[@]}"; do
        [ -z "$org" ] && continue
        info "Generating anchor peer update for $org..."
        fabric_cmd configtxgen \
            -profile GovernanceChannel \
            -outputAnchorPeersUpdate "$ARTIFACTS_DIR/${org}anchors.tx" \
            -channelID "$CHANNEL_NAME" \
            -asOrg "$org" 2>/dev/null || \
        warn "Anchor peer update for $org skipped (may require Fabric 2.5+ configtxgen)"
    done

    local compose_cmd="docker compose"
    if [ -n "$COMPOSE_PROJECT_NAME" ]; then
        compose_cmd="$compose_cmd -p $COMPOSE_PROJECT_NAME"
    fi
    compose_cmd="$compose_cmd -f $COMPOSE_FILE up -d"

    echo ""
    info "Network bootstrap complete."
    echo ""
    echo "Next steps:"
    echo "  1. Start the network:"
    echo "       $compose_cmd"
    echo ""
    echo "  2. Create the governance channel:"
    echo "       ./scripts/create-channel.sh"
    echo ""
    echo "  3. Deploy the bill chaincode:"
    echo "       ./scripts/deploy-chaincode.sh"
    echo ""
    echo "  4. Register participants with scope claims:"
    echo "       ./scripts/register-participants.sh"
    echo ""
    echo "Generated artifacts:"
    echo "  Run dir:  $NETWORK_DIR"
    echo "  Config:   $CONFIG_DIR"
    echo "  Crypto:   $CRYPTO_DIR"
    echo "  Genesis:  $ARTIFACTS_DIR/genesis.block"
    echo "  Channel:  $ARTIFACTS_DIR/${CHANNEL_NAME}.tx"
}

main "$@"
