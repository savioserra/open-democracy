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
#   cd federation/
#   ./scripts/bootstrap-network.sh
#
# After this script completes, start the network with:
#   docker compose -f docker-compose.fabric.yml up -d

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FED_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$FED_DIR/config"
CRYPTO_DIR="$FED_DIR/crypto"
ARTIFACTS_DIR="$FED_DIR/channel-artifacts"

# Fabric binary location — override with FABRIC_BIN env var.
FABRIC_BIN="${FABRIC_BIN:-$(command -v cryptogen >/dev/null 2>&1 && dirname "$(command -v cryptogen)" || echo "")}"

CHANNEL_NAME="${CHANNEL_NAME:-governance}"

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
    for org in OpenDemocracy ExampleGov; do
        info "Generating anchor peer update for $org..."
        fabric_cmd configtxgen \
            -profile GovernanceChannel \
            -outputAnchorPeersUpdate "$ARTIFACTS_DIR/${org}MSPanchors.tx" \
            -channelID "$CHANNEL_NAME" \
            -asOrg "${org}MSP" 2>/dev/null || \
        warn "Anchor peer update for $org skipped (may require Fabric 2.5+ configtxgen)"
    done

    echo ""
    info "Network bootstrap complete."
    echo ""
    echo "Next steps:"
    echo "  1. Start the network:"
    echo "       cd $FED_DIR"
    echo "       docker compose -f docker-compose.fabric.yml up -d"
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
    echo "  Crypto:   $CRYPTO_DIR"
    echo "  Genesis:  $ARTIFACTS_DIR/genesis.block"
    echo "  Channel:  $ARTIFACTS_DIR/${CHANNEL_NAME}.tx"
}

main "$@"
