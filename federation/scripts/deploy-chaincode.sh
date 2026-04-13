#!/usr/bin/env bash
# deploy-chaincode.sh — Package and deploy the bill chaincode to the
# open-democracy Fabric network.
#
# Uses the Fabric 2.x lifecycle: package → install → approve → commit.
# The endorsement policy requires MAJORITY of member organizations,
# ensuring no single org can unilaterally update the ledger.
#
# Prerequisites:
#   - Network running from a generated founding-network run
#   - Peers joined to the channel
#   - peer CLI with correct environment variables
#
# Usage:
#   source federation/runs/<instance>/run.env
#   ./scripts/deploy-chaincode.sh [--channel governance] [--version 1.0] [--sequence 1]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FED_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$FED_DIR/.." && pwd)"
NETWORK_DIR="${NETWORK_DIR:-$FED_DIR}"
CRYPTO_DIR="${CRYPTO_DIR:-$NETWORK_DIR/crypto}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$NETWORK_DIR/channel-artifacts}"

# ── Defaults ─────────────────────────────────────────────────────────────

CHANNEL_NAME="${1:-governance}"
CC_NAME="bill"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQUENCE="${CC_SEQUENCE:-1}"
CC_SRC_PATH="$REPO_ROOT/chaincode/bill"
CC_LABEL="${CC_NAME}_${CC_VERSION}"

ORDERER_ADDR="${ORDERER_ADDR:-orderer1.od.example.com:7050}"
ORDERER_CA="${ORDERER_CA:-$CRYPTO_DIR/ordererOrganizations/od.example.com/msp/tlscacerts/tlsca.od.example.com-cert.pem}"

# ── Parse arguments ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --channel)  CHANNEL_NAME="$2"; shift 2;;
        --version)  CC_VERSION="$2"; CC_LABEL="${CC_NAME}_${CC_VERSION}"; shift 2;;
        --sequence) CC_SEQUENCE="$2"; shift 2;;
        *) shift;;
    esac
done

# ── Helpers ──────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
fatal() { echo "FATAL: $*" >&2; exit 1; }

require_generated_run() {
    if [ ! -f "$ORDERER_CA" ]; then
        fatal "Missing orderer TLS CA at $ORDERER_CA

Source federation/runs/<instance>/run.env or set NETWORK_DIR/CRYPTO_DIR/ORDERER_CA
to an active generated founding-network run before using this script."
    fi
    mkdir -p "$ARTIFACTS_DIR"
}

WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

# ── Main ─────────────────────────────────────────────────────────────────

info "Deploying chaincode '$CC_NAME' v$CC_VERSION (seq $CC_SEQUENCE) to channel '$CHANNEL_NAME'"
echo ""

require_generated_run

# Step 1: Package the chaincode.
info "Step 1/4: Packaging chaincode..."
peer lifecycle chaincode package "$WORK_DIR/${CC_LABEL}.tar.gz" \
    --path "$CC_SRC_PATH" \
    --lang golang \
    --label "$CC_LABEL"

info "  Package: $WORK_DIR/${CC_LABEL}.tar.gz"

# Step 2: Install on all peers.
info "Step 2/4: Installing chaincode on peers..."
echo ""
echo "Install the package on each organization's peer(s):"
echo ""
echo "  # As Org1 admin (OpenDemocracy):"
echo "  export CORE_PEER_LOCALMSPID=OpenDemocracyMSP"
echo "  export CORE_PEER_ADDRESS=peer0.opendemocracy.od.example.com:7051"
echo "  export CORE_PEER_MSPCONFIGPATH=\$FED_DIR/crypto/peerOrganizations/opendemocracy.od.example.com/users/Admin@opendemocracy.od.example.com/msp"
echo "  peer lifecycle chaincode install ${CC_LABEL}.tar.gz"
echo ""
echo "  # As Org2 admin (ExampleGov):"
echo "  export CORE_PEER_LOCALMSPID=ExampleGovMSP"
echo "  export CORE_PEER_ADDRESS=peer0.examplegov.od.example.com:7051"
echo "  export CORE_PEER_MSPCONFIGPATH=\$FED_DIR/crypto/peerOrganizations/examplegov.od.example.com/users/Admin@examplegov.od.example.com/msp"
echo "  peer lifecycle chaincode install ${CC_LABEL}.tar.gz"
echo ""

# Try to install on the first peer (if environment is configured).
if peer lifecycle chaincode install "$WORK_DIR/${CC_LABEL}.tar.gz" 2>/dev/null; then
    info "  Installed on current peer"

    # Query installed to get package ID.
    PACKAGE_ID=$(peer lifecycle chaincode queryinstalled 2>&1 | grep "$CC_LABEL" | awk '{print $3}' | tr -d ',')
    info "  Package ID: $PACKAGE_ID"
else
    echo "  (Skipping auto-install — configure peer environment and run manually)"
    echo ""
    echo "After installing, query the package ID:"
    echo "  peer lifecycle chaincode queryinstalled"
    echo ""
    PACKAGE_ID="\${PACKAGE_ID}"
fi

# Step 3: Approve for each org.
info "Step 3/4: Approving chaincode definition..."
echo ""
echo "Each organization must approve the chaincode definition:"
echo ""
echo "  peer lifecycle chaincode approveformyorg \\"
echo "      -o $ORDERER_ADDR --tls --cafile $ORDERER_CA \\"
echo "      --channelID $CHANNEL_NAME \\"
echo "      --name $CC_NAME \\"
echo "      --version $CC_VERSION \\"
echo "      --package-id $PACKAGE_ID \\"
echo "      --sequence $CC_SEQUENCE \\"
echo "      --signature-policy \"OutOf($(echo 'MAJORITY' | tr '[:lower:]' '[:upper:]'), 'OpenDemocracyMSP.peer', 'ExampleGovMSP.peer')\""
echo ""

# Step 4: Commit the chaincode definition.
info "Step 4/4: Committing chaincode definition..."
echo ""
echo "Once all orgs have approved, commit the definition:"
echo ""
echo "  peer lifecycle chaincode commit \\"
echo "      -o $ORDERER_ADDR --tls --cafile $ORDERER_CA \\"
echo "      --channelID $CHANNEL_NAME \\"
echo "      --name $CC_NAME \\"
echo "      --version $CC_VERSION \\"
echo "      --sequence $CC_SEQUENCE \\"
echo "      --peerAddresses peer0.opendemocracy.od.example.com:7051 \\"
echo "      --tlsRootCertFiles $FED_DIR/crypto/peerOrganizations/opendemocracy.od.example.com/peers/peer0.opendemocracy.od.example.com/tls/ca.crt \\"
echo "      --peerAddresses peer0.examplegov.od.example.com:7051 \\"
echo "      --tlsRootCertFiles $FED_DIR/crypto/peerOrganizations/examplegov.od.example.com/peers/peer0.examplegov.od.example.com/tls/ca.crt"
echo ""
echo "Verify:"
echo "  peer lifecycle chaincode querycommitted --channelID $CHANNEL_NAME --name $CC_NAME"
echo ""

# Save the package for distribution to other orgs.
cp "$WORK_DIR/${CC_LABEL}.tar.gz" "$ARTIFACTS_DIR/${CC_LABEL}.tar.gz" 2>/dev/null || true
info "Chaincode package saved to: $ARTIFACTS_DIR/${CC_LABEL}.tar.gz"
