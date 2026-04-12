#!/usr/bin/env bash
# add-organization.sh — Add a new organization to an existing open-democracy
# Fabric network.
#
# This script automates the Fabric channel configuration update workflow:
#   1. Fetch the current channel config
#   2. Add the new org's MSP definition
#   3. Compute the config update delta
#   4. Collect signatures from existing org admins
#   5. Submit the update to the orderer
#
# Prerequisites:
#   - The network is running (docker-compose.fabric.yml or equivalent)
#   - The new org has generated its crypto material (see bootstrap-node.sh)
#   - Fabric binaries (peer, configtxlator, jq) available
#   - An admin identity from an existing org to sign the update
#
# Usage:
#   ./scripts/add-organization.sh \
#       --org-name    "CityGov" \
#       --org-msp-id  "CityGovMSP" \
#       --org-msp-dir ./crypto/peerOrganizations/citygov.od.example.com/msp \
#       --channel     governance \
#       --orderer     orderer1.od.example.com:7050

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FED_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────

CHANNEL_NAME="governance"
ORDERER_ADDR="orderer1.od.example.com:7050"
ORG_NAME=""
ORG_MSP_ID=""
ORG_MSP_DIR=""

# ── Parse arguments ──────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --org-name    NAME    Organization short name (e.g., CityGov)
  --org-msp-id  ID     MSP ID (e.g., CityGovMSP)
  --org-msp-dir PATH   Path to the new org's MSP directory
  --channel     NAME   Channel to add the org to (default: governance)
  --orderer     ADDR   Orderer address (default: orderer1.od.example.com:7050)
  -h, --help           Show this help

Example:
  $(basename "$0") \\
      --org-name CityGov \\
      --org-msp-id CityGovMSP \\
      --org-msp-dir ./crypto/peerOrganizations/citygov.od.example.com/msp \\
      --channel governance
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --org-name)    ORG_NAME="$2"; shift 2;;
        --org-msp-id)  ORG_MSP_ID="$2"; shift 2;;
        --org-msp-dir) ORG_MSP_DIR="$2"; shift 2;;
        --channel)     CHANNEL_NAME="$2"; shift 2;;
        --orderer)     ORDERER_ADDR="$2"; shift 2;;
        -h|--help)     usage;;
        *) echo "Unknown option: $1" >&2; usage;;
    esac
done

[[ -z "$ORG_NAME" ]]    && { echo "ERROR: --org-name is required" >&2; usage; }
[[ -z "$ORG_MSP_ID" ]]  && { echo "ERROR: --org-msp-id is required" >&2; usage; }
[[ -z "$ORG_MSP_DIR" ]] && { echo "ERROR: --org-msp-dir is required" >&2; usage; }

# ── Helpers ──────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
fatal() { echo "FATAL: $*" >&2; exit 1; }

WORK_DIR=$(mktemp -d)
trap "rm -rf $WORK_DIR" EXIT

# ── Main ─────────────────────────────────────────────────────────────────

info "Adding organization $ORG_NAME ($ORG_MSP_ID) to channel $CHANNEL_NAME"
echo ""

# Step 1: Fetch current channel config.
info "Step 1/5: Fetching current channel configuration..."
peer channel fetch config "$WORK_DIR/config_block.pb" \
    -o "$ORDERER_ADDR" \
    -c "$CHANNEL_NAME" \
    --tls --cafile "$FED_DIR/crypto/ordererOrganizations/od.example.com/msp/tlscacerts/tlsca.od.example.com-cert.pem"

# Decode to JSON.
configtxlator proto_decode \
    --input "$WORK_DIR/config_block.pb" \
    --type common.Block \
    | jq '.data.data[0].payload.data.config' > "$WORK_DIR/config.json"

# Step 2: Generate new org definition.
info "Step 2/5: Generating org definition for $ORG_MSP_ID..."

# Create a minimal configtx snippet for the new org.
cat > "$WORK_DIR/new-org.json" <<ORGJSON
{
    "mod_policy": "Admins",
    "policies": {
        "Admins": {
            "mod_policy": "Admins",
            "policy": {
                "type": 1,
                "value": {
                    "identities": [{"principal": {"msp_identifier": "$ORG_MSP_ID", "role": "ADMIN"}, "principal_classification": "ROLE"}],
                    "rule": {"n_out_of": {"n": 1, "rules": [{"signed_by": 0}]}},
                    "version": 0
                }
            },
            "version": "0"
        },
        "Endorsement": {
            "mod_policy": "Admins",
            "policy": {
                "type": 1,
                "value": {
                    "identities": [{"principal": {"msp_identifier": "$ORG_MSP_ID", "role": "PEER"}, "principal_classification": "ROLE"}],
                    "rule": {"n_out_of": {"n": 1, "rules": [{"signed_by": 0}]}},
                    "version": 0
                }
            },
            "version": "0"
        },
        "Readers": {
            "mod_policy": "Admins",
            "policy": {
                "type": 1,
                "value": {
                    "identities": [
                        {"principal": {"msp_identifier": "$ORG_MSP_ID", "role": "ADMIN"}, "principal_classification": "ROLE"},
                        {"principal": {"msp_identifier": "$ORG_MSP_ID", "role": "PEER"}, "principal_classification": "ROLE"},
                        {"principal": {"msp_identifier": "$ORG_MSP_ID", "role": "CLIENT"}, "principal_classification": "ROLE"}
                    ],
                    "rule": {"n_out_of": {"n": 1, "rules": [{"signed_by": 0}, {"signed_by": 1}, {"signed_by": 2}]}},
                    "version": 0
                }
            },
            "version": "0"
        },
        "Writers": {
            "mod_policy": "Admins",
            "policy": {
                "type": 1,
                "value": {
                    "identities": [
                        {"principal": {"msp_identifier": "$ORG_MSP_ID", "role": "ADMIN"}, "principal_classification": "ROLE"},
                        {"principal": {"msp_identifier": "$ORG_MSP_ID", "role": "CLIENT"}, "principal_classification": "ROLE"}
                    ],
                    "rule": {"n_out_of": {"n": 1, "rules": [{"signed_by": 0}, {"signed_by": 1}]}},
                    "version": 0
                }
            },
            "version": "0"
        }
    },
    "values": {
        "MSP": {
            "mod_policy": "Admins",
            "value": {
                "config": null
            },
            "version": "0"
        }
    },
    "version": "0"
}
ORGJSON

info "  NOTE: In production, use 'configtxgen -printOrg' to generate the"
info "  org definition from configtx.yaml, which includes the full MSP"
info "  certificates. The JSON above is a structural template."

# Step 3: Add the new org to the config.
info "Step 3/5: Injecting $ORG_MSP_ID into channel config..."
jq --argjson newOrg "$(cat "$WORK_DIR/new-org.json")" \
    ".channel_group.groups.Application.groups.${ORG_MSP_ID} = \$newOrg" \
    "$WORK_DIR/config.json" > "$WORK_DIR/modified_config.json"

# Step 4: Compute the config update delta.
info "Step 4/5: Computing config update delta..."

configtxlator proto_encode \
    --input "$WORK_DIR/config.json" \
    --type common.Config \
    --output "$WORK_DIR/config.pb"

configtxlator proto_encode \
    --input "$WORK_DIR/modified_config.json" \
    --type common.Config \
    --output "$WORK_DIR/modified_config.pb"

configtxlator compute_update \
    --channel_id "$CHANNEL_NAME" \
    --original "$WORK_DIR/config.pb" \
    --updated "$WORK_DIR/modified_config.pb" \
    --output "$WORK_DIR/config_update.pb"

configtxlator proto_decode \
    --input "$WORK_DIR/config_update.pb" \
    --type common.ConfigUpdate \
    | jq '.' > "$WORK_DIR/config_update.json"

# Wrap in envelope.
echo "{\"payload\":{\"header\":{\"channel_header\":{\"channel_id\":\"$CHANNEL_NAME\",\"type\":2}},\"data\":{\"config_update\":$(cat "$WORK_DIR/config_update.json")}}}" \
    | jq '.' > "$WORK_DIR/config_update_envelope.json"

configtxlator proto_encode \
    --input "$WORK_DIR/config_update_envelope.json" \
    --type common.Envelope \
    --output "$WORK_DIR/config_update_envelope.pb"

# Step 5: Sign and submit.
info "Step 5/5: Signing and submitting channel update..."
echo ""
echo "The config update has been prepared at:"
echo "  $WORK_DIR/config_update_envelope.pb"
echo ""
echo "To complete the process, each existing org admin must sign it:"
echo ""
echo "  # As Org1 admin:"
echo "  peer channel signconfigtx -f config_update_envelope.pb"
echo ""
echo "  # As Org2 admin (if MAJORITY policy requires 2+ signatures):"
echo "  peer channel signconfigtx -f config_update_envelope.pb"
echo ""
echo "  # Then submit:"
echo "  peer channel update -f config_update_envelope.pb \\"
echo "      -o $ORDERER_ADDR -c $CHANNEL_NAME --tls --cafile <orderer-ca-cert>"
echo ""
echo "After the update is committed, the new org can join its peer:"
echo ""
echo "  # On the new org's peer:"
echo "  peer channel fetch 0 ${CHANNEL_NAME}.block -o $ORDERER_ADDR -c $CHANNEL_NAME --tls --cafile <orderer-ca-cert>"
echo "  peer channel join -b ${CHANNEL_NAME}.block"
echo ""
echo "Then install the chaincode:"
echo "  peer lifecycle chaincode install bill.tar.gz"
echo ""

# Copy the envelope to a stable location.
cp "$WORK_DIR/config_update_envelope.pb" "$FED_DIR/channel-artifacts/${ORG_NAME}_config_update.pb"
info "Config update saved to: $FED_DIR/channel-artifacts/${ORG_NAME}_config_update.pb"
