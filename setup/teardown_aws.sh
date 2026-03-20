#!/bin/bash
# ============================================================
# AWS IDS Lab — Teardown
# Terminates all instances and deletes VPC resources
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STATE_FILE="$SCRIPT_DIR/lab_state.env"

if [ ! -f "$STATE_FILE" ]; then
    echo "ERROR: $STATE_FILE not found. Nothing to tear down."
    exit 1
fi

source "$STATE_FILE"

echo "============================================================"
echo "AWS IDS Lab — Teardown"
echo "============================================================"
echo "Region: $REGION"
echo "VPC:    $VPC_ID"

# --- Terminate instances ---
echo ""
echo "Terminating instances..."
for INSTANCE_ID in "$IDS_ID" "$VICTIM_ID" "$ATTACKER_ID"; do
    echo "  Terminating $INSTANCE_ID..."
    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" > /dev/null 2>&1 || true
done

echo "Waiting for instances to terminate..."
aws ec2 wait instance-terminated --instance-ids "$IDS_ID" "$VICTIM_ID" "$ATTACKER_ID" --region "$REGION" 2>/dev/null || true

# --- Delete security group ---
echo "Deleting security group $SG_ID..."
aws ec2 delete-security-group --group-id "$SG_ID" --region "$REGION" 2>/dev/null || true

# --- Detach and delete internet gateway ---
echo "Deleting internet gateway $IGW_ID..."
aws ec2 detach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID" --region "$REGION" 2>/dev/null || true
aws ec2 delete-internet-gateway --internet-gateway-id "$IGW_ID" --region "$REGION" 2>/dev/null || true

# --- Delete subnet ---
echo "Deleting subnet $SUBNET_ID..."
aws ec2 delete-subnet --subnet-id "$SUBNET_ID" --region "$REGION" 2>/dev/null || true

# --- Delete VPC ---
echo "Deleting VPC $VPC_ID..."
aws ec2 delete-vpc --vpc-id "$VPC_ID" --region "$REGION" 2>/dev/null || true

# --- Delete key pair (optional) ---
echo "Deleting key pair $KEY_NAME..."
aws ec2 delete-key-pair --key-name "$KEY_NAME" --region "$REGION" 2>/dev/null || true
rm -f "$SCRIPT_DIR/$KEY_NAME.pem"

# --- Cleanup state ---
rm -f "$STATE_FILE"

echo ""
echo "============================================================"
echo "TEARDOWN COMPLETE"
echo "============================================================"
echo "All AWS resources have been deleted."
