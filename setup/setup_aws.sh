#!/bin/bash
# ============================================================
# AWS IDS Lab — Infrastructure Setup
# Creates VPC, subnet, security group, and 3 EC2 instances
# ============================================================
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
KEY_NAME="${KEY_NAME:-ids-lab-key}"
AMI_ID="${AMI_ID:-ami-04680790a315cd58d}"  # Ubuntu 22.04 us-east-1 (2026-02)
IDS_INSTANCE_TYPE="t3.xlarge"
ATTACKER_INSTANCE_TYPE="t3.small"
VICTIM_INSTANCE_TYPE="t3.micro"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
STATE_FILE="$SCRIPT_DIR/lab_state.env"

echo "============================================================"
echo "AWS IDS Lab — Setup"
echo "============================================================"
echo "Region: $REGION"
echo "Key:    $KEY_NAME"

# Get user's public IP for SSH access
MY_IP=$(curl -s https://checkip.amazonaws.com)/32
echo "Your IP: $MY_IP"

# --- VPC ---
echo ""
echo "Creating VPC..."
VPC_ID=$(aws ec2 create-vpc \
    --cidr-block 10.0.1.0/24 \
    --region "$REGION" \
    --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=ids-lab-vpc}]' \
    --query 'Vpc.VpcId' --output text)
echo "  VPC: $VPC_ID"

# Enable DNS
aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-support '{"Value":true}' --region "$REGION"
aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-hostnames '{"Value":true}' --region "$REGION"

# --- Subnet ---
echo "Creating subnet..."
SUBNET_ID=$(aws ec2 create-subnet \
    --vpc-id "$VPC_ID" \
    --cidr-block 10.0.1.0/24 \
    --region "$REGION" \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=ids-lab-subnet}]' \
    --query 'Subnet.SubnetId' --output text)
echo "  Subnet: $SUBNET_ID"

# --- Internet Gateway ---
echo "Creating internet gateway..."
IGW_ID=$(aws ec2 create-internet-gateway \
    --region "$REGION" \
    --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=ids-lab-igw}]' \
    --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID" --region "$REGION"
echo "  IGW: $IGW_ID"

# --- Route Table ---
echo "Creating route table..."
RTB_ID=$(aws ec2 describe-route-tables \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --region "$REGION" \
    --query 'RouteTables[0].RouteTableId' --output text)
aws ec2 create-route --route-table-id "$RTB_ID" --destination-cidr-block 0.0.0.0/0 \
    --gateway-id "$IGW_ID" --region "$REGION" > /dev/null
aws ec2 associate-route-table --route-table-id "$RTB_ID" --subnet-id "$SUBNET_ID" --region "$REGION" > /dev/null
echo "  Route table: $RTB_ID"

# --- Security Group ---
echo "Creating security group..."
SG_ID=$(aws ec2 create-security-group \
    --group-name ids-lab-sg \
    --description "IDS Lab - all internal + SSH from user" \
    --vpc-id "$VPC_ID" \
    --region "$REGION" \
    --query 'GroupId' --output text)

# SSH from user's IP
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr "$MY_IP" --region "$REGION" > /dev/null

# Dashboard from user's IP
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol tcp --port 8000 --cidr "$MY_IP" --region "$REGION" > /dev/null

# All traffic within VPC
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol -1 --cidr 10.0.1.0/24 --region "$REGION" > /dev/null

echo "  SG: $SG_ID"

# --- Key Pair ---
echo "Creating key pair..."
if ! aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" > /dev/null 2>&1; then
    aws ec2 create-key-pair --key-name "$KEY_NAME" --region "$REGION" \
        --query 'KeyMaterial' --output text > "$SCRIPT_DIR/$KEY_NAME.pem"
    chmod 400 "$SCRIPT_DIR/$KEY_NAME.pem"
    echo "  Key saved: $SCRIPT_DIR/$KEY_NAME.pem"
else
    echo "  Key $KEY_NAME already exists"
fi

# --- Launch IDS Server (on-demand, public IP) ---
echo ""
echo "Launching IDS Server (t3.xlarge, on-demand)..."
IDS_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$IDS_INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SG_ID" \
    --private-ip-address 10.0.1.30 \
    --associate-public-ip-address \
    --user-data "file://$SCRIPT_DIR/user_data_ids.sh" \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ids-lab-ids}]' \
    --region "$REGION" \
    --query 'Instances[0].InstanceId' --output text)
echo "  IDS: $IDS_ID (10.0.1.30)"

# --- Launch Victim (spot) ---
echo "Launching Victim (t3.micro, spot)..."
VICTIM_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$VICTIM_INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SG_ID" \
    --private-ip-address 10.0.1.20 \
    --instance-market-options '{"MarketType":"spot","SpotOptions":{"SpotInstanceType":"one-time"}}' \
    --user-data "file://$SCRIPT_DIR/user_data_victim.sh" \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ids-lab-victim}]' \
    --region "$REGION" \
    --query 'Instances[0].InstanceId' --output text)
echo "  Victim: $VICTIM_ID (10.0.1.20)"

# --- Launch Attacker (spot) ---
echo "Launching Attacker (t3.small, spot)..."
ATTACKER_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$ATTACKER_INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --subnet-id "$SUBNET_ID" \
    --security-group-ids "$SG_ID" \
    --private-ip-address 10.0.1.10 \
    --instance-market-options '{"MarketType":"spot","SpotOptions":{"SpotInstanceType":"one-time"}}' \
    --user-data "file://$SCRIPT_DIR/user_data_attacker.sh" \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ids-lab-attacker}]' \
    --region "$REGION" \
    --query 'Instances[0].InstanceId' --output text)
echo "  Attacker: $ATTACKER_ID (10.0.1.10)"

# --- Wait for IDS public IP ---
echo ""
echo "Waiting for IDS server public IP..."
aws ec2 wait instance-running --instance-ids "$IDS_ID" --region "$REGION"
IDS_PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$IDS_ID" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "  IDS Public IP: $IDS_PUBLIC_IP"

# --- Save state ---
cat > "$STATE_FILE" <<EOF
REGION=$REGION
VPC_ID=$VPC_ID
SUBNET_ID=$SUBNET_ID
IGW_ID=$IGW_ID
SG_ID=$SG_ID
KEY_NAME=$KEY_NAME
IDS_ID=$IDS_ID
VICTIM_ID=$VICTIM_ID
ATTACKER_ID=$ATTACKER_ID
IDS_PUBLIC_IP=$IDS_PUBLIC_IP
EOF

echo ""
echo "============================================================"
echo "LAB READY"
echo "============================================================"
echo ""
echo "SSH to IDS server:"
echo "  ssh -i $SCRIPT_DIR/$KEY_NAME.pem ubuntu@$IDS_PUBLIC_IP"
echo ""
echo "Dashboard (after services start, ~3-5 min):"
echo "  http://$IDS_PUBLIC_IP:8000"
echo ""
echo "SSH to Attacker (via IDS):"
echo "  ssh -i $SCRIPT_DIR/$KEY_NAME.pem -J ubuntu@$IDS_PUBLIC_IP ubuntu@10.0.1.10"
echo ""
echo "SSH to Victim (via IDS):"
echo "  ssh -i $SCRIPT_DIR/$KEY_NAME.pem -J ubuntu@$IDS_PUBLIC_IP ubuntu@10.0.1.20"
echo ""
echo "State saved to: $STATE_FILE"
echo "To destroy: bash $SCRIPT_DIR/../scripts/teardown.sh"
