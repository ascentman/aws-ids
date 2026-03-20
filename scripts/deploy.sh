#!/bin/bash
# ============================================================
# Full deployment pipeline:
# 1. Serialize models (local)
# 2. Create AWS infrastructure
# 3. Upload code + models to instances
# 4. Start services
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
SETUP_DIR="$LAB_DIR/setup"
STATE_FILE="$SETUP_DIR/lab_state.env"
MODELS_DIR="$LAB_DIR/ids_server/models"

echo "============================================================"
echo "IntegratedIDS Lab — Full Deployment"
echo "============================================================"

# --- Step 1: Serialize models ---
if [ ! -f "$MODELS_DIR/lgb_model.pkl" ]; then
    echo ""
    echo "Step 1: Serializing models..."
    cd "$LAB_DIR/.."
    python3 "$SCRIPT_DIR/serialize_models.py"
else
    echo ""
    echo "Step 1: Models already serialized (skip)"
fi

# --- Step 2: Create AWS infrastructure ---
if [ ! -f "$STATE_FILE" ]; then
    echo ""
    echo "Step 2: Creating AWS infrastructure..."
    bash "$SETUP_DIR/setup_aws.sh"
else
    echo ""
    echo "Step 2: Infrastructure already exists (skip)"
fi

source "$STATE_FILE"
KEY_FILE="$SETUP_DIR/$KEY_NAME.pem"

echo ""
echo "Waiting for instances to be ready (~60s)..."
sleep 60

SSH_OPTS="-i $KEY_FILE -o StrictHostKeyChecking=no -o ConnectTimeout=10"

# --- Step 3: Upload code ---
echo ""
echo "Step 3: Uploading code to instances..."

# IDS Server
echo "  Uploading to IDS server ($IDS_PUBLIC_IP)..."
scp $SSH_OPTS -r "$LAB_DIR/ids_server" "ubuntu@$IDS_PUBLIC_IP:/opt/ids-lab/"

# Victim
echo "  Uploading to victim (via jump)..."
scp $SSH_OPTS -o "ProxyJump=ubuntu@$IDS_PUBLIC_IP" \
    -r "$LAB_DIR/victim" "ubuntu@10.0.1.20:/opt/ids-lab/"

# Attacker
echo "  Uploading to attacker (via jump)..."
scp $SSH_OPTS -o "ProxyJump=ubuntu@$IDS_PUBLIC_IP" \
    -r "$LAB_DIR/attacker" "ubuntu@10.0.1.10:/opt/ids-lab/"

# --- Step 4: Start services ---
echo ""
echo "Step 4: Starting services..."

# Start IDS API
echo "  Starting IDS API on $IDS_PUBLIC_IP..."
ssh $SSH_OPTS "ubuntu@$IDS_PUBLIC_IP" << 'REMOTE_IDS'
cd /opt/ids-lab
source venv/bin/activate
pip install -r ids_server/requirements.txt -q 2>/dev/null
nohup python3 ids_server/ids_api.py > /opt/ids-lab/ids_api.log 2>&1 &
echo "IDS API started (PID: $!)"
REMOTE_IDS

# Start IoT simulator on victim
echo "  Starting IoT simulator on victim..."
ssh $SSH_OPTS -o "ProxyJump=ubuntu@$IDS_PUBLIC_IP" "ubuntu@10.0.1.20" << 'REMOTE_VICTIM'
cd /opt/ids-lab
source venv/bin/activate
sudo nohup python3 victim/iot_simulator.py > /opt/ids-lab/iot_sim.log 2>&1 &
sleep 2
nohup python3 victim/traffic_forwarder.py --ids-url http://10.0.1.30:8000 > /opt/ids-lab/forwarder.log 2>&1 &
echo "IoT simulator and forwarder started"
REMOTE_VICTIM

echo ""
echo "============================================================"
echo "DEPLOYMENT COMPLETE"
echo "============================================================"
echo ""
echo "Dashboard: http://$IDS_PUBLIC_IP:8000"
echo ""
echo "To run attacks:"
echo "  ssh $SSH_OPTS -o ProxyJump=ubuntu@$IDS_PUBLIC_IP ubuntu@10.0.1.10"
echo "  cd /opt/ids-lab && source venv/bin/activate"
echo "  python3 attacker/attack_runner.py 10.0.1.20"
echo ""
echo "To start replay demo:"
echo "  curl -X POST http://$IDS_PUBLIC_IP:8000/replay/start?rate=50"
echo ""
echo "To teardown:"
echo "  bash $SCRIPT_DIR/teardown.sh"
