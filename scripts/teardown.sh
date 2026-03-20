#!/bin/bash
# ============================================================
# Teardown — destroys all AWS resources
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SETUP_DIR="$(dirname "$SCRIPT_DIR")/setup"

echo "============================================================"
echo "IntegratedIDS Lab — Teardown"
echo "============================================================"

bash "$SETUP_DIR/teardown_aws.sh"

echo ""
echo "Done. All AWS resources destroyed."
echo "Local model artifacts remain in ids_server/models/"
