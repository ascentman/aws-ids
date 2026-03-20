#!/bin/bash
# Bootstrap script for IDS Server instance
set -ex

export DEBIAN_FRONTEND=noninteractive

# Update system
apt-get update -y
apt-get upgrade -y

# Install Python and dependencies
apt-get install -y python3-pip python3-venv tcpdump

# Create working directory
mkdir -p /opt/ids-lab
cd /opt/ids-lab

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install fastapi uvicorn[standard] jinja2 python-multipart \
    numpy pandas scikit-learn lightgbm shap joblib dpkt websockets

# Signal that bootstrap is complete
touch /opt/ids-lab/.bootstrap_complete
echo "IDS Server bootstrap complete at $(date)" >> /var/log/ids-lab-setup.log
