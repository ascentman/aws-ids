#!/bin/bash
# Bootstrap script for Victim (IoT simulator) instance
set -ex

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y python3-pip python3-venv tcpdump

mkdir -p /opt/ids-lab
cd /opt/ids-lab

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install requests

touch /opt/ids-lab/.bootstrap_complete
echo "Victim bootstrap complete at $(date)" >> /var/log/ids-lab-setup.log
