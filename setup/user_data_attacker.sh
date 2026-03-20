#!/bin/bash
# Bootstrap script for Attacker instance
set -ex

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y python3-pip python3-venv hping3 nmap

mkdir -p /opt/ids-lab
cd /opt/ids-lab

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip

touch /opt/ids-lab/.bootstrap_complete
echo "Attacker bootstrap complete at $(date)" >> /var/log/ids-lab-setup.log
