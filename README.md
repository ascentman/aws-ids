# AWS IoT IDS Testing Lab

Deploy the IntegratedIDS model (LightGBM + Isolation Forest + SHAP) to an AWS environment with real attack traffic generation and a live web dashboard.

## Architecture

```
┌──────────── VPC 10.0.1.0/24 ────────────┐
│                                           │
│  Attacker (10.0.1.10) — t3.small         │
│  - Runs attack scripts (SYN, UDP, HTTP)  │
│           │                               │
│           ▼                               │
│  Victim (10.0.1.20) — t3.micro           │
│  - IoT services (HTTP, Telnet, SSH)      │
│  - tcpdump captures traffic              │
│  - Sends PCAPs to IDS server             │
│           │                               │
│           ▼ POST /predict_pcap            │
│  IDS Server (10.0.1.30) — t3.xlarge      │
│  - FastAPI + IntegratedIDS model          │
│  - Feature extraction from PCAPs         │
│  - Web dashboard (port 8000)             │
│  - Replay engine for test data           │
│                                           │
└───────────────────────────────────────────┘
```

## Prerequisites

- AWS CLI configured (`aws configure`)
- Python 3.10+
- CICIoT2023 dataset at `../dataset/CICIOT23/`

## Quick Start

### 1. Serialize models (local)

```bash
cd aws-ids-lab
python3 scripts/serialize_models.py
```

This trains LightGBM + IsolationForest on CICIoT2023 and saves artifacts to `ids_server/models/`.

### 2. Local test (optional)

```bash
cd ids_server
pip install -r requirements.txt
python3 ids_api.py
# Open http://localhost:8000
# Click "Start Replay" to see demo
```

### 3. Deploy to AWS

```bash
bash scripts/deploy.sh
```

This creates the VPC, launches 3 instances, uploads code, and starts all services.

### 4. Run attacks

```bash
# SSH to attacker (via IDS jump host)
ssh -i setup/ids-lab-key.pem -J ubuntu@<IDS_PUBLIC_IP> ubuntu@10.0.1.10

# Run full attack sequence
cd /opt/ids-lab
source venv/bin/activate
python3 attacker/attack_runner.py 10.0.1.20
```

### 5. Watch dashboard

Open `http://<IDS_PUBLIC_IP>:8000` in your browser.

### 6. Teardown

```bash
bash scripts/teardown.sh
```

## Attack Types

| Attack | CICIoT2023 Class | Method |
|--------|-------------------|--------|
| SYN Flood | DDoS-SYN_Flood | Rapid TCP SYN connections |
| UDP Flood | DDoS-UDP_Flood | Random UDP packets |
| HTTP Flood | DDoS-HTTP_Flood | Rapid HTTP GET requests |
| Slowloris | DDoS-SlowLoris | Partial HTTP connections |
| Port Scan | Recon-PortScan | TCP connect scan |
| SSH Brute Force | DictionaryBruteForce | Common credential attempts |
| Benign | BenignTraffic | Normal IoT requests |

## Alert Levels

- **NORMAL** (green) — benign traffic, high confidence
- **KNOWN_ATTACK** (blue) — classified attack with high confidence
- **SUSPICIOUS** (orange) — conflicting signals (low confidence or SHAP disagreement)
- **ZERO_DAY_CANDIDATE** (red) — very high anomaly score, unknown pattern

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Web dashboard |
| POST | `/predict` | Single sample classification |
| POST | `/predict_batch` | Batch classification |
| POST | `/predict_pcap` | Classify PCAP file |
| POST | `/replay/start` | Start test CSV replay |
| POST | `/replay/stop` | Stop replay |
| GET | `/alerts` | Recent alerts (JSON) |
| GET | `/stats` | Alert distribution |
| WS | `/ws/alerts` | Real-time alert WebSocket |

## Cost

- IDS server (t3.xlarge on-demand): ~$0.17/hr
- Attacker (t3.small spot): ~$0.006/hr
- Victim (t3.micro spot): ~$0.003/hr
- **Total: ~$0.50-2.00 per 2-4 hour session**

## File Structure

```
aws-ids-lab/
├── setup/
│   ├── setup_aws.sh              # Create VPC, SG, instances
│   ├── teardown_aws.sh           # Delete all AWS resources
│   ├── user_data_attacker.sh     # Attacker bootstrap
│   ├── user_data_victim.sh       # Victim bootstrap
│   └── user_data_ids.sh          # IDS server bootstrap
├── ids_server/
│   ├── ids_api.py                # FastAPI service
│   ├── integrated_ids.py         # IntegratedIDS class
│   ├── feature_extractor.py      # PCAP → 46 features
│   ├── replay_engine.py          # Test CSV replay
│   ├── requirements.txt
│   └── templates/
│       └── dashboard.html        # Web dashboard
├── victim/
│   ├── iot_simulator.py          # IoT services
│   └── traffic_forwarder.py      # tcpdump + forward
├── attacker/
│   ├── attack_runner.py          # Attack orchestrator
│   └── attacks/                  # 7 attack scripts
├── scripts/
│   ├── serialize_models.py       # Train & export models
│   ├── deploy.sh                 # Full deploy pipeline
│   └── teardown.sh               # Destroy everything
└── README.md
```
