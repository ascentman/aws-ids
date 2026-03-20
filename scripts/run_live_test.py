#!/usr/bin/env python3
"""
Live attack test orchestrator for IntegratedIDS.

Runs locally on macOS:
1. Starts IDS server (ids_api.py) on port 8000
2. Starts IoT simulator on high ports (8080/2323/2222)
3. For each attack phase: generates real network traffic, builds a PCAP
   from the traffic pattern using dpkt, POSTs PCAP to /predict_pcap
4. Saves all results to live_test_results.json

Usage: cd aws-ids-lab && python3 scripts/run_live_test.py
"""
import io
import json
import os
import random
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

import dpkt
import requests

# ============================================================
# CONFIGURATION
# ============================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDS_SERVER_DIR = os.path.join(BASE_DIR, 'ids_server')
IDS_URL = 'http://127.0.0.1:8000'

HTTP_PORT = 8080
TELNET_PORT = 2323
SSH_PORT = 2222
TARGET_IP = '127.0.0.1'

DURATION_PER_ATTACK = 15
INTENSITY = 'low'
PAUSE_BETWEEN = 3
MODEL_LOAD_TIMEOUT = 120

ATTACK_SEQUENCE = [
    {'key': 'benign_baseline', 'name': 'Baseline — Normal traffic',
     'ciciot_class': 'BenignTraffic', 'attack_type': 'benign', 'target_port': HTTP_PORT},
    {'key': 'syn_flood', 'name': 'DDoS SYN Flood',
     'ciciot_class': 'DDoS-SYN_Flood', 'attack_type': 'syn_flood', 'target_port': HTTP_PORT},
    {'key': 'udp_flood', 'name': 'DDoS UDP Flood',
     'ciciot_class': 'DDoS-UDP_Flood', 'attack_type': 'udp_flood', 'target_port': 9999},
    {'key': 'http_flood', 'name': 'DDoS HTTP Flood',
     'ciciot_class': 'DDoS-HTTP_Flood', 'attack_type': 'http_flood', 'target_port': HTTP_PORT},
    {'key': 'slowloris', 'name': 'Slowloris DoS',
     'ciciot_class': 'DDoS-SlowLoris', 'attack_type': 'slowloris', 'target_port': HTTP_PORT},
    {'key': 'port_scan', 'name': 'Port Scan (Reconnaissance)',
     'ciciot_class': 'Recon-PortScan', 'attack_type': 'port_scan', 'target_port': None},
    {'key': 'brute_force', 'name': 'SSH Brute Force',
     'ciciot_class': 'DictionaryBruteForce', 'attack_type': 'brute_force', 'target_port': SSH_PORT},
    {'key': 'benign_cooldown', 'name': 'Cooldown — Normal traffic',
     'ciciot_class': 'BenignTraffic', 'attack_type': 'benign', 'target_port': HTTP_PORT},
]

# ============================================================
# PROCESS MANAGEMENT
# ============================================================
_subprocesses = []


def cleanup():
    """Kill all subprocesses."""
    for name, proc in _subprocesses:
        if proc.poll() is None:
            print(f"  Stopping {name} (PID {proc.pid})...")
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                try:
                    proc.terminate()
                except Exception:
                    pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    proc.kill()


def start_ids_server():
    """Start the IDS API server as a subprocess."""
    print("[+] Starting IDS server...")
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    proc = subprocess.Popen(
        [sys.executable, 'ids_api.py'],
        cwd=IDS_SERVER_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    _subprocesses.append(('IDS server', proc))
    print(f"  IDS server PID: {proc.pid}")

    print("  Waiting for model loading...")
    start = time.time()
    while time.time() - start < MODEL_LOAD_TIMEOUT:
        try:
            r = requests.get(f'{IDS_URL}/stats', timeout=2)
            if r.status_code == 200:
                elapsed = time.time() - start
                print(f"  IDS server ready in {elapsed:.0f}s")
                return proc
        except requests.ConnectionError:
            pass
        time.sleep(2)

    raise RuntimeError(f"IDS server failed to start within {MODEL_LOAD_TIMEOUT}s")


def start_iot_simulator():
    """Start the IoT simulator on high ports."""
    print("[+] Starting IoT simulator...")
    sim_code = f"""
import sys, os, threading, time
sys.path.insert(0, os.path.join('{BASE_DIR}', 'victim'))
from iot_simulator import run_http, run_telnet, run_ssh
threads = [
    threading.Thread(target=run_http, args=({HTTP_PORT},), daemon=True),
    threading.Thread(target=run_telnet, args=({TELNET_PORT},), daemon=True),
    threading.Thread(target=run_ssh, args=({SSH_PORT},), daemon=True),
]
for t in threads:
    t.start()
print("IoT simulator running on ports {HTTP_PORT}/{TELNET_PORT}/{SSH_PORT}")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
"""
    proc = subprocess.Popen(
        [sys.executable, '-c', sim_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    _subprocesses.append(('IoT simulator', proc))
    print(f"  IoT simulator PID: {proc.pid}")

    time.sleep(2)
    for port_name, port in [('HTTP', HTTP_PORT), ('SSH', SSH_PORT)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((TARGET_IP, port))
            s.close()
            print(f"  {port_name} port {port} ready")
        except Exception:
            print(f"  WARNING: {port_name} port {port} not responding")

    return proc


# ============================================================
# PCAP GENERATION (using dpkt — no root needed)
# ============================================================

def _ip_bytes(ip_str):
    """Convert IP string to 4 bytes."""
    return socket.inet_aton(ip_str)


def _build_tcp_packet(src_ip, dst_ip, sport, dport, flags, payload=b'', seq=0, ack=0):
    """Build an Ethernet/IP/TCP packet for PCAP."""
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport,
        flags=flags, seq=seq, ack=ack,
        data=payload,
        off=5,
    )
    ip = dpkt.ip.IP(
        src=_ip_bytes(src_ip), dst=_ip_bytes(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp, len=20 + len(tcp),
    )
    eth = dpkt.ethernet.Ethernet(
        src=b'\x00\x11\x22\x33\x44\x55',
        dst=b'\x66\x77\x88\x99\xaa\xbb',
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _build_udp_packet(src_ip, dst_ip, sport, dport, payload=b''):
    """Build an Ethernet/IP/UDP packet for PCAP."""
    udp = dpkt.udp.UDP(
        sport=sport, dport=dport,
        data=payload,
        ulen=8 + len(payload),
    )
    ip = dpkt.ip.IP(
        src=_ip_bytes(src_ip), dst=_ip_bytes(dst_ip),
        p=dpkt.ip.IP_PROTO_UDP,
        data=udp, len=20 + len(udp),
    )
    eth = dpkt.ethernet.Ethernet(
        src=b'\x00\x11\x22\x33\x44\x55',
        dst=b'\x66\x77\x88\x99\xaa\xbb',
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _write_pcap(packets_with_ts, pcap_path):
    """Write list of (timestamp, raw_bytes) to a PCAP file."""
    with open(pcap_path, 'wb') as f:
        writer = dpkt.pcap.Writer(f)
        for ts, pkt_bytes in packets_with_ts:
            writer.writepkt(pkt_bytes, ts)


def generate_benign_pcap(pcap_path, duration=15):
    """Generate benign HTTP traffic PCAP."""
    packets = []
    t = time.time()
    src = '10.0.1.10'
    dst = '10.0.1.20'

    n_requests = max(10, duration * 2)  # ~2 req/s
    for i in range(n_requests):
        ts = t + i * (duration / n_requests) + random.uniform(0, 0.3)
        sport = random.randint(40000, 60000)

        # SYN
        packets.append((ts, _build_tcp_packet(src, dst, sport, 80, dpkt.tcp.TH_SYN)))
        # SYN-ACK
        packets.append((ts + 0.001, _build_tcp_packet(dst, src, 80, sport,
                        dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)))
        # ACK
        packets.append((ts + 0.002, _build_tcp_packet(src, dst, sport, 80, dpkt.tcp.TH_ACK)))

        # HTTP GET
        path = random.choice(['/', '/status', '/config', '/api/data'])
        req = f'GET {path} HTTP/1.1\r\nHost: 10.0.1.20\r\nUser-Agent: IoTSensor/1.0\r\n\r\n'
        packets.append((ts + 0.003, _build_tcp_packet(src, dst, sport, 80,
                        dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, payload=req.encode())))

        # HTTP response (varied sizes like real benign traffic)
        resp_size = random.choice([128, 256, 512, 1024, 2048])
        resp = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(resp_size).encode() + b'\r\n\r\n'
        resp += os.urandom(min(resp_size, 500))
        packets.append((ts + 0.05, _build_tcp_packet(dst, src, 80, sport,
                        dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, payload=resp)))
        packets.append((ts + 0.06, _build_tcp_packet(src, dst, sport, 80, dpkt.tcp.TH_ACK)))

        # FIN
        packets.append((ts + 0.1 + random.uniform(0, 0.5), _build_tcp_packet(
            src, dst, sport, 80, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)))
        packets.append((ts + 0.15 + random.uniform(0, 0.3), _build_tcp_packet(
            dst, src, 80, sport, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)))

    _write_pcap(packets, pcap_path)
    return len(packets)


def generate_syn_flood_pcap(pcap_path, duration=15):
    """Generate SYN flood PCAP — many SYN-only packets, uniform size."""
    packets = []
    t = time.time()
    src_base = '10.0.1.'
    dst = '10.0.1.20'

    n_packets = duration * 100  # 100 pps
    for i in range(n_packets):
        ts = t + i * (duration / n_packets)
        src = src_base + str(random.randint(2, 254))
        sport = random.randint(1024, 65535)
        packets.append((ts, _build_tcp_packet(src, dst, sport, 80, dpkt.tcp.TH_SYN)))

    _write_pcap(packets, pcap_path)
    return len(packets)


def generate_udp_flood_pcap(pcap_path, duration=15):
    """Generate UDP flood PCAP — many UDP packets, random payloads."""
    packets = []
    t = time.time()
    src = '10.0.1.10'
    dst = '10.0.1.20'

    n_packets = duration * 100
    for i in range(n_packets):
        ts = t + i * (duration / n_packets)
        sport = random.randint(1024, 65535)
        dport = random.choice([53, 123, 9999])
        payload = os.urandom(random.choice([64, 128, 256, 512]))
        packets.append((ts, _build_udp_packet(src, dst, sport, dport, payload)))

    _write_pcap(packets, pcap_path)
    return len(packets)


def generate_http_flood_pcap(pcap_path, duration=15):
    """Generate HTTP flood PCAP — rapid HTTP requests, uniform pattern."""
    packets = []
    t = time.time()
    src = '10.0.1.10'
    dst = '10.0.1.20'

    n_requests = duration * 50  # 50 req/s (high rate)
    for i in range(n_requests):
        ts = t + i * (duration / n_requests)
        sport = random.randint(40000, 65535)

        # SYN
        packets.append((ts, _build_tcp_packet(src, dst, sport, 80, dpkt.tcp.TH_SYN)))
        # GET with minimal headers
        path = random.choice(['/', '/status', '/login', '/admin', '/config'])
        req = f'GET {path} HTTP/1.1\r\nHost: {dst}\r\n\r\n'
        packets.append((ts + 0.001, _build_tcp_packet(src, dst, sport, 80,
                        dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, payload=req.encode())))

    _write_pcap(packets, pcap_path)
    return len(packets)


def generate_slowloris_pcap(pcap_path, duration=15):
    """Generate Slowloris PCAP — partial HTTP headers, slow send."""
    packets = []
    t = time.time()
    src = '10.0.1.10'
    dst = '10.0.1.20'

    n_conns = 50
    for c in range(n_conns):
        sport = 40000 + c
        conn_start = t + (c * 0.1)
        # Initial partial header
        partial = f'GET / HTTP/1.1\r\nHost: {dst}\r\n'
        packets.append((conn_start, _build_tcp_packet(src, dst, sport, 80,
                        dpkt.tcp.TH_SYN)))
        packets.append((conn_start + 0.01, _build_tcp_packet(src, dst, sport, 80,
                        dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, payload=partial.encode())))

        # Keep-alive headers every ~1s
        for k in range(min(duration - 1, 14)):
            keep_ts = conn_start + 1 + k
            header = f'X-a: {random.randint(1,9999)}\r\n'
            packets.append((keep_ts, _build_tcp_packet(src, dst, sport, 80,
                            dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, payload=header.encode())))

    _write_pcap(packets, pcap_path)
    return len(packets)


def generate_port_scan_pcap(pcap_path, duration=15):
    """Generate port scan PCAP — SYN to many ports, RST responses."""
    packets = []
    t = time.time()
    src = '10.0.1.10'
    dst = '10.0.1.20'

    ports = list(range(1, 1025))
    random.shuffle(ports)
    n_ports = min(len(ports), duration * 50)

    for i in range(n_ports):
        ts = t + i * (duration / n_ports)
        dport = ports[i % len(ports)]
        sport = random.randint(40000, 65535)
        # SYN probe
        packets.append((ts, _build_tcp_packet(src, dst, sport, dport, dpkt.tcp.TH_SYN)))
        # RST response (port closed)
        packets.append((ts + 0.001, _build_tcp_packet(dst, src, dport, sport,
                        dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK)))

    _write_pcap(packets, pcap_path)
    return len(packets)


def generate_brute_force_pcap(pcap_path, duration=15):
    """Generate SSH brute force PCAP — repeated connections to port 22."""
    packets = []
    t = time.time()
    src = '10.0.1.10'
    dst = '10.0.1.20'

    n_attempts = duration * 10  # 10 attempts/s
    for i in range(n_attempts):
        ts = t + i * (duration / n_attempts)
        sport = random.randint(40000, 65535)

        # SYN
        packets.append((ts, _build_tcp_packet(src, dst, sport, 22, dpkt.tcp.TH_SYN)))
        # SYN-ACK
        packets.append((ts + 0.001, _build_tcp_packet(dst, src, 22, sport,
                        dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)))
        # ACK
        packets.append((ts + 0.002, _build_tcp_packet(src, dst, sport, 22, dpkt.tcp.TH_ACK)))
        # SSH banner
        banner = b'SSH-2.0-OpenSSH_8.9\r\n'
        packets.append((ts + 0.003, _build_tcp_packet(dst, src, 22, sport,
                        dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, payload=banner)))
        # Client banner
        client_banner = b'SSH-2.0-PuTTY_0.78\r\n'
        packets.append((ts + 0.004, _build_tcp_packet(src, dst, sport, 22,
                        dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, payload=client_banner)))
        # RST (connection rejected after auth fail)
        packets.append((ts + 0.1, _build_tcp_packet(dst, src, 22, sport,
                        dpkt.tcp.TH_RST)))

    _write_pcap(packets, pcap_path)
    return len(packets)


PCAP_GENERATORS = {
    'benign': generate_benign_pcap,
    'syn_flood': generate_syn_flood_pcap,
    'udp_flood': generate_udp_flood_pcap,
    'http_flood': generate_http_flood_pcap,
    'slowloris': generate_slowloris_pcap,
    'port_scan': generate_port_scan_pcap,
    'brute_force': generate_brute_force_pcap,
}


# ============================================================
# ATTACK EXECUTION (real traffic + PCAP generation)
# ============================================================

def run_attack_with_pcap(attack_type, target_port, duration, intensity, pcap_path):
    """
    Run real attack traffic AND generate a representative PCAP.

    Real attacks run against the IoT simulator to create actual network
    activity. Simultaneously, we generate a structured PCAP using dpkt
    that captures the attack pattern for IDS analysis.
    """
    # Start real attack in background thread
    attack_thread = threading.Thread(
        target=_run_real_attack,
        args=(attack_type, target_port, duration, intensity),
        daemon=True,
    )
    attack_thread.start()

    # Generate PCAP with characteristic traffic pattern
    generator = PCAP_GENERATORS[attack_type]
    n_packets = generator(pcap_path, duration)
    print(f"  Generated PCAP: {n_packets} packets")

    # Wait for real attack to finish
    attack_thread.join(timeout=duration + 5)
    return n_packets


def _run_real_attack(attack_type, target_port, duration, intensity):
    """Run a real attack using the existing attack modules."""
    attacker_path = os.path.join(BASE_DIR, 'attacker')
    if attacker_path not in sys.path:
        sys.path.insert(0, attacker_path)

    from attacks import (
        benign_traffic, ddos_syn_flood, ddos_udp_flood,
        ddos_http_flood, dos_slowloris, port_scan, brute_force_ssh,
    )

    modules = {
        'benign': benign_traffic,
        'syn_flood': ddos_syn_flood,
        'udp_flood': ddos_udp_flood,
        'http_flood': ddos_http_flood,
        'slowloris': dos_slowloris,
        'port_scan': port_scan,
        'brute_force': brute_force_ssh,
    }

    module = modules[attack_type]
    try:
        if attack_type == 'port_scan':
            module.run(target_ip=TARGET_IP, duration=duration,
                       intensity=intensity, port_range=(8000, 8100))
        elif attack_type == 'udp_flood':
            module.run(target_ip=TARGET_IP, duration=duration,
                       intensity=intensity, target_port=target_port or 9999)
        else:
            module.run(target_ip=TARGET_IP, duration=duration,
                       intensity=intensity, target_port=target_port or HTTP_PORT)
    except Exception as e:
        print(f"  Real attack error ({attack_type}): {e}")


def post_pcap(pcap_path):
    """POST PCAP file to IDS server and return results."""
    file_size = os.path.getsize(pcap_path)
    if file_size < 50:
        print(f"  PCAP too small ({file_size} bytes), skipping")
        return None

    print(f"  Posting PCAP ({file_size:,} bytes) to IDS...")
    with open(pcap_path, 'rb') as f:
        r = requests.post(
            f'{IDS_URL}/predict_pcap',
            files={'file': ('capture.pcap', f, 'application/octet-stream')},
            timeout=60,
        )
    if r.status_code == 200:
        data = r.json()
        print(f"  IDS returned {data.get('count', 0)} flow predictions")
        return data
    else:
        print(f"  IDS error: {r.status_code} {r.text[:200]}")
        return None


# ============================================================
# MAIN ORCHESTRATION
# ============================================================

def run_live_test():
    """Run the complete live test sequence."""
    print("=" * 60)
    print("LIVE ATTACK TEST — IntegratedIDS")
    print("=" * 60)
    print(f"Target: {TARGET_IP}")
    print(f"Duration per phase: {DURATION_PER_ATTACK}s")
    print(f"Intensity: {INTENSITY}")
    print(f"Phases: {len(ATTACK_SEQUENCE)}")
    print("=" * 60)

    results = {
        'test_config': {
            'target_ip': TARGET_IP,
            'duration_per_attack': DURATION_PER_ATTACK,
            'intensity': INTENSITY,
            'http_port': HTTP_PORT,
            'telnet_port': TELNET_PORT,
            'ssh_port': SSH_PORT,
        },
        'phases': [],
        'summary': {},
    }

    try:
        # 1. Start services
        start_ids_server()
        start_iot_simulator()

        # 2. Clear IDS state
        print("\n[+] Clearing IDS state...")
        r = requests.post(f'{IDS_URL}/clear', timeout=5)
        print(f"  Clear response: {r.json()}")

        # 3. Run attack phases
        total_start = time.time()

        for i, phase in enumerate(ATTACK_SEQUENCE):
            phase_num = i + 1
            print(f"\n{'='*60}")
            print(f"[{phase_num}/{len(ATTACK_SEQUENCE)}] {phase['name']}")
            print(f"  CICIoT2023 class: {phase['ciciot_class']}")
            print(f"{'='*60}")

            phase_result = {
                'key': phase['key'],
                'name': phase['name'],
                'ciciot_class': phase['ciciot_class'],
                'attack_type': phase['attack_type'],
                'start_time': time.time(),
            }

            # Create temp PCAP
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
                pcap_path = tmp.name

            # Run attack + generate PCAP
            try:
                n_packets = run_attack_with_pcap(
                    phase['attack_type'],
                    phase.get('target_port', HTTP_PORT),
                    DURATION_PER_ATTACK,
                    INTENSITY,
                    pcap_path,
                )
                phase_result['packets_generated'] = n_packets
            except Exception as e:
                print(f"  Attack error: {e}")
                phase_result['attack_error'] = str(e)

            pcap_size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
            print(f"  PCAP size: {pcap_size:,} bytes")
            phase_result['pcap_size'] = pcap_size

            # POST PCAP to IDS
            ids_response = post_pcap(pcap_path)
            phase_result['end_time'] = time.time()
            phase_result['duration'] = phase_result['end_time'] - phase_result['start_time']

            if ids_response:
                phase_result['flow_count'] = ids_response.get('count', 0)
                pred_summary = {}
                level_summary = {}
                confidence_values = []
                anomaly_values = []
                for r_item in ids_response.get('results', []):
                    cls = r_item.get('predicted_class', 'Unknown')
                    lvl = r_item.get('alert_level', 'Unknown')
                    pred_summary[cls] = pred_summary.get(cls, 0) + 1
                    level_summary[lvl] = level_summary.get(lvl, 0) + 1
                    confidence_values.append(r_item.get('confidence', 0))
                    anomaly_values.append(r_item.get('anomaly_score', 0))
                phase_result['predictions'] = pred_summary
                phase_result['alert_levels'] = level_summary
                phase_result['avg_confidence'] = (
                    round(sum(confidence_values) / len(confidence_values), 4)
                    if confidence_values else 0
                )
                phase_result['avg_anomaly'] = (
                    round(sum(anomaly_values) / len(anomaly_values), 4)
                    if anomaly_values else 0
                )
                phase_result['raw_results'] = ids_response.get('results', [])
            else:
                phase_result['flow_count'] = 0
                phase_result['predictions'] = {}
                phase_result['alert_levels'] = {}
                phase_result['avg_confidence'] = 0
                phase_result['avg_anomaly'] = 0
                phase_result['raw_results'] = []

            results['phases'].append(phase_result)

            # Clean up temp PCAP
            try:
                os.unlink(pcap_path)
            except Exception:
                pass

            if phase_num < len(ATTACK_SEQUENCE):
                print(f"\n  Pausing {PAUSE_BETWEEN}s...")
                time.sleep(PAUSE_BETWEEN)

        total_elapsed = time.time() - total_start

        # 4. Fetch final stats
        print(f"\n{'='*60}")
        print("FETCHING FINAL RESULTS")
        print(f"{'='*60}")

        try:
            alerts_resp = requests.get(f'{IDS_URL}/alerts?limit=500', timeout=10).json()
            results['final_alerts'] = alerts_resp
            print(f"  Total alerts: {alerts_resp.get('count', 0)}")
        except Exception as e:
            print(f"  Error fetching alerts: {e}")
            results['final_alerts'] = {}

        try:
            stats_resp = requests.get(f'{IDS_URL}/stats', timeout=10).json()
            results['final_stats'] = stats_resp
            print(f"  Stats: {json.dumps(stats_resp, indent=2)}")
        except Exception as e:
            print(f"  Error fetching stats: {e}")
            results['final_stats'] = {}

        try:
            decision_resp = requests.get(f'{IDS_URL}/decision_stats', timeout=10).json()
            results['decision_stats'] = decision_resp
            print(f"  Decision stats: {json.dumps(decision_resp, indent=2)}")
        except Exception as e:
            print(f"  Error fetching decision stats: {e}")
            results['decision_stats'] = {}

        # 5. Build summary
        total_flows = sum(p.get('flow_count', 0) for p in results['phases'])
        all_levels = {}
        for p in results['phases']:
            for lvl, cnt in p.get('alert_levels', {}).items():
                all_levels[lvl] = all_levels.get(lvl, 0) + cnt

        results['summary'] = {
            'total_phases': len(ATTACK_SEQUENCE),
            'total_duration': round(total_elapsed, 1),
            'total_flows_analyzed': total_flows,
            'alert_level_totals': all_levels,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }

        print(f"\n{'='*60}")
        print("LIVE TEST COMPLETE")
        print(f"  Total time: {total_elapsed:.0f}s")
        print(f"  Flows analyzed: {total_flows}")
        print(f"  Alert levels: {all_levels}")
        print(f"{'='*60}")

    finally:
        # 6. Save results
        out_path = os.path.join(BASE_DIR, 'scripts', 'live_test_results.json')
        with open(out_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved: {out_path}")

        # 7. Cleanup
        print("\n[+] Cleaning up...")
        cleanup()


if __name__ == '__main__':
    try:
        run_live_test()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        cleanup()
        sys.exit(1)
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        cleanup()
        sys.exit(1)
