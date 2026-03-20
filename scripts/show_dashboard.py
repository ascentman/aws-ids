#!/usr/bin/env python3
"""
Start IDS server, open dashboard, then replay live test PCAPs with delays
so all charts (timeline, scatter, pie, bar) populate in real-time.

Usage: python3 scripts/show_dashboard.py
"""
import os
import signal
import subprocess
import sys
import tempfile
import time
import webbrowser

import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDS_SERVER_DIR = os.path.join(BASE_DIR, 'ids_server')
IDS_URL = 'http://127.0.0.1:8000'

sys.path.insert(0, os.path.join(BASE_DIR, 'scripts'))
from run_live_test import (
    generate_benign_pcap, generate_syn_flood_pcap, generate_udp_flood_pcap,
    generate_http_flood_pcap, generate_slowloris_pcap, generate_port_scan_pcap,
    generate_brute_force_pcap,
)

_proc = None


def cleanup(*args):
    global _proc
    if _proc and _proc.poll() is None:
        print("\nStopping IDS server...")
        try:
            os.killpg(os.getpgid(_proc.pid), signal.SIGTERM)
        except Exception:
            _proc.terminate()
        try:
            _proc.wait(timeout=5)
        except Exception:
            pass
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def post_pcap(pcap_path, name):
    """Post a PCAP file to the IDS and return flow count."""
    pcap_size = os.path.getsize(pcap_path)
    try:
        with open(pcap_path, 'rb') as f:
            r = requests.post(
                f'{IDS_URL}/predict_pcap',
                files={'file': ('capture.pcap', f, 'application/octet-stream')},
                timeout=120,
            )
        if r.status_code == 200:
            count = r.json().get('count', 0)
            print(f"  {name:20s} — {count:3d} flows ({pcap_size:,} bytes)")
            return count
        else:
            print(f"  {name:20s} — ERROR {r.status_code}")
            return 0
    except requests.exceptions.ReadTimeout:
        print(f"  {name:20s} — TIMEOUT ({pcap_size:,} bytes), skipping")
        return 0
    except Exception as e:
        print(f"  {name:20s} — ERROR: {e}")
        return 0
    finally:
        try:
            os.unlink(pcap_path)
        except Exception:
            pass


def main():
    global _proc

    # 1. Start IDS server
    print("[+] Starting IDS server...")
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    _proc = subprocess.Popen(
        [sys.executable, 'ids_api.py'],
        cwd=IDS_SERVER_DIR, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    print(f"  PID: {_proc.pid}")

    print("  Waiting for model loading...")
    start = time.time()
    while time.time() - start < 120:
        try:
            r = requests.get(f'{IDS_URL}/stats', timeout=2)
            if r.status_code == 200:
                print(f"  Ready in {time.time()-start:.0f}s")
                break
        except requests.ConnectionError:
            pass
        time.sleep(2)
    else:
        print("  TIMEOUT")
        cleanup()

    # 2. Clear state
    requests.post(f'{IDS_URL}/clear', timeout=5)

    # 3. Feed PCAPs with delays — post first one BEFORE opening browser
    #    so the dashboard sees total>0 and won't auto-start CSV replay
    phases = [
        ('Benign baseline', generate_benign_pcap),
        ('SYN Flood', generate_syn_flood_pcap),
        ('UDP Flood', generate_udp_flood_pcap),
        ('HTTP Flood', generate_http_flood_pcap),
        ('Slowloris', generate_slowloris_pcap),
        ('Port Scan', generate_port_scan_pcap),
        ('SSH Brute Force', generate_brute_force_pcap),
        ('Benign cooldown', generate_benign_pcap),
    ]

    # Use shorter durations (5s) for dashboard demo — fewer packets per
    # PCAP so the async server doesn't block the event loop too long
    DEMO_DURATION = 5

    print(f"\n[+] Feeding PCAPs to IDS (duration={DEMO_DURATION}s per phase)...")
    total_flows = 0

    # Post first PCAP before opening browser to prevent auto-replay
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
        pcap_path = tmp.name
    phases[0][1](pcap_path, duration=DEMO_DURATION)
    count = post_pcap(pcap_path, phases[0][0])
    total_flows += count

    # Now open browser — total > 0, so no auto-replay
    print(f"\n[+] Opening dashboard: {IDS_URL}")
    webbrowser.open(IDS_URL)
    print("  Waiting 3s for WebSocket connection...")
    time.sleep(3)

    # Feed remaining PCAPs with delays for timeline chart
    for i, (name, generator) in enumerate(phases[1:], 1):
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            pcap_path = tmp.name
        generator(pcap_path, duration=DEMO_DURATION)
        count = post_pcap(pcap_path, name)
        total_flows += count

        # Delay between phases so timeline chart shows progression
        if i < len(phases) - 1:
            time.sleep(4)

    # 5. Print summary
    time.sleep(1)
    stats = requests.get(f'{IDS_URL}/stats', timeout=5).json()
    print(f"\n[+] Dashboard populated: {total_flows} flows")
    print(f"  NORMAL:             {stats['alerts']['NORMAL']}")
    print(f"  KNOWN_ATTACK:       {stats['alerts']['KNOWN_ATTACK']}")
    print(f"  SUSPICIOUS:         {stats['alerts']['SUSPICIOUS']}")
    print(f"  ZERO_DAY_CANDIDATE: {stats['alerts']['ZERO_DAY_CANDIDATE']}")

    try:
        dec = requests.get(f'{IDS_URL}/decision_stats', timeout=5).json()
        print(f"\n  Decision Engine Metrics:")
        for level in ['KNOWN_ATTACK', 'SUSPICIOUS']:
            d = dec.get(level, {})
            if d.get('count', 0) > 0:
                print(f"    {level}: count={d['count']}, "
                      f"conf={d['avg_confidence']*100:.1f}%, "
                      f"anom={d['avg_anomaly']*100:.1f}%, "
                      f"shap={d['avg_consistency']*100:.1f}%")
    except Exception:
        pass

    print("\n[+] Dashboard is live. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)
        if _proc.poll() is not None:
            print("  Server exited unexpectedly")
            break


if __name__ == '__main__':
    main()
