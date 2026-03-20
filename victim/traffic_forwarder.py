#!/usr/bin/env python3
"""
Traffic forwarder — captures network traffic with tcpdump
and periodically sends PCAP chunks to the IDS server.
"""
import os
import subprocess
import sys
import time
import tempfile
import requests
import argparse


def capture_and_forward(ids_url: str, interface: str = 'eth0',
                        interval: int = 5, exclude_ssh: bool = True):
    """
    Capture traffic and forward PCAPs to IDS server.

    Args:
        ids_url: IDS server URL (e.g., http://10.0.1.30:8000)
        interface: Network interface to capture on
        interval: Seconds between PCAP uploads
        exclude_ssh: Exclude SSH traffic (port 22) from capture
    """
    print(f"Traffic Forwarder")
    print(f"  Interface: {interface}")
    print(f"  IDS URL: {ids_url}")
    print(f"  Interval: {interval}s")
    print(f"  Exclude SSH: {exclude_ssh}")

    bpf_filter = 'not port 22' if exclude_ssh else ''

    while True:
        pcap_file = tempfile.mktemp(suffix='.pcap')
        try:
            # Capture for `interval` seconds
            cmd = [
                'tcpdump', '-i', interface, '-w', pcap_file,
                '-c', '1000',  # max 1000 packets per chunk
            ]
            if bpf_filter:
                cmd.extend(bpf_filter.split())

            print(f"\n[{time.strftime('%H:%M:%S')}] Capturing {interval}s on {interface}...")
            proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(interval)
            proc.terminate()
            proc.wait(timeout=5)

            # Check if PCAP has data
            if not os.path.exists(pcap_file) or os.path.getsize(pcap_file) < 24:
                print("  No packets captured")
                continue

            pcap_size = os.path.getsize(pcap_file)
            print(f"  Captured {pcap_size} bytes")

            # Upload to IDS
            with open(pcap_file, 'rb') as f:
                try:
                    resp = requests.post(
                        f'{ids_url}/predict_pcap',
                        files={'file': ('capture.pcap', f, 'application/octet-stream')},
                        timeout=30,
                    )
                    if resp.status_code == 200:
                        result = resp.json()
                        n = result.get('count', 0)
                        print(f"  Sent to IDS: {n} flows classified")
                        for r in result.get('results', [])[:5]:
                            print(f"    {r['alert_level']:20s} {r['predicted_class']}"
                                  f" (conf={r['confidence']:.2f}, anom={r['anomaly_score']:.2f})")
                    else:
                        print(f"  IDS error: {resp.status_code}")
                except requests.exceptions.ConnectionError:
                    print(f"  Cannot connect to IDS at {ids_url}")
                except Exception as e:
                    print(f"  Upload error: {e}")
        except Exception as e:
            print(f"  Capture error: {e}")
        finally:
            if os.path.exists(pcap_file):
                os.unlink(pcap_file)


def main():
    parser = argparse.ArgumentParser(description='Traffic Forwarder for IDS')
    parser.add_argument('--ids-url', default='http://10.0.1.30:8000',
                        help='IDS server URL')
    parser.add_argument('--interface', default='eth0',
                        help='Network interface')
    parser.add_argument('--interval', type=int, default=5,
                        help='Capture interval in seconds')
    parser.add_argument('--include-ssh', action='store_true',
                        help='Include SSH traffic in capture')
    args = parser.parse_args()

    capture_and_forward(
        ids_url=args.ids_url,
        interface=args.interface,
        interval=args.interval,
        exclude_ssh=not args.include_ssh,
    )


if __name__ == '__main__':
    main()
