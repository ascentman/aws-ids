"""
Benign traffic generator — generates normal IoT-like traffic patterns.
Maps to CICIoT2023 class: BenignTraffic
"""
import socket
import time
import random


def run(target_ip: str, duration: int = 30, intensity: str = 'medium',
        target_port: int = 80):
    """
    Generate benign-looking traffic patterns.

    Simulates normal IoT device communication:
    - Periodic status checks
    - Sensor data uploads
    - Configuration queries

    Args:
        target_ip: victim IP (must be within lab VPC)
        duration: seconds to run
        intensity: low/medium/high
    """
    intervals = {'low': 2.0, 'medium': 0.5, 'high': 0.1}
    interval = intervals.get(intensity, 0.5)

    requests_templates = [
        'GET /status HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: IoTSensor/1.0\r\n\r\n',
        'GET /config HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: IoTSensor/1.0\r\n\r\n',
        'POST /api/data HTTP/1.1\r\nHost: {ip}\r\nContent-Type: application/json\r\n'
        'Content-Length: 45\r\n\r\n{{"temp":22.5,"humidity":45,"timestamp":{ts}}}',
        'GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: IoTSensor/1.0\r\n\r\n',
    ]

    print(f"[Benign] Target: {target_ip}:{target_port}")
    print(f"[Benign] Duration: {duration}s, Interval: {interval}s")

    sent = 0
    start = time.time()
    while time.time() - start < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, target_port))
            template = random.choice(requests_templates)
            request = template.format(ip=target_ip, ts=int(time.time()))
            sock.sendall(request.encode())
            sock.recv(4096)
            sock.close()
            sent += 1
            if sent % 20 == 0:
                elapsed = time.time() - start
                print(f"  [{elapsed:.0f}s] Sent {sent} benign requests")
        except Exception:
            pass
        # Add jitter for realistic timing
        time.sleep(interval + random.uniform(-0.1, 0.3))

    elapsed = time.time() - start
    print(f"[Benign] Complete: {sent} requests in {elapsed:.1f}s")
    return sent
