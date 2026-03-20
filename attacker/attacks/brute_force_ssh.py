"""
SSH Brute Force — authorized lab testing only.
Attempts SSH connections with common credentials for IDS detection testing.
Maps to CICIoT2023 class: DictionaryBruteForce
"""
import socket
import time
import random


# Common IoT device credentials (public knowledge)
CREDENTIALS = [
    ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
    ('root', 'root'), ('root', 'toor'), ('root', ''),
    ('user', 'user'), ('guest', 'guest'), ('admin', ''),
    ('pi', 'raspberry'), ('ubnt', 'ubnt'), ('admin', 'admin1234'),
    ('root', '123456'), ('admin', '12345'), ('test', 'test'),
    ('admin', 'default'), ('root', 'password'), ('admin', 'pass'),
    ('device', 'device'), ('iot', 'iot123'),
]


def run(target_ip: str, duration: int = 30, intensity: str = 'medium',
        target_port: int = 2222):
    """
    SSH brute force against target.

    Args:
        target_ip: victim IP (must be within lab VPC)
        duration: seconds to run
        intensity: low/medium/high
        target_port: SSH port (default 2222 for fake SSH)
    """
    delays = {'low': 1.0, 'medium': 0.3, 'high': 0.05}
    delay = delays.get(intensity, 0.3)

    print(f"[SSH Brute] Target: {target_ip}:{target_port}")
    print(f"[SSH Brute] Duration: {duration}s, {len(CREDENTIALS)} credentials")

    attempts = 0
    start = time.time()

    while time.time() - start < duration:
        username, password = random.choice(CREDENTIALS)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, target_port))
            # Read SSH banner
            banner = sock.recv(256)
            # Send our banner
            sock.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
            # Simulate failed auth (just close after banner exchange)
            time.sleep(0.1)
            sock.close()
            attempts += 1
            if attempts % 10 == 0:
                elapsed = time.time() - start
                print(f"  [{elapsed:.0f}s] {attempts} attempts (last: {username}:{password})")
        except Exception:
            attempts += 1
        time.sleep(delay)

    elapsed = time.time() - start
    print(f"[SSH Brute] Complete: {attempts} attempts in {elapsed:.1f}s")
    return attempts
