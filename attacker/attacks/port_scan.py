"""
Port Scanner — authorized lab testing only.
Scans target ports for IDS detection testing.
Maps to CICIoT2023 class: Recon-PortScan
"""
import socket
import time
import random


def run(target_ip: str, duration: int = 30, intensity: str = 'medium',
        port_range: tuple = (1, 1024)):
    """
    Port scan against target.

    Args:
        target_ip: victim IP (must be within lab VPC)
        duration: seconds to run
        intensity: low/medium/high (controls scan speed)
        port_range: (start_port, end_port) to scan
    """
    delays = {'low': 0.1, 'medium': 0.02, 'high': 0.005}
    delay = delays.get(intensity, 0.02)

    print(f"[Port Scan] Target: {target_ip}")
    print(f"[Port Scan] Range: {port_range[0]}-{port_range[1]}")
    print(f"[Port Scan] Duration: {duration}s")

    ports = list(range(port_range[0], port_range[1] + 1))
    random.shuffle(ports)

    scanned = 0
    open_ports = []
    start = time.time()

    for port in ports:
        if time.time() - start >= duration:
            break
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
        scanned += 1
        if scanned % 100 == 0:
            elapsed = time.time() - start
            print(f"  [{elapsed:.0f}s] Scanned {scanned} ports, {len(open_ports)} open")
        time.sleep(delay)

    elapsed = time.time() - start
    print(f"[Port Scan] Complete: {scanned} ports in {elapsed:.1f}s")
    print(f"  Open ports: {open_ports}")
    return scanned
