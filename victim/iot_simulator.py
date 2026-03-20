#!/usr/bin/env python3
"""
IoT device simulator — runs lightweight network services
to generate traffic patterns for IDS testing.

Services:
- HTTP server on port 80 (web interface)
- Telnet on port 23 (IoT device access)
- Fake SSH on port 2222 (accepts connections, rejects auth)
"""
import asyncio
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler


# --- HTTP Service (port 80) ---
class IoTWebHandler(BaseHTTPRequestHandler):
    """Simple IoT device web interface."""

    def do_GET(self):
        if self.path == '/status':
            body = '{"device":"IoT-Sensor-01","status":"online","temp":22.5,"uptime":3600}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
        elif self.path == '/config':
            body = '{"ssid":"IoT-Network","firmware":"v2.1.3","ip":"10.0.1.20"}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
        else:
            body = '''<html><head><title>IoT Device</title></head><body>
            <h1>IoT Sensor Dashboard</h1>
            <p>Temperature: 22.5C</p><p>Humidity: 45%</p>
            <p>Status: Online</p>
            <p><a href="/status">API Status</a> | <a href="/config">Config</a></p>
            </body></html>'''
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(content_length)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        body = '{"status":"ok"}'
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        print(f"[HTTP] {self.client_address[0]} - {format % args}")


def run_http(port=80):
    server = HTTPServer(('0.0.0.0', port), IoTWebHandler)
    print(f"[HTTP] Listening on port {port}")
    server.serve_forever()


# --- Telnet Service (port 23) ---
def handle_telnet_client(conn, addr):
    """Handle a single telnet connection."""
    try:
        conn.sendall(b"\r\nIoT-Sensor-01 login: ")
        username = b""
        while not username.endswith(b"\n"):
            data = conn.recv(1024)
            if not data:
                return
            username += data

        conn.sendall(b"Password: ")
        password = b""
        while not password.endswith(b"\n"):
            data = conn.recv(1024)
            if not data:
                return
            password += data

        # Always reject (simulate locked-down device)
        conn.sendall(b"\r\nLogin incorrect\r\n")
        print(f"[Telnet] Failed login from {addr[0]}: {username.strip().decode(errors='ignore')}")
    except Exception as e:
        print(f"[Telnet] Error with {addr}: {e}")
    finally:
        conn.close()


def run_telnet(port=23):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    print(f"[Telnet] Listening on port {port}")
    while True:
        conn, addr = sock.accept()
        print(f"[Telnet] Connection from {addr[0]}")
        threading.Thread(target=handle_telnet_client, args=(conn, addr), daemon=True).start()


# --- Fake SSH Service (port 2222) ---
def handle_ssh_client(conn, addr):
    """Handle a fake SSH connection — sends banner and closes."""
    try:
        conn.sendall(b"SSH-2.0-IoTDevice_1.0\r\n")
        data = conn.recv(1024)
        # After banner exchange, close (no real SSH)
        time.sleep(1)
        conn.close()
        print(f"[SSH] Connection from {addr[0]} (banner exchanged)")
    except Exception as e:
        print(f"[SSH] Error with {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def run_ssh(port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    print(f"[SSH] Listening on port {port}")
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_ssh_client, args=(conn, addr), daemon=True).start()


def main():
    print("=" * 50)
    print("IoT Device Simulator")
    print("=" * 50)
    print("Services:")
    print("  HTTP  — port 80")
    print("  Telnet — port 23")
    print("  SSH   — port 2222")
    print("=" * 50)

    threads = [
        threading.Thread(target=run_http, args=(80,), daemon=True),
        threading.Thread(target=run_telnet, args=(23,), daemon=True),
        threading.Thread(target=run_ssh, args=(2222,), daemon=True),
    ]
    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down IoT simulator...")


if __name__ == '__main__':
    main()
