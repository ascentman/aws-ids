#!/usr/bin/env python3
"""
Attack orchestrator — runs attacks in sequence for IDS testing.

Authorized lab testing only. All attacks target instances within
the isolated VPC (10.0.1.0/24).

Sequence: benign baseline → attacks → benign cooldown
"""
import argparse
import sys
import time

from attacks import (
    benign_traffic,
    ddos_syn_flood,
    ddos_udp_flood,
    ddos_http_flood,
    dos_slowloris,
    port_scan,
    brute_force_ssh,
)

ATTACK_MODULES = {
    'benign': ('BenignTraffic', benign_traffic),
    'syn_flood': ('DDoS-SYN_Flood', ddos_syn_flood),
    'udp_flood': ('DDoS-UDP_Flood', ddos_udp_flood),
    'http_flood': ('DDoS-HTTP_Flood', ddos_http_flood),
    'slowloris': ('DDoS-SlowLoris', dos_slowloris),
    'port_scan': ('Recon-PortScan', port_scan),
    'brute_force': ('DictionaryBruteForce', brute_force_ssh),
}


def run_full_demo(target_ip: str, duration_per_attack: int = 30,
                  intensity: str = 'medium', pause: int = 5):
    """
    Run full attack sequence.

    Order:
    1. Benign baseline (30s)
    2. SYN flood
    3. UDP flood
    4. HTTP flood
    5. Slowloris
    6. Port scan
    7. SSH brute force
    8. Benign cooldown (30s)
    """
    print("=" * 60)
    print("ATTACK RUNNER — IntegratedIDS Lab Test")
    print("=" * 60)
    print(f"Target: {target_ip}")
    print(f"Duration per attack: {duration_per_attack}s")
    print(f"Intensity: {intensity}")
    print(f"Pause between attacks: {pause}s")
    print()

    sequence = [
        ('benign', 'Baseline — Normal traffic'),
        ('syn_flood', 'DDoS SYN Flood'),
        ('udp_flood', 'DDoS UDP Flood'),
        ('http_flood', 'DDoS HTTP Flood'),
        ('slowloris', 'Slowloris DoS'),
        ('port_scan', 'Port Scan'),
        ('brute_force', 'SSH Brute Force'),
        ('benign', 'Cooldown — Normal traffic'),
    ]

    total_start = time.time()
    for i, (attack_key, description) in enumerate(sequence, 1):
        ciciot_class, module = ATTACK_MODULES[attack_key]
        print(f"\n{'='*60}")
        print(f"[{i}/{len(sequence)}] {description}")
        print(f"  CICIoT2023 class: {ciciot_class}")
        print(f"{'='*60}")

        try:
            module.run(
                target_ip=target_ip,
                duration=duration_per_attack,
                intensity=intensity,
            )
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            break
        except Exception as e:
            print(f"  Error: {e}")

        if i < len(sequence):
            print(f"\n  Pausing {pause}s...")
            time.sleep(pause)

    total_elapsed = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"ATTACK SEQUENCE COMPLETE")
    print(f"Total time: {total_elapsed:.0f}s")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description='IDS Lab Attack Runner')
    parser.add_argument('target', help='Target IP (victim, e.g., 10.0.1.20)')
    parser.add_argument('--duration', type=int, default=30,
                        help='Duration per attack in seconds (default: 30)')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'],
                        default='medium', help='Attack intensity')
    parser.add_argument('--pause', type=int, default=5,
                        help='Pause between attacks in seconds')
    parser.add_argument('--attack', choices=list(ATTACK_MODULES.keys()),
                        help='Run a single attack type')
    args = parser.parse_args()

    if args.attack:
        ciciot_class, module = ATTACK_MODULES[args.attack]
        print(f"Running single attack: {args.attack} ({ciciot_class})")
        module.run(args.target, args.duration, args.intensity)
    else:
        run_full_demo(args.target, args.duration, args.intensity, args.pause)


if __name__ == '__main__':
    main()
