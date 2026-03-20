#!/usr/bin/env python3
"""
Створення збалансованої тестової вибірки для replay-демо.

300 BenignTraffic + 700 стратифікованих атак із CICIoT2023 test set.
Holdout класи виключені (вони в holdout_sample.csv).
"""
import os
import sys
import numpy as np
import pandas as pd

SEED = 42
np.random.seed(SEED)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
DATASET_DIR = os.path.join(PROJECT_ROOT, 'dataset', 'CICIOT23')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '..', 'ids_server', 'models')

HOLDOUT_CLASSES = ['Backdoor_Malware', 'BrowserHijacking', 'Uploading_Attack', 'CommandInjection']

N_BENIGN = 300
N_ATTACK = 700


def main():
    test_path = os.path.join(DATASET_DIR, 'test', 'test.csv')
    if not os.path.exists(test_path):
        print(f"ERROR: {test_path} not found")
        sys.exit(1)

    print("Завантаження test.csv...")
    df = pd.read_csv(test_path)
    print(f"  Всього: {len(df)} рядків, {df['label'].nunique()} класів")

    # Виключаємо holdout класи
    df_known = df[~df['label'].isin(HOLDOUT_CLASSES)].copy()

    # --- BenignTraffic ---
    df_benign = df_known[df_known['label'] == 'BenignTraffic']
    n_benign = min(N_BENIGN, len(df_benign))
    sampled_benign = df_benign.sample(n=n_benign, random_state=SEED)
    print(f"  BenignTraffic: {n_benign} зразків")

    # --- Стратифіковані атаки ---
    df_attacks = df_known[df_known['label'] != 'BenignTraffic']
    attack_classes = sorted(df_attacks['label'].unique())
    n_per_class = N_ATTACK // len(attack_classes)
    remainder = N_ATTACK - n_per_class * len(attack_classes)

    attack_samples = []
    for i, cls in enumerate(attack_classes):
        df_cls = df_attacks[df_attacks['label'] == cls]
        n = n_per_class + (1 if i < remainder else 0)
        n = min(n, len(df_cls))
        attack_samples.append(df_cls.sample(n=n, random_state=SEED))

    sampled_attacks = pd.concat(attack_samples, ignore_index=True)
    print(f"  Атаки: {len(sampled_attacks)} зразків із {len(attack_classes)} класів")

    # --- Об'єднання та перемішування ---
    df_balanced = pd.concat([sampled_benign, sampled_attacks], ignore_index=True)
    df_balanced = df_balanced.sample(frac=1, random_state=SEED).reset_index(drop=True)

    output_path = os.path.join(OUTPUT_DIR, 'test_sample.csv')
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    df_balanced.to_csv(output_path, index=False)

    print(f"\nЗбережено: {output_path}")
    print(f"  Всього: {len(df_balanced)} рядків")
    print(f"  Розподіл:")
    for label, count in df_balanced['label'].value_counts().items():
        print(f"    {label}: {count}")


if __name__ == '__main__':
    main()
