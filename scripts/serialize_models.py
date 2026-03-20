#!/usr/bin/env python3
"""
Серіалізація моделей IntegratedIDS для AWS-демо.

Навчає LightGBM, IsolationForest, SHAP explainer на CICIoT2023
та зберігає всі артефакти у форматі joblib/json.
"""
import os
import sys
import json
import time
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import lightgbm as lgb
import shap
import joblib
from sklearn.preprocessing import RobustScaler, LabelEncoder, MinMaxScaler
from sklearn.ensemble import IsolationForest

SEED = 42
np.random.seed(SEED)

# --- Шляхи ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
DATASET_ROOT = os.path.join(PROJECT_ROOT, 'dataset')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '..', 'ids_server', 'models')
os.makedirs(OUTPUT_DIR, exist_ok=True)

DATA_DIR = os.path.join(DATASET_ROOT, 'CICIOT23')

# Holdout класи (zero-day симуляція)
HOLDOUT_CLASSES = ['Backdoor_Malware', 'BrowserHijacking', 'Uploading_Attack', 'CommandInjection']


def clean_features(df, cols):
    X = df[cols].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    medians = X.median()
    X = X.fillna(medians)
    return X, medians


def main():
    print("=" * 60)
    print("СЕРІАЛІЗАЦІЯ МОДЕЛЕЙ IntegratedIDS")
    print("=" * 60)

    # --- 1. Завантаження даних ---
    print("\n1. Завантаження CICIoT2023...")
    df_train = pd.read_csv(f'{DATA_DIR}/train/train.csv')
    df_test = pd.read_csv(f'{DATA_DIR}/test/test.csv')
    df_val = pd.read_csv(f'{DATA_DIR}/validation/validation.csv')
    print(f"   Train: {df_train.shape}, Test: {df_test.shape}, Val: {df_val.shape}")

    # --- 2. Розділення класів ---
    ALL_CLASSES = sorted(df_train['label'].unique())
    KNOWN_CLASSES = sorted([c for c in ALL_CLASSES if c not in HOLDOUT_CLASSES])
    print(f"\n2. Класи: {len(ALL_CLASSES)} всього, {len(KNOWN_CLASSES)} відомих, {len(HOLDOUT_CLASSES)} holdout")

    df_train_known = df_train[df_train['label'].isin(KNOWN_CLASSES)].copy()
    df_test_known = df_test[df_test['label'].isin(KNOWN_CLASSES)].copy()
    df_val_known = df_val[df_val['label'].isin(KNOWN_CLASSES)].copy()
    df_test_holdout = df_test[df_test['label'].isin(HOLDOUT_CLASSES)].copy()

    # --- 3. Попередня обробка ---
    print("\n3. Попередня обробка...")
    feature_cols = [c for c in df_train_known.columns if c != 'label']

    X_train_raw, feature_medians = clean_features(df_train_known, feature_cols)
    X_test_raw, _ = clean_features(df_test_known, feature_cols)
    X_val_raw, _ = clean_features(df_val_known, feature_cols)
    X_holdout_raw, _ = clean_features(df_test_holdout, feature_cols)

    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)
    X_val = scaler.transform(X_val_raw)
    X_holdout = scaler.transform(X_holdout_raw)

    le = LabelEncoder()
    le.fit(KNOWN_CLASSES)
    y_train = le.transform(df_train_known['label'])
    y_test = le.transform(df_test_known['label'])
    y_val = le.transform(df_val_known['label'])

    print(f"   Features: {len(feature_cols)}, Classes: {len(KNOWN_CLASSES)}")

    # --- 4. LightGBM ---
    print("\n4. Навчання LightGBM...")
    lgb_model = lgb.LGBMClassifier(
        n_estimators=500, max_depth=8, num_leaves=63,
        learning_rate=0.05, class_weight='balanced',
        subsample=0.8, colsample_bytree=0.8,
        reg_alpha=0.1, reg_lambda=0.1,
        random_state=SEED, n_jobs=-1, verbose=-1
    )
    t0 = time.time()
    lgb_model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(50, verbose=True), lgb.log_evaluation(100)]
    )
    print(f"   LightGBM: {time.time() - t0:.1f}s")

    from sklearn.metrics import accuracy_score, f1_score
    y_pred = lgb_model.predict(X_test)
    print(f"   Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"   F1 macro: {f1_score(y_test, y_pred, average='macro'):.4f}")

    # --- 5. SHAP Explainer ---
    print("\n5. SHAP TreeExplainer...")
    explainer = shap.TreeExplainer(lgb_model)
    # Тестове обчислення для валідації
    test_sv = explainer.shap_values(X_test[:10])
    print(f"   SHAP explainer ready (test shape: {np.array(test_sv).shape})")

    # --- 6. Isolation Forest ---
    print("\n6. Навчання Isolation Forest...")
    IF_MAX_TRAIN = 200000
    if len(X_train) > IF_MAX_TRAIN:
        if_idx = np.random.choice(len(X_train), IF_MAX_TRAIN, replace=False)
        X_if_train = X_train[if_idx]
    else:
        X_if_train = X_train

    iso_forest = IsolationForest(
        n_estimators=300, contamination='auto',
        max_features=0.8,
        max_samples=min(len(X_if_train), 50000),
        random_state=SEED, n_jobs=-1
    )
    t0 = time.time()
    iso_forest.fit(X_if_train)
    print(f"   IF: {time.time() - t0:.1f}s")

    # Anomaly score scaler
    iso_scores_test = -iso_forest.decision_function(X_test)
    anomaly_scaler = MinMaxScaler().fit(iso_scores_test.reshape(-1, 1))
    print(f"   Anomaly scores range: [{iso_scores_test.min():.4f}, {iso_scores_test.max():.4f}]")

    # --- 7. Збереження артефактів ---
    print("\n7. Збереження артефактів...")
    artifacts = {
        'lgb_model.pkl': lgb_model,
        'iso_forest.pkl': iso_forest,
        'shap_explainer.pkl': explainer,
        'robust_scaler.pkl': scaler,
        'anomaly_scaler.pkl': anomaly_scaler,
        'label_encoder.pkl': le,
        'feature_medians.pkl': feature_medians,
    }
    for name, obj in artifacts.items():
        path = os.path.join(OUTPUT_DIR, name)
        joblib.dump(obj, path)
        size_mb = os.path.getsize(path) / 1024 / 1024
        print(f"   {name}: {size_mb:.1f} MB")

    # Feature columns as JSON
    fc_path = os.path.join(OUTPUT_DIR, 'feature_cols.json')
    with open(fc_path, 'w') as f:
        json.dump(feature_cols, f)
    print(f"   feature_cols.json: {len(feature_cols)} features")

    # Config
    config = {
        'known_classes': list(le.classes_),
        'holdout_classes': HOLDOUT_CLASSES,
        'normal_class': 'BenignTraffic',
        'n_features': len(feature_cols),
        'n_classes': len(KNOWN_CLASSES),
        'thresholds': {
            'confidence': 0.7,
            'shap_consistency': 0.5,
            'anomaly': 0.6,
            'zero_day': 0.85
        }
    }
    cfg_path = os.path.join(OUTPUT_DIR, 'config.json')
    with open(cfg_path, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"   config.json saved")

    # --- 8. Тестова вибірка для replay ---
    print("\n8. Експорт тестової вибірки для replay...")
    n_replay = 1000
    replay_idx = np.random.choice(len(df_test), n_replay, replace=False)
    df_replay = df_test.iloc[replay_idx].reset_index(drop=True)
    replay_path = os.path.join(OUTPUT_DIR, 'test_sample.csv')
    df_replay.to_csv(replay_path, index=False)
    print(f"   test_sample.csv: {len(df_replay)} rows ({df_replay['label'].nunique()} classes)")

    # Holdout sample for zero-day demo
    n_holdout_sample = min(200, len(df_test_holdout))
    holdout_idx = np.random.choice(len(df_test_holdout), n_holdout_sample, replace=False)
    df_holdout_sample = df_test_holdout.iloc[holdout_idx].reset_index(drop=True)
    holdout_path = os.path.join(OUTPUT_DIR, 'holdout_sample.csv')
    df_holdout_sample.to_csv(holdout_path, index=False)
    print(f"   holdout_sample.csv: {len(df_holdout_sample)} rows (zero-day classes)")

    print("\n" + "=" * 60)
    print("СЕРІАЛІЗАЦІЯ ЗАВЕРШЕНА")
    print(f"Артефакти збережено в: {OUTPUT_DIR}")
    print("=" * 60)


if __name__ == '__main__':
    main()
