"""
Replay engine: feeds test CSV samples through IntegratedIDS at configurable rate.

Provides verified demo results using the same features as training data.
"""
import asyncio
import time
from typing import Optional, Callable

import numpy as np
import pandas as pd


class ReplayEngine:
    """Replays test CSV samples through IntegratedIDS at a configurable rate."""

    def __init__(self, ids_model, scaler, feature_cols, feature_medians):
        self.ids = ids_model
        self.scaler = scaler
        self.feature_cols = feature_cols
        self.feature_medians = feature_medians
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self.stats = {
            'total_processed': 0,
            'alerts': {'NORMAL': 0, 'KNOWN_ATTACK': 0, 'SUSPICIOUS': 0, 'ZERO_DAY_CANDIDATE': 0},
            'start_time': None,
            'rate': 0,
        }

    def load_csv(self, csv_path: str):
        """Load test CSV for replay."""
        self.df = pd.read_csv(csv_path)
        self.true_labels = self.df['label'].values if 'label' in self.df.columns else None
        self.feature_data = self._prepare_features(self.df)
        return len(self.df)

    def _prepare_features(self, df):
        """Clean and scale feature data."""
        X = df[self.feature_cols].copy()
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(self.feature_medians)
        return self.scaler.transform(X.values)

    async def start(self, rate: float = 50.0, on_alert: Optional[Callable] = None,
                    include_holdout: bool = False, holdout_path: Optional[str] = None):
        """
        Start replaying samples.

        Args:
            rate: samples per second
            on_alert: async callback(alert_dict) for each classified sample
            include_holdout: whether to include holdout (zero-day) samples
            holdout_path: path to holdout CSV
        """
        if self.running:
            return

        self.running = True
        self.stats['start_time'] = time.time()
        self.stats['total_processed'] = 0
        for k in self.stats['alerts']:
            self.stats['alerts'][k] = 0

        data = self.feature_data
        labels = self.true_labels

        # Optionally mix in holdout samples
        if include_holdout and holdout_path:
            df_holdout = pd.read_csv(holdout_path)
            holdout_features = self._prepare_features(df_holdout)
            holdout_labels = df_holdout['label'].values if 'label' in df_holdout.columns else None

            data = np.vstack([data, holdout_features])
            if labels is not None and holdout_labels is not None:
                labels = np.concatenate([labels, holdout_labels])

            # Shuffle
            idx = np.random.permutation(len(data))
            data = data[idx]
            if labels is not None:
                labels = labels[idx]

        delay = 1.0 / rate
        idx = 0

        while self.running and idx < len(data):
            # Process in small batches for efficiency
            batch_end = min(idx + max(1, int(rate / 10)), len(data))
            X_batch = data[idx:batch_end]
            batch_labels = labels[idx:batch_end] if labels is not None else None

            preds, alerts, details = self.ids.predict(X_batch, compute_shap=True)

            for i in range(len(X_batch)):
                sample_idx = idx + i
                pred_class = self.ids.le.classes_[preds[i]] if preds[i] < len(self.ids.le.classes_) else 'Unknown'
                alert_level = alerts[i]

                self.stats['total_processed'] += 1
                self.stats['alerts'][alert_level] = self.stats['alerts'].get(alert_level, 0) + 1

                elapsed = time.time() - self.stats['start_time']
                self.stats['rate'] = self.stats['total_processed'] / elapsed if elapsed > 0 else 0

                alert_dict = {
                    'id': self.stats['total_processed'],
                    'timestamp': time.time(),
                    'predicted_class': pred_class,
                    'true_label': batch_labels[i] if batch_labels is not None else None,
                    'alert_level': alert_level,
                    'confidence': float(details['confidence'][i]),
                    'anomaly_score': float(details['anomaly_score'][i]),
                    'consistency': float(details['consistency'][i]),
                    'source': 'replay',
                }

                if on_alert:
                    await on_alert(alert_dict)

            idx = batch_end
            await asyncio.sleep(delay * (batch_end - (idx - len(X_batch))))

        self.running = False

    def stop(self):
        """Stop replay."""
        self.running = False
        if self._task:
            self._task.cancel()
