"""
IntegratedIDS — standalone module for the 3-module IDS.

Combines LightGBM classifier, Isolation Forest anomaly detection,
and SHAP-Confidence Agreement Score for 4-level alert classification.
"""
import numpy as np


def normalize_shap(sv_raw):
    """Normalize SHAP values to list of [n_samples, n_features] per class."""
    if isinstance(sv_raw, list):
        return sv_raw
    elif isinstance(sv_raw, np.ndarray) and sv_raw.ndim == 3:
        return [sv_raw[:, :, c] for c in range(sv_raw.shape[2])]
    else:
        return [sv_raw]


def shap_consistency(shap_values_all_classes, proba_vector):
    """
    SHAP-Confidence Agreement Score.

    Checks if SHAP explanation points to the same class as the probability prediction:
    - If match: returns SHAP margin (0..1)
    - If mismatch: returns 0 (disagreement)
    """
    conf_class = np.argmax(proba_vector)
    shap_sums = np.array([sv.sum() for sv in shap_values_all_classes])
    shap_class = np.argmax(shap_sums)
    if conf_class == shap_class:
        sorted_sums = np.sort(shap_sums)[::-1]
        return (sorted_sums[0] - sorted_sums[1]) / (abs(sorted_sums[0]) + abs(sorted_sums[1]) + 1e-8)
    else:
        return 0.0


class IntegratedIDS:
    """
    Integrated IDS with 4-level alert system.

    Combines:
    - LightGBM multiclass classifier
    - SHAP-Confidence Agreement Score (selective — only for suspicious samples)
    - Isolation Forest anomaly detection (trained on all known classes)
    """

    NORMAL = 'NORMAL'
    KNOWN_ATTACK = 'KNOWN_ATTACK'
    SUSPICIOUS = 'SUSPICIOUS'
    ZERO_DAY = 'ZERO_DAY_CANDIDATE'

    def __init__(self, lgb_model, iso_forest, shap_explainer,
                 iso_scaler, label_encoder,
                 normal_class='BenignTraffic',
                 confidence_threshold=0.7,
                 shap_consistency_threshold=0.5,
                 anomaly_threshold=0.6,
                 zero_day_threshold=0.85):
        self.lgb_model = lgb_model
        self.iso_forest = iso_forest
        self.shap_explainer = shap_explainer
        self.iso_scaler = iso_scaler
        self.le = label_encoder
        self.conf_th = confidence_threshold
        self.shap_th = shap_consistency_threshold
        self.anom_th = anomaly_threshold
        self.zday_th = zero_day_threshold

        if normal_class in list(label_encoder.classes_):
            self.normal_idx = list(label_encoder.classes_).index(normal_class)
        else:
            self.normal_idx = 0

    def compute_anomaly_score(self, X):
        """Anomaly score: normalized IF decision function."""
        raw = -self.iso_forest.decision_function(X)
        return np.clip(self.iso_scaler.transform(raw.reshape(-1, 1)).flatten(), 0, 1)

    def compute_shap_consistency(self, X, predictions, batch_size=5000):
        """SHAP-Confidence Agreement Score for a batch of samples."""
        n = len(X)
        consistency = np.zeros(n)
        proba = self.lgb_model.predict_proba(X)

        for start in range(0, n, batch_size):
            end = min(start + batch_size, n)
            sv = normalize_shap(self.shap_explainer.shap_values(X[start:end]))
            proba_batch = proba[start:end]
            n_classes_local = len(sv)
            for i in range(end - start):
                sv_i = [sv[c][i] for c in range(n_classes_local)]
                consistency[start + i] = shap_consistency(sv_i, proba_batch[i])

        return consistency

    def predict(self, X, compute_shap=True, precomputed_consistency=None):
        """
        Full prediction pipeline with selective SHAP.

        SHAP is computed only for suspicious samples (low confidence or high
        anomaly score), speeding up processing 20-50x.

        Returns:
            predictions, alert_levels, details
        """
        n = len(X)

        # 1. LightGBM prediction + confidence
        predictions = self.lgb_model.predict(X)
        probabilities = self.lgb_model.predict_proba(X)
        confidence = probabilities.max(axis=1)

        # 2. Anomaly score (fast, computed for all)
        anomaly = self.compute_anomaly_score(X)

        # 3. SHAP consistency — SELECTIVE
        if precomputed_consistency is not None:
            consistency = precomputed_consistency
        elif compute_shap:
            suspicious_mask = (confidence < self.conf_th) | (anomaly > self.anom_th)
            consistency = np.ones(n)
            n_suspicious = suspicious_mask.sum()
            if n_suspicious > 0:
                consistency[suspicious_mask] = self.compute_shap_consistency(
                    X[suspicious_mask], predictions[suspicious_mask])
        else:
            consistency = np.ones(n) * 0.8

        # 4. Decision Matrix
        alert_levels = np.full(n, self.KNOWN_ATTACK, dtype=object)

        # NORMAL
        normal_mask = (predictions == self.normal_idx)
        alert_levels[normal_mask] = self.NORMAL

        # SUSPICIOUS
        suspicious_mask = ((confidence < self.conf_th) |
                           ((consistency < self.shap_th) & (anomaly > self.anom_th)))
        alert_levels[suspicious_mask] = self.SUSPICIOUS

        # ZERO-DAY (highest priority)
        zday_mask = (anomaly >= self.zday_th)
        alert_levels[zday_mask] = self.ZERO_DAY

        details = {
            'confidence': confidence,
            'consistency': consistency,
            'anomaly_score': anomaly,
            'probabilities': probabilities
        }

        return predictions, alert_levels, details

    def predict_single(self, X_single):
        """Predict a single sample (convenience wrapper)."""
        X = X_single.reshape(1, -1) if X_single.ndim == 1 else X_single
        preds, alerts, details = self.predict(X, compute_shap=True)
        pred_class = self.le.classes_[preds[0]] if preds[0] < len(self.le.classes_) else 'Unknown'
        return {
            'predicted_class': pred_class,
            'alert_level': alerts[0],
            'confidence': float(details['confidence'][0]),
            'anomaly_score': float(details['anomaly_score'][0]),
            'consistency': float(details['consistency'][0]),
        }
