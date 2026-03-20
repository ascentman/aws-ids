"""
FastAPI service for IntegratedIDS.

Endpoints:
    POST /predict        — single sample classification
    POST /predict_batch  — batch classification
    POST /replay/start   — start replaying test CSV
    POST /replay/stop    — stop replay
    POST /capture/start  — start classifying live captured traffic
    POST /capture/stop   — stop capture processing
    GET  /alerts         — recent alerts (JSON)
    GET  /stats          — alert distribution stats
    GET  /               — HTML dashboard
    WS   /ws/alerts      — real-time alert feed
"""
import asyncio
import json
import logging
import os
import time
from collections import deque
from typing import List, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')

import joblib
import numpy as np
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from integrated_ids import IntegratedIDS
from feature_extractor import extract_features_from_pcap, features_to_array
from replay_engine import ReplayEngine

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')

app = FastAPI(title="IntegratedIDS API", version="1.0")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# --- Global state ---
ids_model: Optional[IntegratedIDS] = None
scaler = None
feature_cols = None
feature_medians = None
replay_engine: Optional[ReplayEngine] = None
recent_alerts = deque(maxlen=500)
alert_stats = {
    'NORMAL': 0, 'KNOWN_ATTACK': 0, 'SUSPICIOUS': 0, 'ZERO_DAY_CANDIDATE': 0,
    'total': 0, 'start_time': time.time(),
    'attack_types': {},
}
# Per-level metric accumulators: {level: {'confidence_sum', 'anomaly_sum', 'consistency_sum', 'count'}}
level_metrics = {
    level: {'confidence_sum': 0.0, 'anomaly_sum': 0.0, 'consistency_sum': 0.0, 'count': 0}
    for level in ['NORMAL', 'KNOWN_ATTACK', 'SUSPICIOUS', 'ZERO_DAY_CANDIDATE']
}
ws_clients: List[WebSocket] = []
capture_running = False


def load_models():
    """Load all model artifacts from disk."""
    global ids_model, scaler, feature_cols, feature_medians, replay_engine

    print("Loading model artifacts...")
    lgb_model = joblib.load(os.path.join(MODELS_DIR, 'lgb_model.pkl'))
    iso_forest = joblib.load(os.path.join(MODELS_DIR, 'iso_forest.pkl'))
    shap_explainer = joblib.load(os.path.join(MODELS_DIR, 'shap_explainer.pkl'))
    scaler = joblib.load(os.path.join(MODELS_DIR, 'robust_scaler.pkl'))
    anomaly_scaler = joblib.load(os.path.join(MODELS_DIR, 'anomaly_scaler.pkl'))
    label_encoder = joblib.load(os.path.join(MODELS_DIR, 'label_encoder.pkl'))
    feature_medians = joblib.load(os.path.join(MODELS_DIR, 'feature_medians.pkl'))

    with open(os.path.join(MODELS_DIR, 'feature_cols.json')) as f:
        feature_cols = json.load(f)

    with open(os.path.join(MODELS_DIR, 'config.json')) as f:
        config = json.load(f)

    thresholds = config.get('thresholds', {})
    ids_model = IntegratedIDS(
        lgb_model=lgb_model,
        iso_forest=iso_forest,
        shap_explainer=shap_explainer,
        iso_scaler=anomaly_scaler,
        label_encoder=label_encoder,
        normal_class=config.get('normal_class', 'BenignTraffic'),
        confidence_threshold=thresholds.get('confidence', 0.7),
        shap_consistency_threshold=thresholds.get('shap_consistency', 0.5),
        anomaly_threshold=thresholds.get('anomaly', 0.6),
        zero_day_threshold=thresholds.get('zero_day', 0.85),
    )

    replay_engine = ReplayEngine(ids_model, scaler, feature_cols, feature_medians)
    print(f"Models loaded: {len(feature_cols)} features, {config.get('n_classes')} classes")


@app.on_event("startup")
async def startup():
    load_models()


# --- Utility ---
async def broadcast_alert(alert: dict):
    """Send alert to all connected WebSocket clients."""
    msg = json.dumps(alert, default=str)
    disconnected = []
    for ws in ws_clients:
        try:
            await ws.send_text(msg)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        ws_clients.remove(ws)


async def process_alert(alert: dict):
    """Record alert and broadcast to WebSocket clients."""
    recent_alerts.appendleft(alert)
    alert_stats['total'] += 1
    level = alert['alert_level']
    alert_stats[level] = alert_stats.get(level, 0) + 1
    attack_type = alert.get('predicted_class', 'Unknown')
    alert_stats['attack_types'][attack_type] = alert_stats['attack_types'].get(attack_type, 0) + 1

    # Accumulate per-level metrics
    if level in level_metrics:
        m = level_metrics[level]
        m['count'] += 1
        m['confidence_sum'] += alert.get('confidence', 0)
        m['anomaly_sum'] += alert.get('anomaly_score', 0)
        m['consistency_sum'] += alert.get('consistency', 0.8)

    await broadcast_alert(alert)


def prepare_features(data: dict) -> np.ndarray:
    """Prepare a single sample's features for prediction."""
    X = np.zeros((1, len(feature_cols)))
    for i, col in enumerate(feature_cols):
        val = data.get(col, 0)
        if val is None or (isinstance(val, float) and (np.isinf(val) or np.isnan(val))):
            val = float(feature_medians.get(col, 0)) if hasattr(feature_medians, 'get') else 0
        X[0, i] = val
    return scaler.transform(X)


# --- Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.post("/predict")
async def predict_single(data: dict):
    """Classify a single sample."""
    X = prepare_features(data)
    result = ids_model.predict_single(X[0])
    alert = {
        'id': alert_stats['total'] + 1,
        'timestamp': time.time(),
        'source': 'api',
        **result
    }
    await process_alert(alert)
    return result


@app.post("/predict_batch")
async def predict_batch(samples: List[dict]):
    """Classify a batch of samples."""
    X = np.vstack([prepare_features(s) for s in samples])
    preds, alerts, details = ids_model.predict(X, compute_shap=False)
    results = []
    for i in range(len(samples)):
        pred_class = ids_model.le.classes_[preds[i]] if preds[i] < len(ids_model.le.classes_) else 'Unknown'
        result = {
            'predicted_class': pred_class,
            'alert_level': alerts[i],
            'confidence': float(details['confidence'][i]),
            'anomaly_score': float(details['anomaly_score'][i]),
        }
        results.append(result)
        alert = {
            'id': alert_stats['total'] + 1,
            'timestamp': time.time(),
            'source': 'api_batch',
            **result
        }
        await process_alert(alert)
    return results


@app.post("/predict_pcap")
async def predict_pcap(file: UploadFile = File(...)):
    """Classify traffic from an uploaded PCAP file."""
    pcap_bytes = await file.read()
    logging.getLogger(__name__).info(f"predict_pcap: received {len(pcap_bytes)} bytes from {file.filename}")
    feature_dicts = extract_features_from_pcap(pcap_bytes)
    if not feature_dicts:
        return {"count": 0, "error": "No flows extracted from PCAP", "results": []}

    X = features_to_array(feature_dicts, feature_cols)
    X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = scaler.transform(X_clean)

    preds, alerts, details = ids_model.predict(X_scaled, compute_shap=False)
    results = []
    for i in range(len(X_scaled)):
        pred_class = ids_model.le.classes_[preds[i]] if preds[i] < len(ids_model.le.classes_) else 'Unknown'
        result = {
            'predicted_class': pred_class,
            'alert_level': alerts[i],
            'confidence': float(details['confidence'][i]),
            'anomaly_score': float(details['anomaly_score'][i]),
            'src_ip': feature_dicts[i].get('_src_ip', ''),
            'dst_ip': feature_dicts[i].get('_dst_ip', ''),
        }
        results.append(result)
        alert = {
            'id': alert_stats['total'] + 1,
            'timestamp': time.time(),
            'source': 'pcap',
            **result
        }
        await process_alert(alert)
    return {"count": len(results), "results": results}


@app.post("/replay/start")
async def replay_start(rate: float = 50.0, include_holdout: bool = True):
    """Start replaying test CSV samples through the model."""
    csv_path = os.path.join(MODELS_DIR, 'test_sample.csv')
    holdout_path = os.path.join(MODELS_DIR, 'holdout_sample.csv')

    if not os.path.exists(csv_path):
        return {"error": "test_sample.csv not found. Run serialize_models.py first."}

    n = replay_engine.load_csv(csv_path)
    asyncio.create_task(
        replay_engine.start(
            rate=rate,
            on_alert=process_alert,
            include_holdout=include_holdout,
            holdout_path=holdout_path if include_holdout else None,
        )
    )
    return {"status": "started", "samples": n, "rate": rate, "include_holdout": include_holdout}


@app.post("/replay/stop")
async def replay_stop():
    """Stop replay."""
    replay_engine.stop()
    return {"status": "stopped", "stats": replay_engine.stats}


@app.post("/capture/start")
async def capture_start(ids_server_url: str = "http://localhost:8000"):
    """Placeholder for starting live capture processing."""
    global capture_running
    capture_running = True
    return {"status": "capture_started", "note": "Send PCAPs to POST /predict_pcap"}


@app.post("/capture/stop")
async def capture_stop():
    """Stop capture processing."""
    global capture_running
    capture_running = False
    return {"status": "capture_stopped"}


@app.post("/clear")
async def clear_alerts():
    """Clear all alerts and reset stats."""
    global alert_stats, level_metrics
    recent_alerts.clear()
    alert_stats = {
        'NORMAL': 0, 'KNOWN_ATTACK': 0, 'SUSPICIOUS': 0, 'ZERO_DAY_CANDIDATE': 0,
        'total': 0, 'start_time': time.time(),
        'attack_types': {},
    }
    level_metrics = {
        level: {'confidence_sum': 0.0, 'anomaly_sum': 0.0, 'consistency_sum': 0.0, 'count': 0}
        for level in ['NORMAL', 'KNOWN_ATTACK', 'SUSPICIOUS', 'ZERO_DAY_CANDIDATE']
    }
    return {"status": "cleared"}


@app.get("/alerts")
async def get_alerts(limit: int = 50):
    """Get recent alerts."""
    alerts_list = list(recent_alerts)[:limit]
    return {"count": len(alerts_list), "alerts": alerts_list}


@app.get("/stats")
async def get_stats():
    """Get alert distribution stats."""
    elapsed = time.time() - alert_stats['start_time']
    rate = alert_stats['total'] / elapsed if elapsed > 0 else 0
    return {
        'total': alert_stats['total'],
        'rate': round(rate, 1),
        'elapsed': round(elapsed, 1),
        'alerts': {
            'NORMAL': alert_stats.get('NORMAL', 0),
            'KNOWN_ATTACK': alert_stats.get('KNOWN_ATTACK', 0),
            'SUSPICIOUS': alert_stats.get('SUSPICIOUS', 0),
            'ZERO_DAY_CANDIDATE': alert_stats.get('ZERO_DAY_CANDIDATE', 0),
        },
        'attack_types': dict(sorted(
            alert_stats['attack_types'].items(),
            key=lambda x: x[1], reverse=True
        )[:20]),
        'replay_running': replay_engine.running if replay_engine else False,
        'capture_running': capture_running,
    }


@app.get("/decision_stats")
async def decision_stats():
    """Per-level average metrics for the Decision Engine panel."""
    result = {}
    for level in ['NORMAL', 'KNOWN_ATTACK', 'SUSPICIOUS', 'ZERO_DAY_CANDIDATE']:
        m = level_metrics[level]
        n = m['count']
        result[level] = {
            'count': n,
            'avg_confidence': round(m['confidence_sum'] / n, 4) if n > 0 else 0,
            'avg_anomaly': round(m['anomaly_sum'] / n, 4) if n > 0 else 0,
            'avg_consistency': round(m['consistency_sum'] / n, 4) if n > 0 else 0,
        }
    return result


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert feed."""
    await websocket.accept()
    ws_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in ws_clients:
            ws_clients.remove(websocket)


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)
