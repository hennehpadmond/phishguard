import os
import time
import queue
import threading
import pickle
import numpy as np
import joblib
from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
from feature_extractor import get_feature_vector, get_feature_names, is_valid_url
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import VotingClassifier, RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), 'frontend')

app = Flask(__name__, static_folder=os.path.join(FRONTEND_DIR, 'static'), static_url_path='/static')
CORS(app)

# SSE subscriber queues
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()


def _push_event(data: dict):
    """Push a JSON event to all connected SSE clients."""
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(data)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)

# ── Paths ──────────────────────────────────────────────────────────────────────
# notebook folder is INSIDE backend folder
NOTEBOOK_DIR = os.path.join(BASE_DIR, 'notebook')  # backend/notebook/

MODEL_PATHS = {
    'logistic_regression': os.path.join(NOTEBOOK_DIR, 'phishing_pipeline.pkl'),
    'svm':                 os.path.join(NOTEBOOK_DIR, 'svm_phishing_model.pkl'),
    'decision_tree':       os.path.join(NOTEBOOK_DIR, 'decision_tree_phishing_model.pkl'),
    'ensemble':            os.path.join(NOTEBOOK_DIR, 'ensemble_phishing_model.pkl'),
}

SCALER_PATH   = os.path.join(NOTEBOOK_DIR, 'scaler.pkl')
PIPELINE_PATH = os.path.join(NOTEBOOK_DIR, 'phishing_pipeline.pkl')
RFE_PATH      = os.path.join(NOTEBOOK_DIR, 'rfe_selector.pkl')

# ── Globals ────────────────────────────────────────────────────────────────────
models   = {}
scaler   = None
pipeline = None
rfe      = None


# ── Safe loader ────────────────────────────────────────────────────────────────
def safe_load(path, label):
    try:
        import joblib
        obj = joblib.load(path)
        print(f"  [OK]   {label}")
        return obj
    except Exception as e:
        print(f"  [FAIL] {label}")
        print(f"         Reason: {e}")
        return None


def load_all():
    global scaler, pipeline, rfe

    print("\n== Loading artifacts ========================================")
    print(f"  Backend dir:  {BASE_DIR}")
    print(f"  Notebook dir: {NOTEBOOK_DIR}")
    print()

    # Scaler
    if os.path.exists(SCALER_PATH):
        scaler = safe_load(SCALER_PATH, 'scaler.pkl')
    else:
        print(f"  [SKIP] scaler.pkl not found")

    # Pipeline
    if os.path.exists(PIPELINE_PATH):
        pipeline = safe_load(PIPELINE_PATH, 'phishing_pipeline.pkl')
    else:
        print(f"  [SKIP] phishing_pipeline.pkl not found")

    # RFE selector (optional)
    if os.path.exists(RFE_PATH):
        rfe = safe_load(RFE_PATH, 'rfe_selector.pkl')

    # Individual models
    for name, path in MODEL_PATHS.items():
        if os.path.exists(path):
            m = safe_load(path, f'{os.path.basename(path)}')
            if m is not None:
                models[name] = m
        else:
            print(f"  [SKIP] {os.path.basename(path)} not found")

    print()
    print("=============================================================")
    print(f"  Models loaded:   {list(models.keys()) or 'None'}")
    print(f"  Scaler loaded:   {scaler is not None}")
    print(f"  Pipeline loaded: {pipeline is not None}")
    print(f"  RFE loaded:      {rfe is not None}")

    if not models and pipeline is None:
        print("\n  [!] No models loaded.")
        print("     -> Open backend/phishing_detection.ipynb")
        print("     -> Click Run All")
        print("     -> Restart app.py\n")
    else:
        print("\n  [OK] API ready -- http://localhost:5000\n")


load_all()



# ── Predict ────────────────────────────────────────────────────────────────────
def predict_url(url, model_name='svm'):
    start          = time.perf_counter()
    feature_vector = get_feature_vector(url)
    features       = np.array(feature_vector).reshape(1, -1)

    # Use the requested model
    if model_name not in models:
        if not models:
            raise ValueError(
                "No models loaded. "
                "Run backend/phishing_detection.ipynb (Run All Cells) "
                "then restart app.py."
            )
        model_name = list(models.keys())[0]
        print(f"  [INFO] Falling back to model: {model_name}")

    model = models[model_name]

    # Models are pipelines that handle their own scaling, or don't need scaling (DecisionTree)
    prediction = model.predict(features)[0]
    
    try:
        # Get probability for the predicted class
        class_idx = list(model.classes_).index(int(prediction))
        confidence = float(model.predict_proba(features)[0][class_idx])
    except AttributeError:
        # Fallback if model doesn't support predict_proba
        confidence = 1.0

    latency_ms = (time.perf_counter() - start) * 1000

    result = {
        'url':        url,
        'verdict':    'legitimate' if int(prediction) == 1 else 'phishing',
        'is_safe':    int(prediction) == 1,
        'confidence': round(confidence * 100, 2),
        'latency_ms': round(latency_ms, 3),
        'model_used': model_name,
    }
    # Push to SSE subscribers
    threading.Thread(target=_push_event, args=(result,), daemon=True).start()
    return result


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route('/', methods=['GET'])
def home():
    ready = bool(models or pipeline)
    return jsonify({
        'message': 'PhishGuard Detection API',
        'status':  'ready' if ready else 'no_models_loaded',
        'endpoints': {
            'GET  /dashboard':     'Beautiful web interface / GUI',
            'POST /predict':       'Predict a single URL',
            'POST /predict/batch': 'Predict multiple URLs (max 100)',
            'GET  /stream':        'Server-Sent Events stream of all detections',
            'GET  /models':        'List loaded models',
            'GET  /health':        'Health check',
            'GET  /features':      'List feature names',
        }
    })


@app.route('/dashboard')
def dashboard():
    """Serves the frontend interface directly from the Flask backend."""
    return send_from_directory(FRONTEND_DIR, 'index.html')


# ── SSE Stream ─────────────────────────────────────────────────────────────────
@app.route('/stream', methods=['GET'])
def stream():
    """Server-Sent Events endpoint — pushes every detection result to subscribers."""
    import json as _json

    client_q: queue.Queue = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.append(client_q)

    def event_generator():
        # Send a connected ping first
        yield 'event: connected\ndata: {"status":"connected"}\n\n'
        try:
            while True:
                try:
                    data = client_q.get(timeout=25)
                    yield f'data: {_json.dumps(data)}\n\n'
                except queue.Empty:
                    # Heartbeat to keep connection alive
                    yield ': heartbeat\n\n'
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if client_q in _sse_clients:
                    _sse_clients.remove(client_q)

    return Response(
        event_generator(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':               'no-cache',
            'X-Accel-Buffering':           'no',
            'Access-Control-Allow-Origin': '*',
        }
    )


@app.route('/health', methods=['GET'])
def health():
    ready = bool(models or pipeline)
    return jsonify({
        'status':          'healthy' if ready else 'degraded',
        'models_loaded':   list(models.keys()),
        'scaler_loaded':   scaler is not None,
        'rfe_loaded':      rfe is not None,
        'pipeline_loaded': pipeline is not None,
        'message':         'Ready' if ready else 'Run training notebook first',
    })


@app.route('/models', methods=['GET'])
def list_models():
    return jsonify({
        'models':            list(models.keys()),
        'pipeline_loaded':   pipeline is not None,
    })


@app.route('/features', methods=['GET'])
def list_features():
    return jsonify({
        'count':    32,
        'features': get_feature_names(),
    })


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(silent=True)

    if not data or 'url' not in data:
        return jsonify({
            'error':   'Request body must contain "url"',
            'example': {'url': 'https://example.com', 'model': 'svm'}
        }), 400

    url        = str(data.get('url', '')).strip()
    model_name = data.get('model', 'svm')

    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    check = url if url.startswith('http') else 'http://' + url
    if not is_valid_url(check):
        return jsonify({'error': f'Invalid URL format: {url}'}), 400

    try:
        return jsonify(predict_url(url, model_name)), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 503
    except Exception as e:
        return jsonify({'error': f'Prediction failed: {e}'}), 500


@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    data = request.get_json(silent=True)

    if not data or 'urls' not in data:
        return jsonify({'error': 'Body must contain "urls" list'}), 400

    urls = data.get('urls', [])
    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({'error': '"urls" must be a non-empty list'}), 400
    if len(urls) > 100:
        return jsonify({'error': 'Maximum 100 URLs per batch'}), 400

    model_name     = data.get('model', 'svm')
    results, errors = [], []

    for url in urls:
        url = str(url).strip()
        try:
            results.append(predict_url(url, model_name))
        except Exception as e:
            errors.append({'url': url, 'error': str(e)})

    return jsonify({
        'total':   len(urls),
        'results': results,
        'errors':  errors,
    }), 200


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n[PhishGuard] Phishing URL Detection API")
    print("   http://localhost:5000\n")
    app.run(debug=False, host='0.0.0.0', port=5000)
