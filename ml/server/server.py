"""
ML inference server for Kill-AI-Leak.

Uses HuggingFace transformer models for prompt injection detection,
toxicity classification, and jailbreak detection.  ONNX Runtime is used
for fast CPU inference when available, with automatic fallback to
PyTorch.

Models:
    - Injection / Jailbreak: protectai/deberta-v3-base-prompt-injection-v2
    - Toxicity:              unitary/toxic-bert

Endpoints:
    POST /predict       -- single prediction
    POST /predict/batch -- batch prediction
    GET  /health        -- liveness probe
"""

import logging
import threading
import time

from flask import Flask, jsonify, request

import config

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("ml-server")

# ---------------------------------------------------------------------------
# Rate limiting (simple in-memory counter)
# ---------------------------------------------------------------------------
_rate_lock = threading.Lock()
_rate_count = 0
_rate_window_start = time.time()
_RATE_LIMIT = 100  # max requests per 60-second window


# ---------------------------------------------------------------------------
# Before-request hooks: authentication and rate limiting
# ---------------------------------------------------------------------------

@app.before_request
def _check_auth():
    """Reject requests without a valid API key when ML_API_KEY is set."""
    if not config.ML_API_KEY:
        return  # Auth disabled (local dev mode)
    if request.endpoint == "health":
        return  # Always allow health checks
    key = request.headers.get("X-API-Key", "")
    if key != config.ML_API_KEY:
        log.warning("Unauthorized request: invalid or missing X-API-Key")
        return jsonify({"error": "unauthorized", "message": "Invalid or missing X-API-Key"}), 401


@app.before_request
def _check_rate_limit():
    """Simple per-minute rate limiter using an in-memory counter."""
    global _rate_count, _rate_window_start
    with _rate_lock:
        now = time.time()
        if now - _rate_window_start >= 60:
            _rate_count = 0
            _rate_window_start = now
        _rate_count += 1
        if _rate_count > _RATE_LIMIT:
            log.warning("Rate limit exceeded: %d requests in current window", _rate_count)
            return jsonify({"error": "rate_limit_exceeded", "message": "Too many requests, try again later"}), 429

# ---------------------------------------------------------------------------
# Globals populated by load_models()
# ---------------------------------------------------------------------------

injection_pipeline = None   # handles both "injection" and "jailbreak"
toxicity_pipeline = None
models_ready = False

# Expected toxicity output categories (our API contract)
TOXICITY_CATEGORIES = [
    "hate_speech", "violence", "self_harm", "sexual", "profanity", "bias",
]

# Mapping from toxic-bert label names to our categories.
# toxic-bert outputs: toxic, severe_toxic, obscene, threat, insult, identity_hate
TOXIC_BERT_MAP = {
    "toxic":         "toxic",          # kept separately, contributes to general score
    "severe_toxic":  "hate_speech",
    "obscene":       "profanity",
    "threat":        "violence",
    "insult":        "hate_speech",    # merged with hate_speech (max)
    "identity_hate": "bias",
}


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

def _load_pipeline_onnx(model_id: str, task: str = "text-classification"):
    """Try to load a model as an ONNX pipeline via optimum.  Returns a
    ``transformers.pipeline`` backed by ONNX Runtime on success, or
    ``None`` if ONNX export/load fails."""
    if not config.USE_ONNX:
        return None
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification

        log.info("Attempting ONNX load for %s ...", model_id)
        t0 = time.time()
        model = ORTModelForSequenceClassification.from_pretrained(
            model_id, export=True,
        )
        from transformers import AutoTokenizer, pipeline
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        pipe = pipeline(
            task,
            model=model,
            tokenizer=tokenizer,
            truncation=True,
            max_length=config.MAX_LENGTH,
        )
        elapsed = time.time() - t0
        log.info("ONNX pipeline ready for %s (%.1fs)", model_id, elapsed)
        return pipe
    except Exception as exc:
        log.warning("ONNX load failed for %s: %s -- falling back to PyTorch", model_id, exc)
        return None


def _load_pipeline_pytorch(model_id: str, task: str = "text-classification"):
    """Load a model using the standard transformers pipeline (PyTorch)."""
    from transformers import pipeline

    log.info("Loading PyTorch pipeline for %s ...", model_id)
    t0 = time.time()
    pipe = pipeline(
        task,
        model=model_id,
        tokenizer=model_id,
        device=config.DEVICE,
        truncation=True,
        max_length=config.MAX_LENGTH,
    )
    elapsed = time.time() - t0
    log.info("PyTorch pipeline ready for %s (%.1fs)", model_id, elapsed)
    return pipe


def _load_pipeline(model_id: str, task: str = "text-classification"):
    """Load with ONNX first; fall back to PyTorch."""
    pipe = _load_pipeline_onnx(model_id, task)
    if pipe is not None:
        return pipe
    return _load_pipeline_pytorch(model_id, task)


def load_models():
    """Download / cache and load all models.  Called once at startup."""
    global injection_pipeline, toxicity_pipeline, models_ready

    log.info("Loading models ...")
    overall_t0 = time.time()

    # -- Injection / Jailbreak model (single model for both) ----------------
    injection_pipeline = _load_pipeline(config.MODEL_INJECTION)

    # -- Toxicity model (multi-label) ---------------------------------------
    # toxic-bert is a multi-label classifier; use top_k=None to get all
    # label scores in a single forward pass.
    toxicity_pipeline = _load_pipeline(config.MODEL_TOXICITY)

    overall_elapsed = time.time() - overall_t0
    log.info("All models loaded in %.1fs", overall_elapsed)
    models_ready = True


def warmup():
    """Run one dummy prediction per model so the first real request is fast."""
    log.info("Warming up models ...")
    t0 = time.time()
    dummy = "This is a warmup sentence."
    predict_injection(dummy)
    predict_toxicity(dummy)
    elapsed = time.time() - t0
    log.info("Warmup complete in %.1fs", elapsed)


# ---------------------------------------------------------------------------
# Prediction helpers
# ---------------------------------------------------------------------------

def predict_injection(text: str) -> dict:
    """Return injection probability.

    The deberta model returns labels ``INJECTION`` / ``SAFE`` (or similar).
    We normalise to our contract: label in {injection, clean}, score = P(injection).
    """
    results = injection_pipeline(text, truncation=True, max_length=config.MAX_LENGTH)

    # results is a list of dicts: [{"label": "INJECTION", "score": 0.99}, ...]
    # Build a score map keyed on upper-cased label.
    score_map = {r["label"].upper(): float(r["score"]) for r in results}

    injection_score = score_map.get("INJECTION", 0.0)
    # If the model only returned a SAFE/BENIGN label, infer injection score.
    if "INJECTION" not in score_map:
        safe_score = score_map.get("SAFE", score_map.get("BENIGN", 1.0))
        injection_score = 1.0 - safe_score

    label = "injection" if injection_score >= 0.5 else "clean"
    return {
        "label": label,
        "score": round(injection_score, 6),
        "labels": {
            "injection": round(injection_score, 6),
            "clean": round(1.0 - injection_score, 6),
        },
    }


def predict_jailbreak(text: str) -> dict:
    """Jailbreak detection -- same model as injection (prompt-injection-v2
    handles both attack classes).  Returns labels keyed as jailbreak/clean
    to match the API contract."""
    results = injection_pipeline(text, truncation=True, max_length=config.MAX_LENGTH)

    score_map = {r["label"].upper(): float(r["score"]) for r in results}

    injection_score = score_map.get("INJECTION", 0.0)
    if "INJECTION" not in score_map:
        safe_score = score_map.get("SAFE", score_map.get("BENIGN", 1.0))
        injection_score = 1.0 - safe_score

    label = "jailbreak" if injection_score >= 0.5 else "clean"
    return {
        "label": label,
        "score": round(injection_score, 6),
        "labels": {
            "jailbreak": round(injection_score, 6),
            "clean": round(1.0 - injection_score, 6),
        },
    }


def predict_toxicity(text: str) -> dict:
    """Return per-category toxicity scores mapped to our label set.

    toxic-bert outputs per-category scores for:
        toxic, severe_toxic, obscene, threat, insult, identity_hate

    We map these to our expected categories:
        hate_speech, violence, self_harm, sexual, profanity, bias
    """
    # top_k=None returns scores for every label.
    results = toxicity_pipeline(text, top_k=None, truncation=True, max_length=config.MAX_LENGTH)

    # results is a list of dicts: [{"label": "toxic", "score": 0.98}, ...]
    raw_scores = {r["label"].lower(): float(r["score"]) for r in results}

    # Map raw scores to our categories.  Some raw labels merge (max) into
    # the same target category.
    mapped: dict[str, float] = {cat: 0.0 for cat in TOXICITY_CATEGORIES}

    for raw_label, target in TOXIC_BERT_MAP.items():
        raw_val = raw_scores.get(raw_label, 0.0)
        if target == "toxic":
            # The generic "toxic" score does not map 1:1 to any of our
            # categories.  Spread it lightly: it nudges hate_speech upward.
            mapped["hate_speech"] = max(mapped["hate_speech"], raw_val * 0.5)
            continue
        mapped[target] = max(mapped[target], raw_val)

    # self_harm and sexual are not directly covered by toxic-bert.
    # Leave them at 0.0 (the model does not predict these).

    # Round for cleaner JSON.
    mapped = {k: round(v, 6) for k, v in mapped.items()}

    max_cat = max(mapped, key=mapped.get)  # type: ignore[arg-type]
    max_score = mapped[max_cat]

    return {
        "label": max_cat if max_score >= 0.3 else "clean",
        "score": round(max_score, 6),
        "labels": mapped,
    }


PREDICTOR_MAP = {
    "injection": predict_injection,
    "toxicity":  predict_toxicity,
    "jailbreak": predict_jailbreak,
}


# ---------------------------------------------------------------------------
# Flask endpoints
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    """Liveness and readiness probe."""
    if not models_ready:
        return jsonify({"status": "not_ready"}), 503
    return jsonify({"status": "ok"}), 200


@app.route("/predict", methods=["POST"])
def predict():
    """Single prediction endpoint."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "request body must be JSON"}), 400

    text = data.get("text", "")
    model_type = data.get("model_type", "")

    if not text:
        return jsonify({"error": "text is required"}), 400
    if model_type not in PREDICTOR_MAP:
        return jsonify({
            "error": f"unknown model_type: {model_type}; "
                     f"expected one of {list(PREDICTOR_MAP.keys())}"
        }), 400

    start = time.time()
    result = PREDICTOR_MAP[model_type](text)
    elapsed_ms = (time.time() - start) * 1000
    log.info(
        "predict model_type=%s label=%s score=%.4f latency_ms=%.1f",
        model_type, result["label"], result["score"], elapsed_ms,
    )

    return jsonify(result), 200


@app.route("/predict/batch", methods=["POST"])
def predict_batch():
    """Batch prediction endpoint."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data, list):
        return jsonify({"error": "request body must be a JSON array"}), 400

    results = []
    start = time.time()
    for item in data:
        text = item.get("text", "")
        model_type = item.get("model_type", "")
        if not text or model_type not in PREDICTOR_MAP:
            results.append({"label": "error", "score": 0.0, "labels": {}})
            continue
        results.append(PREDICTOR_MAP[model_type](text))

    elapsed_ms = (time.time() - start) * 1000
    log.info("predict_batch size=%d latency_ms=%.1f", len(data), elapsed_ms)

    return jsonify(results), 200


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    load_models()
    warmup()
    log.info("Starting ML inference server on port %d ...", config.PORT)
    app.run(host="0.0.0.0", port=config.PORT, debug=False)
