"""
Configuration for the ML inference server.

All settings are configurable via environment variables.
"""

import os

import torch

# ---------------------------------------------------------------------------
# Model paths (HuggingFace model IDs or local paths)
# ---------------------------------------------------------------------------
MODEL_INJECTION: str = os.environ.get(
    "MODEL_INJECTION", "protectai/deberta-v3-base-prompt-injection-v2"
)

MODEL_TOXICITY: str = os.environ.get(
    "MODEL_TOXICITY", "unitary/toxic-bert"
)

MODEL_NER: str = os.environ.get(
    "MODEL_NER", "dslim/bert-base-NER"
)

# ---------------------------------------------------------------------------
# Inference settings
# ---------------------------------------------------------------------------
USE_ONNX: bool = os.environ.get("USE_ONNX", "true").lower() in ("true", "1", "yes")

MAX_LENGTH: int = int(os.environ.get("MAX_LENGTH", "512"))

# Auto-detect CUDA; override with DEVICE=cpu or DEVICE=cuda
_default_device = "cuda" if torch.cuda.is_available() else "cpu"
DEVICE: str = os.environ.get("DEVICE", _default_device)

# ---------------------------------------------------------------------------
# Server settings
# ---------------------------------------------------------------------------
PORT: int = int(os.environ.get("PORT", "5000"))

# API key for authenticating requests. If empty/unset, auth is disabled
# (local dev mode).
ML_API_KEY: str = os.environ.get("ML_API_KEY", "")
