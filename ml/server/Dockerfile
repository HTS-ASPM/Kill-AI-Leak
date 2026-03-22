FROM python:3.11-slim

WORKDIR /app

# System dependencies required by torch / onnxruntime / sentencepiece.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Use a persistent HuggingFace cache inside the image.
ENV HF_HOME=/app/models

# Install Python dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download models during build so the container starts fast.
RUN python -c "\
from transformers import pipeline; \
pipeline('text-classification', model='protectai/deberta-v3-base-prompt-injection-v2'); \
pipeline('text-classification', model='unitary/toxic-bert')"

COPY config.py .
COPY server.py .

EXPOSE 5000

CMD ["python", "server.py"]
