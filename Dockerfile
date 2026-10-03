FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN ./build.sh && python -m pytest -q tests

# One worker: pending Kyber handshake keys are kept in memory.
ENV SESSION_COOKIE_SECURE=1
CMD gunicorn --workers 1 --threads 8 --bind 0.0.0.0:${PORT:-8000} app:app
