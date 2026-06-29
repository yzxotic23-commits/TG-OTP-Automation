FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN python -m venv .venv \
    && .venv/bin/pip install --no-cache-dir --upgrade pip \
    && .venv/bin/pip install --no-cache-dir -r requirements.txt

COPY telegram_otp_allinone.py sheets_sync.py ./
COPY accounts.json shooteraccounts.json ./
COPY railway/ /railway/

RUN chmod +x /railway/entrypoint.sh /railway/run-with-env.sh

ENV PYTHONUNBUFFERED=1
ENV RAILWAY_DATA_DIR=/data

# LISTEN (~170 session SQLite)
ENV TELEGRAM_LISTEN_MIN_FD=8192

ENTRYPOINT ["/railway/entrypoint.sh"]
