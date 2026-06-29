#!/bin/bash
# Load /app/.env then exec (Railway Variables → entrypoint writes .env)
set -a
[[ -f /app/.env ]] && . /app/.env
set +a
exec "$@"
