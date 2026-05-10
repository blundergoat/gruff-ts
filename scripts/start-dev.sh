#!/usr/bin/env bash
set -euo pipefail

HOST="${GRUFF_HOST:-127.0.0.1}"
PORT="${GRUFF_PORT:-8767}"
PROJECT_ROOT="${GRUFF_PROJECT_ROOT:-$(pwd)}"

npm run start-dev -- --host "$HOST" --port "$PORT" --project-root "$PROJECT_ROOT"
