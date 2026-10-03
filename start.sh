#!/bin/sh
set -eu

cd "$(dirname "$0")"
PORT_TO_USE="${SERVER_PORT:-${PORT:-8000}}"
BOT_PYTHON="${BOT_PYTHON_BIN:-$PWD/.runtime/bot-venv/bin/python}"
BOT_URL="${BOT_INTERNAL_URL:-}"
if [ -z "$BOT_URL" ] && [ -f .env ]; then
  BOT_URL="$(sed -n 's/^BOT_INTERNAL_URL=//p' .env | tail -n 1 | tr -d "\"'")"
fi
RUN_LOCAL_BOT=0
case "$BOT_URL" in
  http://127.0.0.1|http://127.0.0.1:*) RUN_LOCAL_BOT=1 ;;
  https://*) RUN_LOCAL_BOT=0 ;;
  "") RUN_LOCAL_BOT=0 ;;
  *) echo "ERROR: BOT_INTERNAL_URL must use local HTTP or external HTTPS."; exit 1 ;;
esac

if ! command -v php >/dev/null 2>&1; then
  echo "ERROR: PHP CLI is missing. Build the included Dockerfile or use an image with PHP and Python 3."
  exit 127
fi

BOT_PID=""
if [ "$RUN_LOCAL_BOT" -eq 1 ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "WARNING: Python 3 is unavailable; starting the PHP website without its local bot. Configure BOT_INTERNAL_URL with the external bot's HTTPS address."
    RUN_LOCAL_BOT=0
  fi
fi

if [ "$RUN_LOCAL_BOT" -eq 1 ]; then
  if [ ! -x "$BOT_PYTHON" ]; then
    mkdir -p .runtime
    python3 -m venv .runtime/bot-venv
    BOT_PYTHON="$PWD/.runtime/bot-venv/bin/python"
  fi
  if ! "$BOT_PYTHON" -c 'import discord' >/dev/null 2>&1; then
    "$BOT_PYTHON" -m pip install --disable-pip-version-check -r bot/requirements.txt
  fi
  "$BOT_PYTHON" bot/main.py &
  BOT_PID=$!
fi
php -d upload_max_filesize=5M -d post_max_size=20M -d max_file_uploads=3 -S "0.0.0.0:${PORT_TO_USE}" -t . index.php &
PHP_PID=$!
stop_services() {
  kill "$PHP_PID" 2>/dev/null || true
  if [ -n "$BOT_PID" ]; then kill "$BOT_PID" 2>/dev/null || true; fi
  wait "$PHP_PID" 2>/dev/null || true
  if [ -n "$BOT_PID" ]; then wait "$BOT_PID" 2>/dev/null || true; fi
}
trap stop_services EXIT INT TERM

wait "$PHP_PID"
