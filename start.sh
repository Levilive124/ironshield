#!/bin/sh
set -eu

cd "$(dirname "$0")"
PORT_TO_USE="${SERVER_PORT:-${PORT:-8000}}"

if ! command -v php >/dev/null 2>&1; then
  echo "ERROR: PHP CLI is missing. Use PHP 8.1 or newer for this standalone website server."
  exit 127
fi

php -d upload_max_filesize=5M -d post_max_size=20M -d max_file_uploads=3 -S "0.0.0.0:${PORT_TO_USE}" -t . index.php &
PHP_PID=$!
stop_services() {
  kill "$PHP_PID" 2>/dev/null || true
  wait "$PHP_PID" 2>/dev/null || true
}
trap stop_services EXIT INT TERM

wait "$PHP_PID"
