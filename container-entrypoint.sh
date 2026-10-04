#!/bin/sh
set -eu

PORT_TO_USE="${SERVER_PORT:-${PORT:-8080}}"
case "$PORT_TO_USE" in
  ''|*[!0-9]*) echo "ERROR: SERVER_PORT/PORT must be a numeric TCP port." >&2; exit 2 ;;
esac
if [ "$PORT_TO_USE" -lt 1 ] || [ "$PORT_TO_USE" -gt 65535 ]; then
  echo "ERROR: SERVER_PORT/PORT is outside the valid TCP port range." >&2
  exit 2
fi

sed -ri "s/^Listen [0-9]+$/Listen ${PORT_TO_USE}/" /etc/apache2/ports.conf
sed -ri "s/<VirtualHost \\*:[0-9]+>/<VirtualHost *:${PORT_TO_USE}>/" /etc/apache2/sites-enabled/000-default.conf

exec "$@"
