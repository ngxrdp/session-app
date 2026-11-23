#!/bin/sh
# Start the full app: Node bot server (serves telegram-web + session APIs)
# plus an optional public HTTPS tunnel for testing on a phone.
set -eu

BASE=$(cd "$(dirname "$0")" && pwd)
BOT="$BASE/bot"
PORT=${PORT:-3000}
LOG=${LOG:-"$BASE/server.log"}

if [ ! -d "$BOT/node_modules" ]; then
  (cd "$BOT" && npm install --no-audit --no-fund)
fi

APP_URL_VALUE=${APP_URL:-}
if [ -z "$APP_URL_VALUE" ] && [ "${TUNNEL:-1}" = "1" ]; then
  rm -f "$BASE/tunnel.log"
  nohup ssh -tt -p 443 -R0:127.0.0.1:$PORT \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 -o ConnectTimeout=15 a.pinggy.io > "$BASE/tunnel.log" 2>&1 &
  i=0
  while [ $i -lt 40 ]; do
    APP_URL_VALUE=$(grep -oE 'https://[a-z0-9-]+\.run\.pinggy-free\.link' "$BASE/tunnel.log" 2>/dev/null | head -1 || true)
    [ -n "$APP_URL_VALUE" ] && break
    i=$((i + 1))
    sleep 1
  done
  if [ -z "$APP_URL_VALUE" ]; then
    echo "Could not obtain tunnel URL; see $BASE/tunnel.log" >&2
    exit 1
  fi
  echo "APP_URL=$APP_URL_VALUE"
fi

echo "Starting server on port $PORT (log: $LOG)"
cd "$BOT"
PORT="$PORT" APP_URL="$APP_URL_VALUE" nohup node bot.js >> "$LOG" 2>&1 &
echo $! > "$BASE/server.pid"
sleep 2
curl -fsS "http://127.0.0.1:$PORT/" >/dev/null
echo "Ready. Open: ${APP_URL_VALUE:-http://127.0.0.1:$PORT}"
