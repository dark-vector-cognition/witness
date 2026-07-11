#!/bin/zsh
set -euo pipefail

cd "${0:A:h}"

if ! command -v node >/dev/null 2>&1; then
  osascript -e 'display alert "DVC Agent Flight Recorder" message "Node.js 22 or later is required before first launch." as critical'
  exit 1
fi

npm run dev &
APP_PID=$!
trap 'kill "$APP_PID" 2>/dev/null || true' EXIT INT TERM

for attempt in {1..30}; do
  if curl -fsS http://localhost:3000/ >/dev/null 2>&1; then
    open http://localhost:3000/
    wait "$APP_PID"
    exit $?
  fi
  sleep 1
done

osascript -e 'display alert "DVC Agent Flight Recorder" message "The local interface did not become ready within 30 seconds." as critical'
exit 1
