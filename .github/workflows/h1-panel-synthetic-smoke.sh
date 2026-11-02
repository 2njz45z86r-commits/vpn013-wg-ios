#!/usr/bin/env bash
# Synthetic disposable container only; no production connections, files, or keys.
set -euo pipefail
image='ghcr.io/h1cloudltd/3x-ui-ptero@sha256:e9f38aa7d3282fa9c00baac9f2245d41853a98842f8e48b8843c09921511d2f9'
name="wg-panel-check-${GITHUB_RUN_ID:?}"
base="${RUNNER_TEMP:?}/h1-synthetic-home"
mkdir -p "$base/.xray-cache"
chmod 777 "$base"
cp "$1" "$base/.xray-cache/xray-26.6.27"
chmod 755 "$base/.xray-cache" "$base/.xray-cache/xray-26.6.27"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull "$image" >/dev/null
docker run -d --name "$name" --network none --cap-drop ALL --security-opt no-new-privileges \
  --memory 1g --cpus 2 --mount "type=bind,src=$base,dst=/home/container" \
  -e STARTUP='/bin/sh /app/start.sh 25119' -e XUI_VERSION=image -e XRAY_PIN_VERSION=26.6.27 \
  -e XUI_USERNAME=fixtureuser -e XUI_PASSWORD=fixturepassword -e XUI_WEBBASEPATH=fixture \
  -e FAKE_RAM_MB=0 -e FAKE_LOAD=0 "$image" >/dev/null
for _ in $(seq 1 90); do
  if docker exec "$name" sh -c 'curl -sS -o /dev/null --max-time 1 http://127.0.0.1:25119/fixture/login' >/dev/null 2>&1; then
    break
  fi
  if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then
    echo 'Synthetic panel exited before becoming ready' >&2
    exit 1
  fi
  sleep 1
done
docker exec "$name" sh -c 'curl -sS -o /dev/null --max-time 2 http://127.0.0.1:25119/fixture/login'
docker exec "$name" sh -c 'command -v python3 >/dev/null && command -v sqlite3 >/dev/null'
docker exec "$name" sh -c '/home/container/bin/xray-linux-amd64 version | head -n 1'
docker exec "$name" sh -c "sqlite3 /home/container/db/x-ui.db \"select 'synthetic_subscription_port=' || value from settings where key='subPort';\""
echo 'synthetic_panel_started=true isolated_network=true production_contact=false'
