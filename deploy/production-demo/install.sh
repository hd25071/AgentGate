#!/usr/bin/env bash
set -euo pipefail

BUNDLE=""
DEST="/home/zhiyuan/agentgate-demo"
PORT="18081"
RUN_DEMO="false"
SKIP_BUILD="false"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2 ;;
    --dest) DEST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --run-demo) RUN_DEMO="true"; shift ;;
    --skip-build) SKIP_BUILD="true"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$BUNDLE" ] || [ ! -f "$BUNDLE" ]; then
  echo "bundle not found: $BUNDLE" >&2
  exit 2
fi
case "$DEST" in
  /opt/*|/home/*) ;;
  *) echo "destination must be under /opt or /home" >&2; exit 2 ;;
esac
case "$PORT" in
  *[!0-9]*|"") echo "invalid port: $PORT" >&2; exit 2 ;;
esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo "port out of range: $PORT" >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "docker daemon is not accessible" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "docker compose v2 is required" >&2; exit 2; }

APP_DIR="$DEST/app"
ENV_FILE="$DEST/agentgate.env"
project_owns_port="false"
if docker ps --filter 'name=^/agentgate-prod-demo-agentgate-1$' --format '{{.Ports}}' \
  | grep -q "127.0.0.1:$PORT->8080/tcp"; then
  project_owns_port="true"
fi

if [ "$project_owns_port" != "true" ] && ss -lntH 2>/dev/null | grep -q ":$PORT "; then
  echo "port $PORT is already in use" >&2
  exit 2
fi

mkdir -p "$APP_DIR"
tar -xzf "$BUNDLE" -C "$APP_DIR"

if [ ! -f "$ENV_FILE" ]; then
  secret() {
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  }
  token_secret="$(secret)"
  admin_token="$(secret)"
  while [ "$token_secret" = "$admin_token" ]; do
    admin_token="$(secret)"
  done
  umask 077
  sed \
    -e "s/^AG_TOKEN_SECRET=.*/AG_TOKEN_SECRET=$token_secret/" \
    -e "s/^AG_ADMIN_TOKEN=.*/AG_ADMIN_TOKEN=$admin_token/" \
    -e "s/^AG_PORT=.*/AG_PORT=$PORT/" \
    "$APP_DIR/deploy/production-demo/.env.prod-demo.example" > "$ENV_FILE"
fi

COMPOSE=(docker compose -p agentgate-prod-demo --env-file "$ENV_FILE" -f "$APP_DIR/docker-compose.yml" -f "$APP_DIR/deploy/production-demo/docker-compose.prod-demo.yml")

if [ "$SKIP_BUILD" = "true" ]; then
  "${COMPOSE[@]}" up -d
else
  "${COMPOSE[@]}" up -d --build
fi

ready="false"
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1; then
    ready="true"
    break
  fi
  sleep 2
done

if [ "$ready" != "true" ]; then
  "${COMPOSE[@]}" ps >&2 || true
  "${COMPOSE[@]}" logs --tail 120 agentgate >&2 || true
  echo "AgentGate did not become ready" >&2
  exit 1
fi

if [ "$RUN_DEMO" = "true" ]; then
  bash "$APP_DIR/deploy/production-demo/smoke.sh" \
    --app-dir "$APP_DIR" \
    --env-file "$ENV_FILE" \
    --port "$PORT"
fi

echo "AGENTGATE_DEMO=ready"
echo "AGENTGATE_ADMIN=http://127.0.0.1:$PORT/admin/ui"
echo "AGENTGATE_ENV_FILE=$ENV_FILE"
curl -fsS "http://127.0.0.1:$PORT/readyz"
echo
"${COMPOSE[@]}" exec -T agentgate agentgate-cli audit verify
