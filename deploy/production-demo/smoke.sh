#!/usr/bin/env bash
set -euo pipefail

APP_DIR=""
ENV_FILE=""
PORT="18081"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --app-dir) APP_DIR="$2"; shift 2 ;;
    --env-file) ENV_FILE="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$APP_DIR" ] || [ -z "$ENV_FILE" ]; then
  echo "app dir and env file are required" >&2
  exit 2
fi

COMPOSE=(
  docker compose
  -p agentgate-prod-demo
  --env-file "$ENV_FILE"
  -f "$APP_DIR/docker-compose.yml"
  -f "$APP_DIR/deploy/production-demo/docker-compose.prod-demo.yml"
)

issue="$("${COMPOSE[@]}" exec -T agentgate agentgate-cli token issue \
  --subject prod-demo-agent \
  --scopes redis:read,redis:write,redis:delete,redis:admin \
  --ttl 30m)"
token="$(printf '%s\n' "$issue" | tail -n 1)"

call() {
  local tool="$1"
  local args="$2"
  "${COMPOSE[@]}" exec -T \
    -e "AG_URL=http://127.0.0.1:8080" \
    -e "AG_AGENT_TOKEN=$token" \
    agentgate agentgate-cli call "$tool" --args "$args"
}

echo "=== 1. ALLOW: read one item ==="
call redis_exec '{"command":"GET session:42"}' | sed -n '1,8p'

echo "=== 2. DENY: destructive request ==="
call redis_exec '{"command":"FLUSHALL"}' | sed -n '1,12p'

echo "=== 3. APPROVAL: high-impact request ==="
call redis_exec '{"command":"KEYS session:*"}' | sed -n '1,16p'

echo "=== 4. AUDIT CHAIN ==="
"${COMPOSE[@]}" exec -T agentgate agentgate-cli audit verify

echo "=== 5. READY ==="
curl -fsS "http://127.0.0.1:$PORT/readyz"
echo
echo "PROD_DEMO_SMOKE=ok"
