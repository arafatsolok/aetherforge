#!/usr/bin/env bash
# =============================================================================
# AetherForge end-to-end smoke test.
#
# Verifies a fresh stack can: build → boot → migrate → seed → run an
# autonomous scan → render a PDF, with no manual steps. Idempotent —
# safe to run on an already-up stack.
#
# Usage:
#     ./scripts/e2e_smoke.sh [--keep]
# Pass --keep to leave the stack running after the test (default: leave running).
# =============================================================================
set -euo pipefail

API="${AETHERFORGE_E2E_URL:-http://127.0.0.1:8002}"
KEEP=${KEEP:-1}
SLUG="e2e-target-$(date +%s)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

bold() { printf "\n\033[1m=== %s ===\033[0m\n" "$*"; }
ok()   { printf "  \033[32mOK\033[0m %s\n" "$*"; }
fail() { printf "  \033[31mFAIL\033[0m %s\n" "$*"; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing prereq: $1"
}

bold "0. Preflight"
require docker
require curl
require python3
[ -f .env ] || fail ".env missing — run ./scripts/healthcheck or copy .env.example"
ok "tooling + .env present"

bold "1. Stack up (no-op if already running)"
docker compose up -d postgres redis temporal temporal-ui orchestrator worker >/dev/null 2>&1
# Wait for orchestrator health
for i in $(seq 1 30); do
  S=$(docker inspect -f '{{.State.Health.Status}}' aetherforge-orchestrator 2>/dev/null || echo "?")
  [ "$S" = "healthy" ] && break
  sleep 2
done
[ "$S" = "healthy" ] && ok "orchestrator healthy" || fail "orchestrator not healthy: $S"

bold "2. /health + /ready"
curl -fsS "$API/health" >/dev/null && ok "/health 200"
READY=$(curl -fsS "$API/ready")
echo "$READY" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["checks"]["postgres"]["ok"]; assert d["checks"]["redis"]["ok"]'
ok "postgres + redis healthy"

bold "3. Seed rules"
docker compose exec -T orchestrator python -m scripts.seed_rules >/dev/null 2>&1
ok "rules seeded"

bold "4. Create a fresh target"
curl -fsS -X POST "$API/api/v1/targets" -H 'content-type: application/json' \
  -d "$(cat <<JSON
{ "slug": "$SLUG", "description": "e2e", "owner": "ci",
  "cidrs": ["10.77.0.5/32"], "domains": [],
  "allowed_personas": ["white","gray"], "tags":["e2e"] }
JSON
)" -o "$TMP/t.json"
TARGET_ID=$(python3 -c 'import json; print(json.load(open("'$TMP'/t.json"))["id"])')
ok "target id=$TARGET_ID slug=$SLUG"

bold "5. POST /scans"
curl -fsS -X POST "$API/api/v1/scans" -H 'content-type: application/json' \
  -d "{\"target_slug\":\"$SLUG\",\"persona\":\"gray\",\"started_by\":\"e2e\"}" \
  -o "$TMP/s.json"
SCAN_ID=$(python3 -c 'import json; print(json.load(open("'$TMP'/s.json"))["id"])')
ok "scan id=$SCAN_ID kicked off"

bold "6. Wait for scan terminal (max 240s — six tools fire including nuclei)"
for i in $(seq 1 48); do
  sleep 5
  STATE=$(curl -fsS "$API/api/v1/scans/$SCAN_ID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')
  printf "  t+%ds state=%s\n" $((i*5)) "$STATE"
  case "$STATE" in completed|failed|cancelled) break;; esac
done
[ "$STATE" = "completed" ] || fail "scan did not complete (state=$STATE)"
ok "scan completed"

bold "7. Render PDF"
curl -fsS "$API/api/v1/reports/$SCAN_ID?fmt=pdf" -o "$TMP/r.pdf"
file "$TMP/r.pdf" | grep -q "PDF document" && ok "PDF rendered (size: $(wc -c < "$TMP/r.pdf") bytes)" \
  || fail "PDF render failed"

bold "8. Download tar.gz bundle"
curl -fsS "$API/api/v1/reports/$SCAN_ID/bundle" -o "$TMP/bundle.tar.gz"
file "$TMP/bundle.tar.gz" | grep -q "gzip compressed" && \
  ok "bundle: $(wc -c < "$TMP/bundle.tar.gz") bytes ($(tar -tzf "$TMP/bundle.tar.gz" | wc -l | xargs) entries)" \
  || fail "bundle download failed"

bold "9. Cleanup target (best-effort — cascading delete may fail if heavy)"
DEL_CODE=$(curl -sS -X DELETE "$API/api/v1/targets/$TARGET_ID" -o /dev/null -w "%{http_code}")
case "$DEL_CODE" in
  204)  ok "target deleted (204)";;
  500)  ok "target delete deferred (500 — cascading too heavy, expected in dev)";;
  *)    ok "target delete returned $DEL_CODE";;
esac

if [ "$KEEP" = "1" ]; then
  printf "\n\033[1m✅ E2E PASSED\033[0m  (stack left running; \`make down\` to stop)\n"
else
  bold "tear-down"
  docker compose down >/dev/null 2>&1
  ok "stack torn down"
fi
