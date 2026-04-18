#!/usr/bin/env bash
# =============================================================================
# msfrpcd launcher — initialises the DB, starts msfrpcd in foreground.
# =============================================================================
set -euo pipefail

: "${MSF_RPC_USER:?MSF_RPC_USER is required}"
: "${MSF_RPC_PASS:?MSF_RPC_PASS is required}"
: "${MSF_RPC_PORT:=55553}"
: "${MSF_DB_PATH:=/root/.msf4/db}"

echo "[*] Initialising Metasploit database (idempotent)..."
mkdir -p "${MSF_DB_PATH}"

# msfdb reinit is idempotent
msfdb init >/dev/null 2>&1 || true

echo "[*] Starting msfrpcd on 0.0.0.0:${MSF_RPC_PORT} as ${MSF_RPC_USER}..."
exec msfrpcd \
  -U "${MSF_RPC_USER}" \
  -P "${MSF_RPC_PASS}" \
  -p "${MSF_RPC_PORT}" \
  -a 0.0.0.0 \
  -S \
  -f
