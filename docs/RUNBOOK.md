# AetherForge — Operator Runbook

One-page reference for running, monitoring, and recovering the platform.

---

## Day-zero checklist

```bash
# 1. Clone + secrets
cp .env.example .env
chmod 600 .env                          # required in production
# Edit .env — set strong passwords for every CHANGE_ME row.
# Set AETHERFORGE_FORBIDDEN_CIDRS to a deny range that EXCLUDES your scope
# (default 0.0.0.0/0 forbids the whole internet by design).

# 2. Enable auth (REQUIRED in production)
# When AETHERFORGE_API_KEY is set, /api/v1/* requires the X-API-Key header
# and /ui/* requires login via the session cookie. Unset = dev mode only.
echo "AETHERFORGE_API_KEY=$(openssl rand -hex 32)" >> .env

# 3. Build + boot core
make build
make up

# 4. First-time DB init
make migrate
make seed                               # rules + KB

# 5. Optional heavy services
docker compose --profile exploit up -d  # msfrpcd
docker compose --profile scan    up -d  # OpenVAS
docker compose --profile monitor up -d  # Wazuh manager

# 6. Verify
curl -fsS http://127.0.0.1:8002/health  # /health is always public
KEY=$(grep AETHERFORGE_API_KEY .env | cut -d= -f2)
curl -fsS -H "X-API-Key: $KEY" http://127.0.0.1:8002/api/v1/rules?size=1
make e2e                                # full smoke test
```

## Authentication

**Two credentials are accepted:**

| Channel | How | When to use |
| --- | --- | --- |
| `X-API-Key` header | Send `X-API-Key: <AETHERFORGE_API_KEY>` on every request | CLI, CI, automation, programmatic clients |
| Session cookie    | Sign in via `POST /ui/login` form (browser) | Operator console at `/ui/*` |

**Login flow (browser):**
1. Visit any `/ui/*` URL → middleware redirects to `/ui/login?next=<path>`.
2. Submit the form with the API key value. On success the server rotates
   the signed session cookie (fresh `sid` + `login_at` per login) and
   redirects to the originally requested page.
3. Sign out from the top nav (`POST /ui/logout` clears the session).

**Always-public paths (no auth needed):** `/health`, `/ready`,
`/metrics`, `/static/*`, `/openapi.json`, `/docs`, `/redoc`,
`/ui/login`, `/ui/logout`.

**Security events emitted:** every 401 logs `auth.api.denied` /
`auth.ui.denied` / `auth.unknown.denied` (structlog); failed
`/ui/login` POSTs log `ui.login.failed`. Successful logins log
`ui.login.success`. Wire these into your SIEM to alert on
credential stuffing.

**Rotation:** generate a new key and restart the orchestrator. All
existing sessions become invalid (the session cookie is signed with
`AETHERFORGE_SECRET_KEY`, so rotating that key invalidates them too).

---

## Daily operation

> All `/api/v1/*` examples below require `-H "X-API-Key: $AETHERFORGE_API_KEY"`
> when auth is enabled. Browser flows use `/ui/login` first.

| Task | Command |
| --- | --- |
| Sign in (browser)  | open `http://127.0.0.1:8002/` → redirected to `/ui/login` |
| Sign out (browser) | top-nav **Sign out** button (POST `/ui/logout`) |
| Start a scan       | `curl -X POST -H "X-API-Key: $K" .../api/v1/scans -d '{"target_slug":"…","persona":"gray"}'` |
| Tail audit (live)  | open `http://127.0.0.1:8002/ui/scans/<id>` (SSE) |
| Triage findings    | `http://127.0.0.1:8002/ui/findings` |
| Download report    | `curl -H "X-API-Key: $K" …/api/v1/reports/<id>?fmt=pdf` |
| Bundle for offline | `curl -H "X-API-Key: $K" …/api/v1/reports/<id>/bundle` |
| Drift inspection   | `curl -H "X-API-Key: $K" …/api/v1/drift/<target_id>` |
| Continuous monitor | `curl -X POST -H "X-API-Key: $K" .../api/v1/drift/monitor -d '{"target_slug":…,"interval_seconds":21600}'` |
| Stop monitor       | `curl -X POST -H "X-API-Key: $K" .../api/v1/drift/monitor/<slug>/stop` |
| Stack status       | `make status` |

---

## Personas — operational meaning

| Persona | Allowed phases | Black-box flag | Common use |
| --- | --- | --- | --- |
| **white** | `recon.passive` only | n/a | Asset inventory, no probes touch the target |
| **gray**  | + active recon, vuln_scan, exploit.safe | n/a | CI gate, regular VA |
| **black** | full kill-chain incl. post-exploit & exfil sim | **target.replica_only must be `true`** | Lab/replica only — refused on production targets at API ingress (HTTP 403) |

Switch persona mid-scan: `POST .../api/v1/scans/<id>/escalate?to=black&authorised_by=…`

---

## Safety gates (cannot be turned off)

1. **`AETHERFORGE_FORBIDDEN_CIDRS`** — wildcard deny that overrides any allow.
2. **`Target.allowed_personas`** — listed personas only.
3. **`Target.replica_only`** — black persona requires this `true`. Default `false` = production-safe.
4. **Argv sanitiser** — every Docker arg passes the allow-list regex; shell metas (`$ \` ; | & < > " ' \\`) rejected.
5. **Sandbox policy ceilings** — 4 GiB / 2 h / 512 PIDs hard caps; `--cap-drop=ALL`, read-only rootfs, no-new-privs, AppArmor.
6. **Audit log is immutable** — append-only, monotonic per-scan sequence, ULIDs.

---

## Common incidents

### Workflow stuck in `running` with no progress
```bash
docker compose logs worker --tail=100 | grep -E "Failed activation|RPCError|TimeoutError"
# Inspect at http://127.0.0.1:8088 (Temporal UI)
# Send stop signal:
curl -X POST "http://127.0.0.1:8002/api/v1/scans/<id>/stop?reason=stuck"
```

### `executor.image_missing` for a tool
```bash
docker build -t aetherforge/<tool>:latest docker/tools/<tool>/
docker compose restart worker
```

### `wazuh.push.skip` / `msf.rpc.unreachable`
Expected when the relevant `--profile` isn't up. Activities are best-effort
and never fail the scan. To enable:
```bash
docker compose --profile exploit up -d  # for MSF
docker compose --profile monitor up -d  # for Wazuh
```

### Volume permission denied on artefacts
Phase 8 entrypoints (`docker/{orchestrator,worker}/entrypoint.sh`) chown
`/opt/aetherforge/data/artifacts` to the right uid AND align the
in-container `aetherforge` user with the host docker socket's GID on
every boot — **no manual chown is needed**. If you do see EACCES on a
fresh deployment, check that compose isn't overriding `user:` (which
would skip the entrypoint's privilege drop) and that
`docker-compose.override.yml` is not present.

### Drift comparing different runs of the same target shows wild add/remove
The fingerprint must be scan-independent (Phase 7 fix). If you see this on
a fork, verify `app/parsers/__init__.py:fingerprint()` does NOT include
`scan_id` in its hash payload.

---

## Backup + restore

```bash
# Postgres dump
docker compose exec -T postgres pg_dump -U aetherforge -Fc aetherforge > db.dump

# Artefact dir (named volume)
docker run --rm -v autonomous_vapt_platform_artifacts:/src -v "$PWD":/dst \
  alpine tar -czf /dst/artifacts.tar.gz -C /src .

# Restore
docker compose exec -T -i postgres pg_restore -U aetherforge -d aetherforge < db.dump
docker run --rm -v autonomous_vapt_platform_artifacts:/dst -v "$PWD":/src \
  alpine sh -c 'cd /dst && tar -xzf /src/artifacts.tar.gz'
```

---

## Panic stop / nuke

```bash
make panic                # kill all containers, keep volumes
make nuke CONFIRM=yes     # destroy volumes too (irreversible)
```

---

## Where things live

```
data/artifacts/<scan>/<execution>/{stdout,stderr,exit_code,meta.json}
rules/<persona>/<file>.yaml      → seeded into DB by `make seed`
configs/personas.yaml             → overlay over the hardcoded baseline
configs/tools.yaml                → per-tool image + sandbox overrides
configs/targets.yaml              → optional declarative target inventory
migrations/versions/              → Alembic revisions
docs/ARCHITECTURE.md              → full design diagrams
```

---

## Phase recap

| Phase | Theme | Key artefact |
| --- | --- | --- |
| 0 | Skeleton + Docker Compose | `docker-compose.yml`, all 13 tool Dockerfiles |
| 1 | Rule Engine + Persona + KB | `app/core/rule_engine/`, 16 baseline rules |
| 2 | Tool Wrappers + Sandbox Executor | `app/executor/docker_executor.py`, 13 wrappers |
| 3 | Temporal Workflows + Loop | `AutonomousScanWorkflow`, 11 activities |
| 4 | Recon + Scanning + dedup | nuclei/httpx/subfinder images, fact dedup |
| 5 | Exploitation + replica_only gate | `MsfExecutor`, replica_only flag |
| 6 | Dashboard + PDF reporter | HTMX dashboard, WeasyPrint PDF |
| 7 | Wazuh + drift detection | `PostgresDriftDetector`, `ContinuousMonitorWorkflow` |
| 8 | Hardening + evasion + e2e | docker-GID entrypoint, evasion profiles, `make e2e` |

`make e2e` runs the full pipeline (build → boot → migrate → seed → scan
→ PDF render → tar.gz bundle → cleanup) in under 60 s.
