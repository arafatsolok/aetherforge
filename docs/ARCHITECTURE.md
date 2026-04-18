# AetherForge — Architecture

This document is the authoritative source for how the platform is wired
together. Diagrams should always match the code — if you change one,
change the other.

---

## 1. Guiding principles

1. **Zero inference at runtime.** No LLM, no neural net, no stochastic
   decision node. Every next action is the output of a pure function of
   `(world_state, persona, rule_set)`.
2. **Durable by construction.** Long-running state lives in Postgres or
   Temporal, never in process memory. Crashing a worker must not lose a
   single pending command.
3. **Scope is a contract.** The command generator refuses any output
   whose destination is outside the scope declared in
   `configs/targets.yaml` or the target record.
4. **Everything is an artifact.** stdout, stderr, parsed facts, exit
   codes, and the very command-line that was run are all persisted with
   a monotonic sequence number. You can reconstruct the full session
   offline from the audit table.
5. **Tools are cattle.** Each invocation of a security tool is a fresh,
   ephemeral container joined to the target network. No persistent state
   inside tool containers.

---

## 2. Service topology

```
                                                ┌───────────────────┐
                                                │   Operator (you)  │
                                                └──────────┬────────┘
                                                           │  HTTPS / WS
                                                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                            aetherforge_backplane                     │
│                                                                      │
│ ┌─────────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────────┐ │
│ │ Orchestrator│◄─►│ Postgres │◄─►│ Temporal │◄─►│   Worker(s)      │ │
│ │  (FastAPI)  │   │   16     │   │  server  │   │ (Temporal +      │ │
│ │             │   │ (JSONB)  │   │          │   │  RQ consumer)    │ │
│ └──────┬──────┘   └──────────┘   └──────────┘   └────────┬─────────┘ │
│        │                                                  │           │
│        ▼                                                  ▼           │
│ ┌─────────────┐                                    ┌─────────────┐    │
│ │   Redis     │◄──────────────── pub/sub ─────────►│   Redis     │    │
│ │  (queue +   │                                    │  (same)     │    │
│ │   locks +   │                                    │             │    │
│ │   state kv) │                                    └─────────────┘    │
│ └─────────────┘                                                       │
└──────────────────────────────────────────────────────────────────────┘
        │                                                  │
        │  (Docker API: docker.sock)                       │  spawn
        ▼                                                  ▼
┌──────────────────────────────────────────────────────────────────────┐
│                             aetherforge_targets                      │
│                                                                      │
│  ┌──────┐ ┌───────┐ ┌────────────┐ ┌─────────┐ ┌───────┐ ┌─────────┐ │
│  │ nmap │ │ nuclei│ │  nettacker │ │ sqlmap  │ │ nikto │ │  msf    │ │
│  └──────┘ └───────┘ └────────────┘ └─────────┘ └───────┘ └─────────┘ │
│              (each spawned per-invocation, removed on exit)          │
└─────────────────────────────────┬────────────────────────────────────┘
                                  │
                                  ▼
                          ┌──────────────┐
                          │   Replica    │
                          │ under test   │
                          └──────────────┘
```

---

## 3. The autonomous loop

The loop is authored as a **Temporal workflow** so it survives worker
restarts and can be paused/resumed/killed surgically. Each iteration is
one workflow *signal* cycle:

```
╔════════════════════════════════════════════════════════════════════════╗
║                         Autonomous VAPT loop                          ║
╠════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║   ┌──────────────┐                                                     ║
║   │  Iteration   │                                                     ║
║   │  start       │                                                     ║
║   └──────┬───────┘                                                     ║
║          ▼                                                             ║
║  ┌──────────────────┐   fact list                                      ║
║  │  1. Observe      │──────┐                                           ║
║  │  (read world     │      │                                           ║
║  │   state)         │      │                                           ║
║  └──────────────────┘      ▼                                           ║
║                    ┌──────────────────────┐                            ║
║                    │ 2. Evaluate rules    │                            ║
║                    │  (Rule Engine)       │                            ║
║                    │  persona-gated       │                            ║
║                    └──────────┬───────────┘                            ║
║                               ▼                                        ║
║                    ┌──────────────────────┐                            ║
║                    │ 3. Pick next action  │                            ║
║                    │  = highest-priority  │                            ║
║                    │  unexecuted rule     │                            ║
║                    └──────────┬───────────┘                            ║
║                               │    (none)                              ║
║                               ├──────────► sleep / escalate persona    ║
║                               ▼                                        ║
║                    ┌──────────────────────┐                            ║
║                    │ 4. Generate command  │                            ║
║                    │  (pydantic-validated │                            ║
║                    │   + scope-checked)   │                            ║
║                    └──────────┬───────────┘                            ║
║                               ▼                                        ║
║                    ┌──────────────────────┐                            ║
║                    │ 5. Execute (Docker   │                            ║
║                    │  sandbox, cgroup-    │                            ║
║                    │  capped, timeout)    │                            ║
║                    └──────────┬───────────┘                            ║
║                               ▼                                        ║
║                    ┌──────────────────────┐                            ║
║                    │ 6. Parse output,     │                            ║
║                    │   extract new facts  │                            ║
║                    │   (tool parser)      │                            ║
║                    └──────────┬───────────┘                            ║
║                               ▼                                        ║
║                    ┌──────────────────────┐                            ║
║                    │ 7. Persist (facts,   │                            ║
║                    │  findings, audit,    │                            ║
║                    │  drift snapshot)     │                            ║
║                    └──────────┬───────────┘                            ║
║                               ▼                                        ║
║                    ┌──────────────────────┐                            ║
║                    │ 8. Decide: continue, │                            ║
║                    │  escalate persona,   │                            ║
║                    │  or terminate        │                            ║
║                    └──────────┬───────────┘                            ║
║                               ▼                                        ║
║                         loop back to 1                                 ║
╚════════════════════════════════════════════════════════════════════════╝
```

Steps 1–8 correspond to the activities implemented in
`app.workflows.activities.*`. Step 5 is the only step with network I/O
outside the backplane.

---

## 4. Database schema (Phase 0 outline)

All tables use `id BIGSERIAL PRIMARY KEY` + a `created_at` /
`updated_at` timestamp. Core tables (fleshed out in Phase 1):

| Table          | Purpose                                                       |
| -------------- | ------------------------------------------------------------- |
| `targets`      | Hosts / CIDRs / domains in scope                              |
| `scans`        | A single autonomous loop run against a target                 |
| `personas`     | White / gray / black definitions + per-run overrides          |
| `rules`        | Versioned rule definitions (JSONB body)                       |
| `rule_matches` | Which rule matched which fact on which iteration              |
| `facts`        | Parsed observations (open port, service banner, CVE hit, …)  |
| `findings`     | Human-reviewable vulnerabilities (severity + CVSS)            |
| `executions`   | One row per tool-container invocation                         |
| `artifacts`    | Large blobs (XML, PCAP, PDF) stored on disk + pointer in DB   |
| `audit_log`    | Immutable append-only log of every generated command          |
| `drift`        | Delta snapshots between consecutive scans                     |

All 13 SQLModel classes are implemented (Phase 1+) and live under
`app/models/`. The schema is migrated via Alembic — see
`migrations/versions/` for the versioned upgrades.

---

## 5. Rule schema (preview — fully defined in Phase 1)

```yaml
# rules/gray_hat/nmap_deep_scan_on_open_port.yaml
id: r.scan.nmap.deep_on_open_port
version: 1
persona: [gray, black]
phase: enumeration
priority: 60
description: >
  When a fact of type `port_open` is present and has not yet been deep-scanned,
  run a version-detection scan against that single port.

when:
  all:
    - fact_type: port_open
    - not_fact: { fact_type: service_banner, where: { port: $fact.port } }

then:
  action: execute_tool
  tool:  nmap
  params:
    target:   $fact.host
    ports:    [$fact.port]
    flags:    ["-sV", "-sC", "--version-intensity", "5"]
  on_success:
    - emit_fact: service_banner
  on_failure:
    - cooldown_seconds: 300
```

Rules are YAML on disk, hot-loaded into `rules` (JSONB). The loader
validates each rule against `app/core/rule_engine/schema.py`.

---

## 6. Persona enforcement

Persona is a *capability set*, not a mode. Every rule declares which
personas may fire it. When a scan runs, a `PersonaContext` is attached
to the workflow — the rule engine filters the candidate rules by
persona before ranking.

Escalation is **explicit**: a `gray` scan cannot escalate to `black`
unless an operator signals the workflow with `escalate_persona`. The
workflow records the escalation request and its initiator in the audit
log.

---

## 7. Tool execution sandbox

A single tool invocation is:

```
TOOL_SPEC(YAML)  +  FACT(parsed from prior step)
     │
     ▼
CommandGenerator      — builds argv + env, checks scope/persona
     │
     ▼
DockerExecutor        — docker run --rm --network aetherforge_targets
                         --cap-drop=ALL
                         --read-only --tmpfs /tmp
                         --memory=... --cpu-shares=...
                         --ulimit nproc=... --security-opt=no-new-privileges
                         aetherforge/nmap:latest  <argv>
     │
     ▼
StdoutStream          — captured, persisted to artifacts/, parsed
     │
     ▼
ToolParser            — returns List[Fact]
```

All tool containers:

* Drop every Linux capability (`--cap-drop=ALL`).
* Run as a non-root user inside the container.
* Use a read-only rootfs with a tmpfs `/tmp`.
* Are bound to a per-run cgroup (`--memory`, `--pids-limit`,
  `--cpu-shares`).
* Are joined only to `aetherforge_targets` (no backplane access).
* Are removed on exit (`--rm`).

---

## 8. API surface (current — 28 routes)

### Liveness / readiness
| Route                                 | Method | Purpose                                  |
| ------------------------------------- | ------ | ---------------------------------------- |
| `/health`                             | GET    | Liveness                                 |
| `/ready`                              | GET    | Readiness (DB + Redis live-checked)      |

### Resources
| Route                                          | Method      | Purpose                              |
| ---------------------------------------------- | ----------- | ------------------------------------ |
| `/api/v1/targets`                              | GET / POST  | List + create                        |
| `/api/v1/targets/{id}`                         | GET / PATCH / DELETE | CRUD by id              |
| `/api/v1/targets/slug/{slug}`                  | GET         | Lookup by slug                       |
| `/api/v1/scans`                                | GET / POST  | List + start                         |
| `/api/v1/scans/{id}`                           | GET         | Fetch                                |
| `/api/v1/scans/{id}/status`                    | GET         | Live workflow query                  |
| `/api/v1/scans/{id}/stop`                      | POST        | Signal stop                          |
| `/api/v1/scans/{id}/escalate`                  | POST        | Signal persona escalation            |
| `/api/v1/rules`                                | GET / POST  | List + upsert                        |
| `/api/v1/rules/{rule_id}`                      | GET         | Fetch by id                          |
| `/api/v1/rules/validate`                       | POST        | Validate against schema              |
| `/api/v1/personas`                             | GET         | Persona list                         |
| `/api/v1/personas/current`                     | GET         | Resolve persona for the request      |
| `/api/v1/findings`                             | GET         | List filterable                      |
| `/api/v1/findings/{id}`                        | GET / PATCH | Triage workflow                      |
| `/api/v1/tools`                                | GET         | Registry                             |
| `/api/v1/tools/{name}`                         | GET         | One tool                             |

### Reporting + audit + drift + metrics
| Route                                          | Method | Purpose                              |
| ---------------------------------------------- | ------ | ------------------------------------ |
| `/api/v1/reports/{scan_id}`                    | GET    | JSON / HTML / PDF report             |
| `/api/v1/reports/{scan_id}/bundle`             | GET    | tar.gz of artefacts + report + meta  |
| `/api/v1/audit`                                | GET    | List audit entries                   |
| `/api/v1/audit/scans/{id}/stream`              | WS     | LISTEN/NOTIFY-driven WS stream       |
| `/api/v1/audit/scans/{id}/sse`                 | GET    | LISTEN/NOTIFY-driven SSE stream      |
| `/api/v1/metrics/overview`                     | GET    | Operator metrics                     |
| `/api/v1/drift/{target_id}`                    | GET    | Snapshot + delta history             |
| `/api/v1/drift/monitor`                        | POST   | Start `ContinuousMonitorWorkflow`    |
| `/api/v1/drift/monitor/{slug}/stop`            | POST   | Stop monitor                         |

### UI
| Route                          | Method | Purpose                  |
| ------------------------------ | ------ | ------------------------ |
| `/`                            | GET    | Overview                 |
| `/ui/scans` `/ui/scans/{id}`   | GET    | Scans + per-scan detail  |
| `/ui/findings`                 | GET    | Findings triage          |
| `/ui/targets`                  | GET    | Targets table            |
| `/ui/_partials/*`              | GET    | HTMX swap targets        |

---

## 9. Extending the platform

**New tool:** add `rules/<persona>/<tool>/*.yaml` + write a
`ToolWrapper` subclass in `app/tools/wrappers/<tool>.py` + write the
Dockerfile in `docker/tools/<tool>/`.

**New rule:** drop a YAML into `rules/<persona>/`, run
`make rules-validate`, restart the worker. Rules are hot-loaded but
only new scans see the updated ruleset.

**New persona:** edit `configs/personas.yaml` — add the persona,
declare its rate-limits + allowed phases + parent. Add test fixtures
covering which existing rules fire under it.
