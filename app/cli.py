"""AetherForge CLI — REST consumer.

Talks to a running orchestrator over HTTP. The base URL defaults to
``http://127.0.0.1:8002`` and can be overridden with
``AETHERFORGE_API`` or ``--api`` on each command.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.table import Table

from app import __version__
from app.config import Persona, get_settings

app = typer.Typer(
    name="aetherforge",
    help="AetherForge — autonomous VAPT orchestrator CLI.",
    add_completion=False,
    no_args_is_help=True,
)
target_app = typer.Typer(name="target", help="Manage targets.")
scan_app = typer.Typer(name="scan", help="Start / inspect scans.")
persona_app = typer.Typer(name="persona", help="Inspect personas.")
audit_app = typer.Typer(name="audit", help="Inspect the audit log.")

app.add_typer(target_app)
app.add_typer(scan_app)
app.add_typer(persona_app)
app.add_typer(audit_app)

console = Console()


def _api() -> str:
    return os.environ.get("AETHERFORGE_API", "http://127.0.0.1:8002").rstrip("/")


def _client() -> httpx.Client:
    return httpx.Client(base_url=_api(), timeout=15.0)


def _die(msg: str) -> None:
    console.print(f"[red]error[/red] {msg}")
    raise typer.Exit(code=1)


def _print_json(d: Any) -> None:
    import json as _json
    console.print_json(data=d) if hasattr(console, "print_json") else \
        console.print(_json.dumps(d, indent=2))


# ---------------------------------------------------------------------------
# top-level
# ---------------------------------------------------------------------------
@app.command()
def version() -> None:
    """Print the installed AetherForge version."""
    console.print(f"aetherforge [bold]{__version__}[/bold]")


@app.command()
def info() -> None:
    """Dump resolved local settings."""
    settings = get_settings()
    t = Table(title="AetherForge runtime", show_lines=False)
    t.add_column("Key", style="cyan")
    t.add_column("Value")
    for k, v in settings.model_dump().items():
        display = "***" if any(x in k for x in ("password", "secret", "pass")) else v
        t.add_row(str(k), str(display))
    console.print(t)


@app.command()
def health() -> None:
    """Probe the live API for liveness + readiness."""
    with _client() as c:
        try:
            h = c.get("/health").raise_for_status().json()
            r = c.get("/ready").json()
        except httpx.HTTPError as exc:
            _die(f"api unreachable @ {_api()}: {exc}")
            return
    console.print(f"[green]/health[/green]  {h}")
    console.print(f"[green]/ready[/green]   {r}")


# ---------------------------------------------------------------------------
# target sub-app
# ---------------------------------------------------------------------------
@target_app.command("list")
def target_list() -> None:
    """List targets."""
    with _client() as c:
        body = c.get("/api/v1/targets").json()
    t = Table(show_lines=False)
    for col in ("id", "slug", "cidrs", "personas", "replica"):
        t.add_column(col, style="cyan" if col == "id" else "")
    for row in body.get("items", []):
        t.add_row(
            str(row["id"]), row["slug"],
            ",".join(row.get("cidrs") or []),
            ",".join(row.get("allowed_personas") or []),
            "yes" if row.get("replica_only") else "no",
        )
    console.print(t)


@target_app.command("add")
def target_add(
    slug: str = typer.Option(..., "--slug"),
    cidr: list[str] = typer.Option([], "--cidr", help="repeatable"),
    persona: list[str] = typer.Option(["white"], "--persona"),
    replica_only: bool = typer.Option(False, "--replica-only"),
    description: str = typer.Option("", "--description"),
) -> None:
    """Register a new target."""
    payload = {
        "slug": slug, "description": description, "owner": "cli",
        "cidrs": cidr, "domains": [],
        "allowed_personas": persona, "tags": ["cli"],
        "replica_only": replica_only,
    }
    with _client() as c:
        r = c.post("/api/v1/targets", json=payload)
    if r.status_code >= 300:
        _die(f"create failed: HTTP {r.status_code} {r.text[:200]}")
    _print_json(r.json())


@target_app.command("delete")
def target_delete(target_id: int = typer.Argument(...)) -> None:
    """Delete a target by id."""
    with _client() as c:
        r = c.delete(f"/api/v1/targets/{target_id}")
    if r.status_code in (204, 404):
        console.print(f"[green]deleted[/green] target {target_id}")
    else:
        _die(f"delete failed: HTTP {r.status_code} {r.text[:200]}")


# ---------------------------------------------------------------------------
# scan sub-app
# ---------------------------------------------------------------------------
@scan_app.command("start")
def scan_start(
    target: str = typer.Option(..., "--target", "-t", help="Target slug."),
    persona: Persona = typer.Option(Persona.WHITE, "--persona", "-p"),
) -> None:
    """Kick off an autonomous scan against TARGET as PERSONA."""
    with _client() as c:
        r = c.post("/api/v1/scans", json={
            "target_slug": target, "persona": persona.value,
            "started_by": "cli",
        })
    if r.status_code >= 300:
        _die(f"scan start failed: HTTP {r.status_code} {r.text[:200]}")
    body = r.json()
    console.print(
        f"[green]started[/green] scan id=[bold]{body['id']}[/bold] "
        f"workflow=[dim]{body['workflow_id']}[/dim]"
    )


@scan_app.command("list")
def scan_list(limit: int = typer.Option(20, "--limit", "-n")) -> None:
    """List recent scans."""
    with _client() as c:
        body = c.get(f"/api/v1/scans?size={limit}").json()
    t = Table(show_lines=False)
    for col in ("id", "state", "persona", "iter", "exec", "facts", "term"):
        t.add_column(col)
    for s in body.get("items", []):
        t.add_row(
            str(s["id"]), s["state"], s["persona"],
            str(s["iterations"]), str(s["executions_total"]),
            str(s["facts_total"]), s.get("terminal_reason") or "—",
        )
    console.print(t)


@scan_app.command("status")
def scan_status(scan_id: int = typer.Argument(...)) -> None:
    """Query the live workflow status for SCAN_ID."""
    with _client() as c:
        r = c.get(f"/api/v1/scans/{scan_id}/status")
    if r.status_code >= 300:
        _die(f"status failed: HTTP {r.status_code} {r.text[:200]}")
    _print_json(r.json())


@scan_app.command("stop")
def scan_stop(
    scan_id: int = typer.Argument(...),
    reason: str = typer.Option("cli-stop", "--reason"),
) -> None:
    """Signal a graceful stop."""
    with _client() as c:
        r = c.post(f"/api/v1/scans/{scan_id}/stop", params={"reason": reason})
    if r.status_code in (202, 409):
        console.print(f"[green]stop sent[/green] scan {scan_id}: {r.json()}")
    else:
        _die(f"stop failed: HTTP {r.status_code} {r.text[:200]}")


# ---------------------------------------------------------------------------
# persona sub-app
# ---------------------------------------------------------------------------
@persona_app.command("list")
def persona_list() -> None:
    """List the three built-in personas + descriptions."""
    with _client() as c:
        body = c.get("/api/v1/personas").json()
    t = Table(show_lines=False)
    t.add_column("persona", style="cyan")
    t.add_column("description")
    for p, desc in body.get("descriptions", {}).items():
        t.add_row(p, desc)
    console.print(t)


# ---------------------------------------------------------------------------
# audit sub-app
# ---------------------------------------------------------------------------
@audit_app.command("tail")
def audit_tail(
    scan_id: int | None = typer.Option(None, "--scan", help="Filter by scan id."),
    limit: int = typer.Option(50, "--limit", "-n"),
) -> None:
    """Tail the audit log (use --scan to filter to one scan)."""
    params: dict[str, Any] = {"limit": limit}
    if scan_id is not None:
        params["scan_id"] = scan_id
    with _client() as c:
        body = c.get("/api/v1/audit", params=params).json()
    t = Table(show_lines=False)
    for col in ("seq", "scan", "event", "rule", "persona"):
        t.add_column(col)
    for e in reversed(body.get("items", [])):
        t.add_row(
            str(e["sequence"]), str(e["scan_id"] or "—"),
            e["event"], e.get("rule_id") or "—",
            e.get("persona") or "—",
        )
    console.print(t)


if __name__ == "__main__":
    app()
