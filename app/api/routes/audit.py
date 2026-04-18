"""Audit log — list / tail / WebSocket stream."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, select

from app.api.dependencies import SessionDep
from app.database import get_session_factory
from app.logging_config import get_logger
from app.models.audit import AuditLog

router = APIRouter()
log = get_logger(__name__)


@router.get("", summary="List audit entries (filterable, newest-first)")
async def list_audit(
    session: SessionDep,
    scan_id: int | None = Query(None, ge=1),
    event: str | None = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    stmt = select(AuditLog)
    if scan_id is not None:
        stmt = stmt.where(AuditLog.scan_id == scan_id)
    if event is not None:
        stmt = stmt.where(AuditLog.event == event)
    stmt = stmt.order_by(desc(AuditLog.id)).limit(limit).offset(offset)
    rows = (await session.execute(stmt)).scalars().all()
    return {
        "items": [
            {
                "id": r.id, "ulid": r.ulid, "scan_id": r.scan_id,
                "sequence": r.sequence, "event": r.event,
                "persona": r.persona, "actor": r.actor, "rule_id": r.rule_id,
                "payload": r.payload,
                "created_at": r.created_at.isoformat() + "Z",
            }
            for r in rows
        ],
        "count": len(rows),
    }


@router.websocket("/scans/{scan_id}/stream")
async def stream_scan_audit(websocket: WebSocket, scan_id: int) -> None:
    """Live tail of audit entries for one scan over WebSocket.

    LISTEN/NOTIFY-driven (same plumbing as the SSE endpoint): the
    ``emit_audit`` activity issues ``NOTIFY aetherforge_audit, '<scan_id>'``
    after each insert; this handler wakes immediately. 5s heartbeat
    covers missed wake-ups + keeps the WS alive through proxies.
    """
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.config import get_settings

    await websocket.accept()
    factory = get_session_factory()
    engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
    last_seen = 0
    wakeup = asyncio.Event()
    raw = None
    conn = None

    target = str(scan_id)

    def _on_notify(_pid: int, _channel: str, payload: str) -> None:
        if payload == target:
            wakeup.set()

    try:
        # 1. Send the existing backlog up front.
        async with factory() as session:
            stmt = (select(AuditLog).where(AuditLog.scan_id == scan_id)
                    .order_by(AuditLog.id).limit(500))
            for r in (await session.execute(stmt)).scalars().all():
                await websocket.send_json(_row_dict(r))
                last_seen = max(last_seen, int(r.id))   # type: ignore[arg-type]

        # 2. Register LISTEN.
        try:
            conn = await engine.raw_connection()
            raw = conn.driver_connection
            await raw.add_listener("aetherforge_audit", _on_notify)
        except Exception as exc:
            log.debug("ws.listen_setup_failed", exc_info=exc)

        # 3. Push loop — wake on NOTIFY, fallback 5s heartbeat.
        while True:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(wakeup.wait(), timeout=5.0)
            wakeup.clear()

            async with factory() as session:
                stmt = (select(AuditLog).where(AuditLog.scan_id == scan_id)
                        .where(AuditLog.id > last_seen).order_by(AuditLog.id)
                        .limit(200))
                rows = (await session.execute(stmt)).scalars().all()
            for r in rows:
                await websocket.send_json(_row_dict(r))
                last_seen = max(last_seen, int(r.id))   # type: ignore[arg-type]
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close(code=1011)
        except Exception as exc:
            log.debug("ws.close_failed", exc_info=exc)
    finally:
        try:
            if raw is not None:
                await raw.remove_listener("aetherforge_audit", _on_notify)
            if conn is not None:
                conn.close()
        except Exception as exc:
            log.debug("ws.cleanup_failed", exc_info=exc)
        await engine.dispose()


@router.get("/scans/{scan_id}/sse", summary="SSE audit stream (LISTEN/NOTIFY)")
async def stream_scan_audit_sse(scan_id: int) -> StreamingResponse:
    """Server-Sent Events tail of the audit log.

    Uses Postgres LISTEN/NOTIFY for sub-second latency. The ``emit_audit``
    activity issues ``NOTIFY aetherforge_audit, '<scan_id>'`` after every
    insert; this generator wakes on each notify and pulls only new rows.
    Falls back to a 5s poll tick to handle missed wake-ups + heartbeat.
    """
    factory = get_session_factory()

    async def gen() -> AsyncIterator[bytes]:
        from sqlalchemy.ext.asyncio import create_async_engine

        from app.config import get_settings

        # A dedicated engine + raw asyncpg connection so we can LISTEN.
        s = get_settings()
        engine = create_async_engine(s.database_url, pool_pre_ping=True)
        last_seen = 0
        wakeup = asyncio.Event()

        # Drain existing rows first so the client gets the backlog.
        async with factory() as session:
            stmt = (
                select(AuditLog)
                .where(AuditLog.scan_id == scan_id)
                .order_by(AuditLog.id).limit(500)
            )
            for r in (await session.execute(stmt)).scalars().all():
                body = json.dumps(_row_dict(r), default=str)
                yield f"event: audit\ndata: {body}\n\n".encode()
                last_seen = max(last_seen, int(r.id))      # type: ignore[arg-type]

        # Acquire raw asyncpg connection to register LISTEN.
        try:
            conn = await engine.raw_connection()  # type: ignore[no-untyped-call]
            raw = conn.driver_connection
            target = str(scan_id)

            def _on_notify(_pid: int, _channel: str, payload: str) -> None:
                if payload == target:
                    wakeup.set()

            await raw.add_listener("aetherforge_audit", _on_notify)
        except Exception:
            raw = None

        try:
            while True:
                # Wait for NOTIFY or 5s timeout (heartbeat + missed-wake guard).
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(wakeup.wait(), timeout=5.0)
                wakeup.clear()

                async with factory() as session:
                    stmt = (
                        select(AuditLog)
                        .where(AuditLog.scan_id == scan_id)
                        .where(AuditLog.id > last_seen)
                        .order_by(AuditLog.id).limit(200)
                    )
                    rows = (await session.execute(stmt)).scalars().all()
                if rows:
                    for r in rows:
                        body = json.dumps(_row_dict(r), default=str)
                        yield f"event: audit\ndata: {body}\n\n".encode()
                        last_seen = max(last_seen, int(r.id))   # type: ignore[arg-type]
                else:
                    yield b": ping\n\n"
        finally:
            try:
                if raw:
                    await raw.remove_listener("aetherforge_audit", _on_notify)
                conn.close()
            except Exception:
                pass
            await engine.dispose()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


def _row_dict(r: AuditLog) -> dict[str, Any]:
    return {
        "id": r.id, "scan_id": r.scan_id, "sequence": r.sequence,
        "event": r.event, "persona": r.persona, "actor": r.actor,
        "rule_id": r.rule_id, "payload": r.payload,
        "created_at": r.created_at.isoformat() + "Z",
    }
