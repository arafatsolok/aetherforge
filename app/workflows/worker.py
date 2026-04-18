"""Temporal worker — registers ``AutonomousScanWorkflow`` + every activity.

Run directly:
    python -m app.workflows.worker
"""

from __future__ import annotations

import asyncio
import signal

from temporalio.client import Client
from temporalio.worker import Worker

from app.config import get_settings
from app.database import init_db
from app.logging_config import configure_logging, get_logger
from app.workflows.activities import ALL_ACTIVITIES
from app.workflows.autonomous_scan import AutonomousScanWorkflow
from app.workflows.continuous_monitor import ContinuousMonitorWorkflow


async def _ensure_namespace(host: str, namespace: str, log: object) -> None:
    """Idempotently register the Temporal namespace on first boot."""
    from google.protobuf.duration_pb2 import Duration  # noqa: PLC0415
    from temporalio.api.workflowservice.v1 import (  # noqa: PLC0415
        DescribeNamespaceRequest,
        RegisterNamespaceRequest,
    )
    from temporalio.client import Client as _C  # noqa: PLC0415
    from temporalio.service import RPCError  # noqa: PLC0415

    bootstrap = await _C.connect(host, namespace="default")
    try:
        await bootstrap.workflow_service.describe_namespace(
            DescribeNamespaceRequest(namespace=namespace)
        )
        log.info("temporal.namespace.present", namespace=namespace)  # type: ignore[attr-defined]
    except RPCError:
        try:
            await bootstrap.workflow_service.register_namespace(
                RegisterNamespaceRequest(
                    namespace=namespace,
                    description="AetherForge autonomous VAPT scans",
                    workflow_execution_retention_period=Duration(seconds=14 * 86400),
                )
            )
            log.info("temporal.namespace.registered", namespace=namespace)  # type: ignore[attr-defined]
        except RPCError as exc:
            if "already exists" in str(exc).lower():
                log.info("temporal.namespace.race", namespace=namespace)  # type: ignore[attr-defined]
            else:
                raise


async def _main() -> None:
    settings = get_settings()
    configure_logging(settings)
    log = get_logger(__name__)

    log.info(
        "worker.starting",
        temporal_host=settings.temporal_host,
        namespace=settings.temporal_namespace,
        task_queue=settings.temporal_task_queue,
        workflows=["AutonomousScanWorkflow", "ContinuousMonitorWorkflow"],
        activity_count=len(ALL_ACTIVITIES),
    )

    await init_db()
    await _ensure_namespace(settings.temporal_host, settings.temporal_namespace, log)

    client = await Client.connect(
        settings.temporal_host, namespace=settings.temporal_namespace,
    )

    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[AutonomousScanWorkflow, ContinuousMonitorWorkflow],
        activities=ALL_ACTIVITIES,
        max_concurrent_activities=settings.worker_max_concurrent_activities,
        max_concurrent_workflow_tasks=settings.worker_max_concurrent_workflows,
    )

    stop_event = asyncio.Event()

    def _stop(signum: int, _frame: object) -> None:
        log.info("worker.signal", signum=signum)
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _stop, int(sig), None)

    async with worker:
        log.info("worker.ready")
        await stop_event.wait()
        log.info("worker.shutting-down")


if __name__ == "__main__":
    asyncio.run(_main())
