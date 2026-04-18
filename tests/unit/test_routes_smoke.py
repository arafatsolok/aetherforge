"""Route smoke tests — verify every route's import + signature shape.

These don't hit the DB (no live infra in unit tier) — they import the
route module + check that handlers can be introspected for required
parameters. The integration suite proves real DB execution.
"""

from __future__ import annotations

import inspect

import pytest

from app.api.routes import (
    audit,
    dashboard,
    drift,
    findings,
    health,
    metrics,
    personas,
    reports,
    rules,
    scans,
    targets,
    tools,
)

ROUTE_MODULES = [
    audit, dashboard, drift, findings, health, metrics,
    personas, reports, rules, scans, targets, tools,
]


@pytest.mark.unit
class TestRouteModulesImport:
    def test_every_route_module_exports_router(self) -> None:
        for mod in ROUTE_MODULES:
            assert hasattr(mod, "router"), f"{mod.__name__} missing 'router'"

    def test_every_route_handler_has_a_callable(self) -> None:
        for mod in ROUTE_MODULES:
            for route in mod.router.routes:                # type: ignore[attr-defined]
                handler = getattr(route, "endpoint", None)
                if handler is None:
                    continue
                assert callable(handler), f"{mod.__name__}: {route.path} not callable"

    def test_no_route_returns_phase_0_stub(self) -> None:
        """Earlier phases left ``return {"phase": 0, ...}`` stubs — must be gone."""
        for mod in ROUTE_MODULES:
            for route in mod.router.routes:                # type: ignore[attr-defined]
                handler = getattr(route, "endpoint", None)
                if handler is None:
                    continue
                src = inspect.getsource(handler)
                assert '"phase": 0' not in src, \
                    f"{mod.__name__}: {route.path} still has phase-0 stub"


@pytest.mark.unit
class TestReportRouteSignatures:
    def test_get_report_takes_fmt_query(self) -> None:
        sig = inspect.signature(reports.get_report)
        assert "fmt" in sig.parameters

    def test_get_bundle_exists(self) -> None:
        assert hasattr(reports, "get_bundle")


@pytest.mark.unit
class TestDriftRouteSignatures:
    def test_drift_endpoints_present(self) -> None:
        names = {getattr(r, "name", "") for r in drift.router.routes}
        assert "list_drift" in names
        assert "start_monitor" in names
        assert "stop_monitor" in names


@pytest.mark.unit
class TestMetricsRouteSignatures:
    def test_overview_present(self) -> None:
        names = {getattr(r, "name", "") for r in metrics.router.routes}
        assert "overview" in names


@pytest.mark.unit
class TestDashboardRouteSignatures:
    def test_all_pages_registered(self) -> None:
        paths = {getattr(r, "path", "") for r in dashboard.router.routes}
        for required in ("/", "/ui/scans", "/ui/findings", "/ui/targets",
                         "/ui/scans/{scan_id}",
                         "/ui/_partials/scans_rows", "/ui/_partials/metrics"):
            assert required in paths, f"dashboard missing {required}"
