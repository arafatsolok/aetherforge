"""DTO sanity tests for workflow data shapes (Temporal serialization-safety)."""

from __future__ import annotations

import dataclasses
import json

import pytest

from app.workflows.data import (
    EscalatePersonaSignal,
    InvocationSpec,
    IterationOutcome,
    ScanInput,
    StopSignal,
)


def _roundtrip(obj: object) -> dict:
    """Anything Temporal will pass should JSON-roundtrip through a dict."""
    d = dataclasses.asdict(obj) if dataclasses.is_dataclass(obj) else dict(obj)  # type: ignore[arg-type]
    return json.loads(json.dumps(d, default=str))


@pytest.mark.unit
class TestDTOs:
    def test_scan_input(self) -> None:
        s = ScanInput(
            scan_id=1, scan_ulid="01ABC", target_id=2,
            target_slug="lab", target_scope_cidrs=["10.0.0.0/24"],
            persona="gray", started_by="api",
        )
        d = _roundtrip(s)
        assert d["scan_id"] == 1
        assert d["persona"] == "gray"
        assert d["max_iterations"] == 100

    def test_iteration_outcome_no_action(self) -> None:
        o = IterationOutcome(has_action=False)
        assert o.invocation is None
        d = _roundtrip(o)
        assert d["has_action"] is False

    def test_invocation_spec(self) -> None:
        spec = InvocationSpec(
            tool_name="nmap", image="aetherforge/nmap:latest",
            argv=["-sT", "-Pn", "127.0.0.1"],
            cap_add=["NET_RAW"], cap_drop=["ALL"],
            memory_bytes=512_000_000, cpu_shares=512,
            timeout_seconds=60, read_only_rootfs=True, run_as_uid=10100,
            network="aetherforge_targets", rule_id="r.test", persona="gray",
        )
        d = _roundtrip(spec)
        assert d["tool_name"] == "nmap"
        assert d["argv"][0] == "-sT"

    def test_signals(self) -> None:
        s1 = StopSignal(reason="x", actor="op")
        s2 = EscalatePersonaSignal(to="black", authorised_by="lead")
        assert _roundtrip(s1)["reason"] == "x"
        assert _roundtrip(s2)["to"] == "black"
