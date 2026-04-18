"""Unit tests for WazuhClient using respx for HTTPX mocking."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.config import Settings
from app.services.wazuh_client import (
    WazuhAuthError,
    WazuhClient,
    WazuhUnreachable,
)


def _client() -> WazuhClient:
    s = Settings().model_copy(update={
        "wazuh_host": "wazuh-manager",
        "wazuh_api_port": 55000,
        "wazuh_api_user": "wazuh-wui",
    })
    return WazuhClient(settings=s)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_login_success() -> None:
    c = _client()
    with respx.mock(base_url=c._base_url(), assert_all_called=True) as rs:
        rs.post("/security/user/authenticate").mock(
            return_value=httpx.Response(200, json={"data": {"token": "tok-123"}})
        )
        token = await c.login()
        assert token == "tok-123"
    await c.close()


@pytest.mark.asyncio
@pytest.mark.unit
async def test_login_failure_raises_auth_error() -> None:
    c = _client()
    with respx.mock(base_url=c._base_url()) as rs:
        rs.post("/security/user/authenticate").mock(
            return_value=httpx.Response(401, text="bad creds")
        )
        with pytest.raises(WazuhAuthError):
            await c.login()
    await c.close()


@pytest.mark.asyncio
@pytest.mark.unit
async def test_unreachable_returns_unreachable() -> None:
    c = _client()
    with respx.mock(base_url=c._base_url()) as rs:
        rs.post("/security/user/authenticate").mock(
            side_effect=httpx.ConnectError("name resolution failed")
        )
        with pytest.raises(WazuhUnreachable):
            await c.login()
    await c.close()


@pytest.mark.asyncio
@pytest.mark.unit
async def test_list_agents_uses_token() -> None:
    c = _client()
    with respx.mock(base_url=c._base_url()) as rs:
        rs.post("/security/user/authenticate").mock(
            return_value=httpx.Response(200, json={"data": {"token": "tok-X"}})
        )
        rs.get("/agents").mock(
            return_value=httpx.Response(200, json={
                "data": {"affected_items": [{"id": "001", "name": "lab-host"}]}
            })
        )
        agents = await c.list_agents()
        assert agents == [{"id": "001", "name": "lab-host"}]
    await c.close()


@pytest.mark.asyncio
@pytest.mark.unit
async def test_push_event_succeeds() -> None:
    c = _client()
    with respx.mock(base_url=c._base_url()) as rs:
        rs.post("/security/user/authenticate").mock(
            return_value=httpx.Response(200, json={"data": {"token": "tok-Y"}})
        )
        rs.put("/events").mock(return_value=httpx.Response(200, json={}))
        ok = await c.push_custom_event(
            location="aetherforge:scan:1", log_format="json",
            body={"hello": "world"},
        )
        assert ok is True
    await c.close()
