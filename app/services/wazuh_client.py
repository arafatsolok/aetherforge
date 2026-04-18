"""Async wrapper over the Wazuh Manager REST API.

Wazuh's API requires a JWT obtained via Basic-auth login. Tokens last
~15 min by default — this client refreshes lazily on 401.

Endpoints used:
  POST /security/user/authenticate          login
  GET  /agents                              list agents
  GET  /alerts                              read alerts (Wazuh 4.8+ via indexer)
  PUT  /events                              push custom event into the manager
"""

from __future__ import annotations

import base64
import contextlib
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import Settings
from app.logging_config import get_logger

log = get_logger(__name__)


class WazuhUnreachable(RuntimeError):
    """Raised when the manager is down / unreachable."""


class WazuhAuthError(RuntimeError):
    """Raised when login fails."""


@dataclass(slots=True)
class WazuhClient:
    """Lazy-connected Wazuh API client.

    All calls are best-effort: when the manager is unreachable, methods
    raise ``WazuhUnreachable`` so callers can no-op cleanly (the
    activities log + continue rather than failing the whole scan).
    """

    settings: Settings
    timeout: float = 5.0
    _token: str | None = field(default=None, init=False)
    _http: httpx.AsyncClient | None = field(default=None, init=False)

    def _base_url(self) -> str:
        return f"https://{self.settings.wazuh_host}:{self.settings.wazuh_api_port}"

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                base_url=self._base_url(),
                timeout=self.timeout,
                verify=False,            # self-signed cert by default
            )
        return self._http

    async def close(self) -> None:
        if self._http is not None:
            with contextlib.suppress(Exception):
                await self._http.aclose()
            self._http = None

    # -------------------------------------------------------------------
    # Auth
    # -------------------------------------------------------------------
    async def login(self) -> str:
        c = await self._client()
        creds = base64.b64encode(
            f"{self.settings.wazuh_api_user}:{self.settings.wazuh_api_password.get_secret_value()}".encode()
        ).decode()
        try:
            r = await c.post(
                "/security/user/authenticate",
                headers={"Authorization": f"Basic {creds}"},
            )
        except (httpx.ConnectError, httpx.ReadTimeout) as exc:
            raise WazuhUnreachable(f"wazuh login: {exc}") from exc
        if r.status_code != 200:
            raise WazuhAuthError(f"wazuh login {r.status_code}: {r.text[:200]}")
        token = r.json().get("data", {}).get("token")
        if not token:
            raise WazuhAuthError("wazuh login returned no token")
        self._token = token
        return token

    async def _headers(self) -> dict[str, str]:
        if self._token is None:
            await self.login()
        return {"Authorization": f"Bearer {self._token}"}

    async def _get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        c = await self._client()
        try:
            r = await c.get(path, headers=await self._headers(), **kwargs)
        except (httpx.ConnectError, httpx.ReadTimeout) as exc:
            raise WazuhUnreachable(f"wazuh GET {path}: {exc}") from exc
        if r.status_code == 401:
            self._token = None
            r = await c.get(path, headers=await self._headers(), **kwargs)
        r.raise_for_status()
        return r.json()

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------
    async def list_agents(self) -> list[dict[str, Any]]:
        body = await self._get("/agents")
        return body.get("data", {}).get("affected_items", [])

    async def list_alerts(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """Read recent alerts. Wazuh 4.8+ paginates via offset/limit."""
        body = await self._get("/alerts", params={"limit": limit})
        return body.get("data", {}).get("affected_items", [])

    async def push_custom_event(
        self, *, location: str, log_format: str, body: dict[str, Any]
    ) -> bool:
        """Push a custom event into the Wazuh manager so it gets analysed."""
        c = await self._client()
        try:
            r = await c.put(
                "/events",
                headers={**await self._headers(), "Content-Type": "application/json"},
                json={"events": [
                    {"location": location, "log_format": log_format, "log": body}
                ]},
            )
        except (httpx.ConnectError, httpx.ReadTimeout) as exc:
            raise WazuhUnreachable(f"wazuh push: {exc}") from exc
        if r.status_code == 401:
            self._token = None
            return await self.push_custom_event(
                location=location, log_format=log_format, body=body
            )
        return r.status_code in (200, 201)


__all__ = ["WazuhAuthError", "WazuhClient", "WazuhUnreachable"]
