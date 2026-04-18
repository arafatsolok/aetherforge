"""Secrets safety helpers.

* ``check_env_file_permissions`` — refuse to boot in production if
  ``.env`` is world-readable. Logs a warning in development.
* ``VaultLoader`` — stub for HashiCorp Vault integration. Returns the
  configured static value when Vault isn't enabled; replace with a
  real Vault HTTP client in your fork.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from app.config import Settings
from app.logging_config import get_logger

log = get_logger(__name__)


_ALLOWED_ENV_MODE: Final[int] = 0o600


def check_env_file_permissions(env_path: Path, settings: Settings) -> None:
    """Verify ``.env`` is owner-only readable. Raises in production."""
    if not env_path.exists():
        return                            # OK — env vars supplied by orchestrator
    mode = stat.S_IMODE(env_path.stat().st_mode)
    if mode & 0o077:                      # any group/world bit set
        msg = (
            f".env at {env_path} has mode {oct(mode)} — should be 0o600. "
            "Run: chmod 600 .env"
        )
        if settings.is_production:
            raise PermissionError(msg)
        log.warning("secrets.env_perms_loose", path=str(env_path), mode=oct(mode))


# ---------------------------------------------------------------------------
# Vault stub
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class VaultLoader:
    """Resolves secret references like ``vault:secret/data/aetherforge#api_key``.

    Phase 8 ships the contract + a passthrough resolver. A production
    fork should plug in ``hvac`` + AppRole auth + token caching here —
    every call site already passes a ``VaultLoader`` instance so no
    other code needs to change.
    """

    enabled: bool = False
    base_url: str | None = None
    token: str | None = None

    def resolve(self, value: str) -> str:
        """Return the secret value. ``vault:`` refs become a no-op when disabled."""
        if not value.startswith("vault:"):
            return value
        if not self.enabled:
            log.debug("vault.disabled", ref=value[:32])
            return ""
        path, _, key = value[len("vault:"):].partition("#")
        # NOTE: real impl here. Phase 8 ships the shape only.
        log.warning("vault.stub.resolve", path=path, key=key)
        return ""


def vault_loader_from_env() -> VaultLoader:
    return VaultLoader(
        enabled=os.environ.get("AETHERFORGE_VAULT_ENABLED", "").lower() in {"true", "1"},
        base_url=os.environ.get("AETHERFORGE_VAULT_URL"),
        token=os.environ.get("AETHERFORGE_VAULT_TOKEN"),
    )


__all__ = ["VaultLoader", "check_env_file_permissions", "vault_loader_from_env"]
