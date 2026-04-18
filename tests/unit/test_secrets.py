"""Unit tests for env-perm checker + Vault stub."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.config import Settings
from app.utils.secrets import (
    VaultLoader,
    check_env_file_permissions,
    vault_loader_from_env,
)


@pytest.mark.unit
class TestEnvPerms:
    def test_missing_env_is_ok(self, tmp_path: Path) -> None:
        check_env_file_permissions(tmp_path / "nope.env", Settings())

    def test_loose_perms_warn_in_dev(self, tmp_path: Path) -> None:
        p = tmp_path / ".env"
        p.write_text("X=1")
        os.chmod(p, 0o644)            # group/world readable
        s = Settings().model_copy(update={"env": "development"})
        check_env_file_permissions(p, s)   # no raise

    def test_loose_perms_raise_in_prod(self, tmp_path: Path) -> None:
        p = tmp_path / ".env"
        p.write_text("X=1")
        os.chmod(p, 0o644)
        s = Settings().model_copy(update={
            "env": "production",
            "secret_key": "x" * 32,
        })
        with pytest.raises(PermissionError):
            check_env_file_permissions(p, s)

    def test_owner_only_passes(self, tmp_path: Path) -> None:
        p = tmp_path / ".env"
        p.write_text("X=1")
        os.chmod(p, 0o600)
        s = Settings().model_copy(update={"env": "production",
                                           "secret_key": "x" * 32})
        check_env_file_permissions(p, s)


@pytest.mark.unit
class TestVaultLoader:
    def test_passthrough_for_non_vault(self) -> None:
        v = VaultLoader()
        assert v.resolve("plain-secret") == "plain-secret"

    def test_disabled_vault_returns_empty_for_ref(self) -> None:
        v = VaultLoader(enabled=False)
        assert v.resolve("vault:secret/data/x#k") == ""

    def test_loader_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("AETHERFORGE_VAULT_ENABLED", "true")
        monkeypatch.setenv("AETHERFORGE_VAULT_URL", "http://vault:8200")
        v = vault_loader_from_env()
        assert v.enabled is True
        assert v.base_url == "http://vault:8200"
