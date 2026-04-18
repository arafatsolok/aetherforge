"""Scope-enforcement helpers."""

from __future__ import annotations

import pytest

from app.utils.security import (
    is_cidr_forbidden,
    is_target_in_scope,
    sanitize_argv_token,
)


@pytest.mark.unit
class TestScope:
    def test_in_scope(self) -> None:
        assert is_target_in_scope("10.0.0.5", ["10.0.0.0/24"])
        assert is_target_in_scope("10.0.0.0/28", ["10.0.0.0/24"])

    def test_out_of_scope(self) -> None:
        assert not is_target_in_scope("10.0.1.5", ["10.0.0.0/24"])

    def test_empty_scope_rejects(self) -> None:
        assert not is_target_in_scope("10.0.0.5", [])

    def test_hostname_rejected(self) -> None:
        assert not is_target_in_scope("example.com", ["10.0.0.0/24"])


@pytest.mark.unit
class TestForbidden:
    def test_internet_default_forbidden(self) -> None:
        assert is_cidr_forbidden("8.8.8.8", ["0.0.0.0/0"])

    def test_private_not_forbidden_when_not_listed(self) -> None:
        assert not is_cidr_forbidden("10.0.0.5", ["203.0.113.0/24"])


@pytest.mark.unit
class TestArgvToken:
    @pytest.mark.parametrize("tok", ["nmap", "-sV", "10.0.0.5", "example.com", "port=80"])
    def test_safe_tokens(self, tok: str) -> None:
        assert sanitize_argv_token(tok) == tok

    @pytest.mark.parametrize("tok", ["$(id)", "`ls`", "x;y", "x|y", "x\nid", " "])
    def test_unsafe_tokens(self, tok: str) -> None:
        with pytest.raises(ValueError):
            sanitize_argv_token(tok)
