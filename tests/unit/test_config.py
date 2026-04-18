"""Settings + persona ordering sanity checks."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from app.config import Persona, Settings, get_settings


@pytest.mark.unit
def test_settings_load() -> None:
    s = get_settings()
    assert s.default_persona in Persona
    assert s.tool_rate_limit_for(Persona.WHITE) <= s.tool_rate_limit_for(Persona.GRAY)
    assert s.tool_rate_limit_for(Persona.GRAY) <= s.tool_rate_limit_for(Persona.BLACK)


@pytest.mark.unit
def test_persona_covers() -> None:
    assert Persona.BLACK.covers(Persona.GRAY)
    assert Persona.BLACK.covers(Persona.WHITE)
    assert Persona.GRAY.covers(Persona.WHITE)
    assert not Persona.WHITE.covers(Persona.GRAY)
    assert not Persona.GRAY.covers(Persona.BLACK)


# ---------------------------------------------------------------------------
# M6 — API key entropy floor
# ---------------------------------------------------------------------------
def _prod(api_key: str) -> Settings:
    """Build a production Settings with everything else strong."""
    strong = "0" + "1" * 5 + "2" * 5 + "3" * 5 + "abc"   # ≥12 unique
    return Settings(
        env="production",
        secret_key=SecretStr("a" * 4 + "b" * 4 + "c" * 4 + "d" * 4
                              + "e" * 4 + "f" * 4 + "0123456789"),  # 32+ chars, ≥10 unique
        api_key=SecretStr(api_key),
        msf_rpc_pass=SecretStr(strong),
        openvas_password=SecretStr(strong),
        wazuh_api_password=SecretStr(strong),
        database_url="postgresql+asyncpg://u:p@host:5432/db",
    )


@pytest.mark.unit
class TestApiKeyEntropyFloor:
    """≥24 chars, ≥12 unique, no 'change-me' prefix in production."""

    def test_low_entropy_24char_is_rejected(self) -> None:
        # 24 chars, only 9 unique — would have passed the OLD ≥8 rule.
        weak = "abcdefgha" * 3                            # len=27, 9 unique
        with pytest.raises(ValidationError) as ei:
            _prod(weak)
        msg = str(ei.value)
        assert "unique characters" in msg or "entropy" in msg

    def test_too_short_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _prod("abcdefghijklmnopqrstuv")               # 22 chars

    def test_change_me_prefix_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _prod("change-me-strong-and-long-key-12345-abc")

    def test_strong_key_accepted(self) -> None:
        # 32 chars, 17 unique — passes
        s = _prod("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
        assert s.api_key is not None

    def test_dev_env_skips_validation(self) -> None:
        # Same weak key, but env=development → no validation.
        s = Settings(env="development",
                     api_key=SecretStr("abcdefgha" * 3))
        assert s.api_key is not None
