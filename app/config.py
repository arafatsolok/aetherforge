"""Central configuration.

All runtime configuration flows through ``Settings``. Environment variables
are the single source of truth — nothing is read from disk until the app
is booted, and `get_settings()` is `lru_cache`d so late mutations are
impossible.
"""

from __future__ import annotations

import enum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AnyHttpUrl, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Persona(enum.StrEnum):
    """The three built-in personas. Lower personas are strict subsets of higher ones."""

    WHITE = "white"
    GRAY = "gray"
    BLACK = "black"

    @property
    def ordinal(self) -> int:
        return {"white": 0, "gray": 1, "black": 2}[self.value]

    def covers(self, other: Persona) -> bool:
        """Return True if *this* persona is authorised to run an *other*-persona action."""
        return self.ordinal >= other.ordinal


class RunMode(enum.StrEnum):
    API = "api"
    WORKER = "worker"
    CLI = "cli"


class Settings(BaseSettings):
    """Process-wide settings, loaded once from env / .env."""

    model_config = SettingsConfigDict(
        env_prefix="AETHERFORGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- Meta ---------------------------------------------------------------
    env: Literal["development", "staging", "production"] = "development"
    mode: RunMode = RunMode.API
    secret_key: SecretStr = Field(
        default=SecretStr("change-me-in-production"),
        description="Used for session signing + CSRF + artifact HMAC",
    )
    api_key: SecretStr | None = Field(
        default=None,
        description=(
            "When set, every /api/v1/* request must echo this value via "
            "X-API-Key. UI traffic (browser) authenticates via /ui/login + "
            "session cookie. Unset = development-mode (no auth)."
        ),
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # ---- Paths --------------------------------------------------------------
    base_dir: Path = Field(default_factory=lambda: Path("/opt/aetherforge"))
    data_dir: Path = Field(default_factory=lambda: Path("/opt/aetherforge/data"))
    rules_dir: Path = Field(default_factory=lambda: Path("/opt/aetherforge/rules"))
    configs_dir: Path = Field(default_factory=lambda: Path("/opt/aetherforge/configs"))
    templates_dir: Path = Field(default_factory=lambda: Path("/opt/aetherforge/templates"))
    static_dir: Path = Field(default_factory=lambda: Path("/opt/aetherforge/static"))

    # ---- API ----------------------------------------------------------------
    api_host: str = "0.0.0.0"  # noqa: S104 — bind inside container
    api_port: int = 8000
    api_workers: int = 2
    api_reload: bool = False
    api_cors_origins: Annotated[list[AnyHttpUrl] | list[str], NoDecode] = Field(
        default_factory=list
    )

    # ---- Persona defaults ---------------------------------------------------
    default_persona: Persona = Persona.WHITE

    # ---- Database -----------------------------------------------------------
    database_url: str = Field(
        default="postgresql+asyncpg://aetherforge:changeme@postgres:5432/aetherforge",
        description="SQLAlchemy async DSN",
    )
    database_echo: bool = False
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # ---- Redis --------------------------------------------------------------
    redis_url: str = "redis://redis:6379/0"

    # ---- Temporal -----------------------------------------------------------
    temporal_host: str = "temporal:7233"
    temporal_namespace: str = "aetherforge"
    temporal_task_queue: str = "aetherforge-main"

    # ---- Metasploit RPC -----------------------------------------------------
    metasploit_host: str = "metasploit"
    metasploit_port: int = 55553
    msf_rpc_user: str = "aetherforge"
    msf_rpc_pass: SecretStr = SecretStr("change-me")

    # ---- OpenVAS ------------------------------------------------------------
    openvas_host: str = "openvas"
    openvas_port: int = 9392
    openvas_user: str = "admin"
    openvas_password: SecretStr = SecretStr("change-me")

    # ---- Wazuh --------------------------------------------------------------
    wazuh_host: str = "wazuh-manager"
    wazuh_api_port: int = 55000
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: SecretStr = SecretStr("change-me")

    # ---- Tool sandbox -------------------------------------------------------
    tool_run_timeout: int = 3600
    tool_memory_limit: int = 1_073_741_824  # 1 GiB
    tool_cpu_shares: int = 512
    tool_rate_limit_white: int = 2
    tool_rate_limit_gray: int = 20
    tool_rate_limit_black: int = 100

    # ---- Scope enforcement --------------------------------------------------
    strict_scope_enforcement: bool = True
    forbidden_cidrs: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["0.0.0.0/0"]
    )

    # ---- Observability ------------------------------------------------------
    prometheus_enabled: bool = True
    prometheus_port: int = 9090

    # ---- Worker tuning ------------------------------------------------------
    worker_max_concurrent_activities: int = 20
    worker_max_concurrent_workflows: int = 50

    # ---- Validators ---------------------------------------------------------
    @field_validator("api_cors_origins", mode="before")
    @classmethod
    def _split_cors(cls, v: object) -> object:
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @field_validator("forbidden_cidrs", mode="before")
    @classmethod
    def _split_forbidden(cls, v: object) -> object:
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @field_validator("secret_key")
    @classmethod
    def _secret_not_default(cls, v: SecretStr, info: object) -> SecretStr:
        """Enforce a real secret in production.

        Rejects values that are too short, too repetitive, or look like
        a literal placeholder. ``"x" * 32`` (one unique char) and
        ``"abcdefgh..." * 4`` (low alphabet diversity) both fail.
        """
        sv = v.get_secret_value()
        values = getattr(info, "data", {}) or {}
        is_prod = values.get("env") == "production"

        problems: list[str] = []
        if sv.startswith("change-me"):
            problems.append("starts with the placeholder 'change-me'")
        if len(sv) < 32:
            problems.append(f"length {len(sv)} < 32")
        # Reject low-entropy keys: require ≥10 unique characters.
        unique = len(set(sv))
        if unique < 10:
            problems.append(f"only {unique} unique characters (entropy too low)")

        if problems and is_prod:
            raise ValueError(
                "AETHERFORGE_SECRET_KEY rejected in production: "
                + "; ".join(problems)
                + ". Generate one with `openssl rand -hex 32`.",
            )
        return v

    @field_validator("msf_rpc_pass", "openvas_password", "wazuh_api_password")
    @classmethod
    def _service_pwd_not_default(cls, v: SecretStr, info: object) -> SecretStr:
        """Reject placeholder service passwords in production.

        Each integration (msfrpcd / OpenVAS / Wazuh) ships with a
        ``change-me`` default for local development. Production must
        override every one — otherwise an attacker that lands inside the
        VAPT network can pivot through the integration plane with known
        credentials.
        """
        values = getattr(info, "data", {}) or {}
        if values.get("env") != "production":
            return v
        sv = v.get_secret_value()
        problems: list[str] = []
        if sv.startswith("change-me"):
            problems.append("starts with placeholder 'change-me'")
        if len(sv) < 12:
            problems.append(f"length {len(sv)} < 12")
        if problems:
            field_name = getattr(info, "field_name", "<service password>")
            raise ValueError(
                f"AETHERFORGE_{field_name.upper()} rejected in production: "
                + "; ".join(problems),
            )
        return v

    @field_validator("database_url")
    @classmethod
    def _database_url_not_default(cls, v: str, info: object) -> str:
        """Reject the well-known ``changeme`` DB password in production."""
        values = getattr(info, "data", {}) or {}
        if values.get("env") != "production":
            return v
        if "changeme" in v:
            raise ValueError(
                "AETHERFORGE_DATABASE_URL contains the placeholder "
                "'changeme'. Set a real DB password in production.",
            )
        return v

    @field_validator("api_key")
    @classmethod
    def _api_key_strong_in_prod(
        cls, v: SecretStr | None, info: object,
    ) -> SecretStr | None:
        """In production, if api_key is set it must be strong; emit a warning
        if it's unset (caller-side decision to skip auth).

        M6 — entropy floor mirrors ``secret_key`` (≥10 unique chars). We
        bump to ≥12 here because the API key is a bearer credential
        with no second factor — a low-entropy string like
        ``"abcdefgha" * 3`` (24 chars, 9 unique) was passing the old
        ``≥8`` rule.
        """
        values = getattr(info, "data", {}) or {}
        if values.get("env") != "production" or v is None:
            return v
        sv = v.get_secret_value()
        problems: list[str] = []
        if sv.startswith("change-me"):
            problems.append("starts with placeholder 'change-me'")
        if len(sv) < 24:
            problems.append(f"length {len(sv)} < 24")
        unique = len(set(sv))
        if unique < 12:
            problems.append(f"only {unique} unique characters (entropy too low)")
        if problems:
            raise ValueError(
                "AETHERFORGE_API_KEY too weak for production: "
                + "; ".join(problems)
                + ". Generate one with `openssl rand -hex 32`.",
            )
        return v

    # ---- Derived helpers ----------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def is_development(self) -> bool:
        return self.env == "development"

    def tool_rate_limit_for(self, persona: Persona) -> int:
        return {
            Persona.WHITE: self.tool_rate_limit_white,
            Persona.GRAY: self.tool_rate_limit_gray,
            Persona.BLACK: self.tool_rate_limit_black,
        }[persona]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton settings accessor.

    Cached so tests can monkeypatch the factory itself; never mutate the
    returned object.
    """
    return Settings()


__all__ = ["Persona", "RunMode", "Settings", "get_settings"]
