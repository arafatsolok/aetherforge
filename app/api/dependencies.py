"""Shared FastAPI dependencies.

All cross-cutting resolution logic (DB session, persona override, target
scope lookup) lives here so route handlers can stay terse.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Persona, Settings, get_settings
from app.database import get_session


def settings_dep() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(settings_dep)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]


def persona_override(
    settings: SettingsDep,
    x_aetherforge_persona: Annotated[str | None, Header()] = None,
) -> Persona:
    """Resolve the persona for the current request.

    Order of precedence:
      1. ``X-AetherForge-Persona`` header (if valid)
      2. settings.default_persona

    FastAPI maps the param name ``x_aetherforge_persona`` to the HTTP
    header ``X-AetherForge-Persona`` via underscore→hyphen conversion
    (which is the default — do NOT pass ``convert_underscores=False``).
    """
    if x_aetherforge_persona:
        try:
            return Persona(x_aetherforge_persona.lower())
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown persona: {x_aetherforge_persona!r}",
            ) from err
    return settings.default_persona


PersonaDep = Annotated[Persona, Depends(persona_override)]


__all__ = [
    "PersonaDep",
    "SessionDep",
    "SettingsDep",
    "persona_override",
    "settings_dep",
]
