"""Persona inspection + runtime override."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.api.dependencies import PersonaDep, SettingsDep
from app.config import Persona

router = APIRouter()


@router.get("", summary="List personas")
async def list_personas() -> dict[str, Any]:
    return {
        "personas": [p.value for p in Persona],
        "descriptions": {
            Persona.WHITE.value: "Passive recon + non-destructive scanning only.",
            Persona.GRAY.value: "Active scanning + safe limited exploitation.",
            Persona.BLACK.value: "Full kill-chain (replica environments only).",
        },
    }


@router.get("/current", summary="Resolve the persona for the current request")
async def current_persona(persona: PersonaDep, settings: SettingsDep) -> dict[str, Any]:
    return {
        "persona": persona.value,
        "default": settings.default_persona.value,
        "rate_limit_rps": settings.tool_rate_limit_for(persona),
    }
