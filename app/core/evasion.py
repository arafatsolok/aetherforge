"""Per-persona evasion profiles.

Tools accept additional flags depending on persona:

  white   — default, no evasion (we don't actively scan)
  gray    — moderate timing (T2), randomised User-Agent, request jitter
  black   — slow timing (T0/T1), nmap decoys, randomised UA, jitter

The command generator looks up the active persona's profile and
appends the resulting flags to the wrapper-built argv. The flag SET is
deterministic per persona — no randomness inside the rule engine — so
replay determinism is preserved. (User-Agent values are picked from a
hash of the rule_id, not random.)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from app.config import Persona


@dataclass(frozen=True, slots=True)
class EvasionProfile:
    """Per-tool flag bundles applied just before argv assembly."""

    nmap_extra:    tuple[str, ...] = ()
    nuclei_extra:  tuple[str, ...] = ()
    ffuf_extra:    tuple[str, ...] = ()
    httpx_extra:   tuple[str, ...] = ()


# Pool of plausible-looking User-Agents (picked deterministically by rule id).
# Kept strictly to LATEST desktop Chrome / Firefox / Safari variants —
# mobile UAs (iPhone, Android) and older browser strings are disproportionately
# flagged by WAFs (LiteSpeed + Cloudflare routinely 403 iPhone UAs paired with
# POST bodies carrying XSS-looking payloads, which is exactly what nuclei's
# tech-detect template sends).
_UA_POOL: Final[tuple[str, ...]] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
)

# Decoy host pool for nmap -D — RFC1918 only so we never spoof real targets.
_DECOY_POOL: Final[tuple[str, ...]] = (
    "10.0.0.42", "10.0.0.99", "10.0.0.123",
    "192.168.1.55", "192.168.1.77",
)


def _stable_pick(rule_id: str, pool: tuple[str, ...]) -> str:
    """Deterministic pick from ``pool`` keyed by ``rule_id`` — replay-safe."""
    h = hashlib.sha1(rule_id.encode("utf-8"), usedforsecurity=False).digest()
    return pool[int.from_bytes(h[:4], "big") % len(pool)]


def evasion_for(persona: Persona, *, rule_id: str = "") -> EvasionProfile:
    if persona == Persona.WHITE:
        return EvasionProfile()

    if persona == Persona.GRAY:
        ua = _stable_pick(rule_id, _UA_POOL)
        # Gray persona keeps default nmap timing — operator wants FAST.
        # UA rotation + light nuclei rate cap is the only evasion.
        return EvasionProfile(
            nmap_extra=(),
            nuclei_extra=(
                "-H", f"User-Agent: {ua}",
                "-rl", "100",
            ),
            ffuf_extra=(
                "-H", f"User-Agent: {ua}",
                "-p", "0.1-0.3",         # 100-300ms request jitter
            ),
            httpx_extra=("-H", f"User-Agent: {ua}"),
        )

    # Persona.BLACK
    ua = _stable_pick(rule_id, _UA_POOL)
    decoys = ",".join((
        _stable_pick(rule_id + "1", _DECOY_POOL),
        _stable_pick(rule_id + "2", _DECOY_POOL),
        "ME",
    ))
    return EvasionProfile(
        nmap_extra=("-T1", "-D", decoys, "--max-rate", "30"),
        nuclei_extra=(
            "-H", f"User-Agent: {ua}",
            "-rl", "20",
        ),
        ffuf_extra=(
            "-H", f"User-Agent: {ua}",
            "-p", "0.5-1.5",             # 500-1500ms jitter
        ),
        httpx_extra=("-H", f"User-Agent: {ua}", "-rate-limit", "5"),
    )


__all__ = ["EvasionProfile", "evasion_for"]
