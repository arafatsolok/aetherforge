"""Scope + argv safety primitives.

These functions are the last line of defence before a command is handed
to Docker. They must be pure, deterministic, and never throw — any
unclear input is rejected by returning ``False``.
"""

from __future__ import annotations

import ipaddress
import re

# Characters safe in a shell-free execve argv token.
# We run commands via docker exec (no shell), but still refuse shell
# metacharacters so a hypothetical future shell-wrapping path is safe.
# Strict alnum + URL/CIDR-safe punctuation. Forbids shell metas:
#   $ ` ; | & < > ' " \ {space} {newline}
_SAFE_ARGV_CHARS = re.compile(r"^[A-Za-z0-9_@:./?&=,+\-\[\]%~]{1,4096}$")

# Broader pattern for header VALUES (User-Agent, Content-Type, etc).
# Same safe set + space + parens + semicolon. Still forbids
# $, `, |, < >, " ', \, newline — so injection can't slip through.
_SAFE_HEADER_CHARS = re.compile(r"^[A-Za-z0-9_@:./?&=,+\-\[\]%~ ;()]{1,4096}$")


def sanitize_argv_token(token: str) -> str:
    """Return the token unchanged if safe, else raise ``ValueError``.

    Does NOT shell-quote — our executor uses argv arrays, not shell strings.
    This is a defensive allow-list filter. Tokens that look like an HTTP
    header value (``User-Agent: …``, ``Content-Type: …; charset=…``)
    are accepted via the wider header pattern.
    """
    if not isinstance(token, str):
        raise TypeError(f"argv token must be str, got {type(token).__name__}")
    if _SAFE_ARGV_CHARS.fullmatch(token):
        return token
    # Header-value fallback — must contain a colon (header sep) to qualify.
    if ":" in token and _SAFE_HEADER_CHARS.fullmatch(token):
        return token
    raise ValueError(f"unsafe argv token: {token!r}")


def _parse_net(cidr_or_host: str) -> ipaddress._BaseNetwork:
    """Parse ``'1.2.3.4'`` or ``'10.0.0.0/8'`` into an IPv4Network / IPv6Network.

    Hostnames are NOT resolved here — resolution happens earlier and this
    layer only operates on numeric addresses.
    """
    return ipaddress.ip_network(cidr_or_host, strict=False)


def is_target_in_scope(target: str, scope_cidrs: list[str]) -> bool:
    """Return True iff ``target`` is inside at least one scope CIDR.

    ``target`` may be an IP, a host, or a CIDR. Hosts are rejected (caller
    must resolve them first).
    """
    if not scope_cidrs:
        return False
    try:
        target_net = _parse_net(target)
    except ValueError:
        # Probably a hostname — this function only handles IPs/CIDRs.
        return False
    for s in scope_cidrs:
        try:
            scope_net = _parse_net(s)
        except ValueError:
            continue
        if target_net.version != scope_net.version:
            continue
        if target_net.subnet_of(scope_net):
            return True
    return False


def is_cidr_forbidden(target: str, forbidden_cidrs: list[str]) -> bool:
    """Return True iff ``target`` falls inside any forbidden range.

    A forbidden hit OVERRIDES an allowed scope — wildcard forbids win.
    """
    try:
        target_net = _parse_net(target)
    except ValueError:
        return False
    for f in forbidden_cidrs:
        try:
            forbidden_net = _parse_net(f)
        except ValueError:
            continue
        if target_net.version != forbidden_net.version:
            continue
        if target_net.subnet_of(forbidden_net) or target_net.overlaps(forbidden_net):
            # Explicit 0.0.0.0/0 still forbids — callers who want to opt
            # out must omit it from FORBIDDEN_CIDRS.
            return True
    return False


__all__ = ["is_cidr_forbidden", "is_target_in_scope", "sanitize_argv_token"]
