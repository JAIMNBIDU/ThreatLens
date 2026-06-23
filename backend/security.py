"""
Input validation + a dependency-free, per-IP rate limiter.

Validation matters because every IOC ends up inside an upstream API URL path
(VirusTotal, Shodan, etc.). Letting arbitrary strings through risks request
forgery against those upstreams and junk traffic burning quota. We accept only
strings that match a known IOC shape and reject everything else up front.

The limiter is an in-memory sliding window. No Redis, no slowapi — for a single
container that's plenty, and it keeps the dependency surface (and thus the
supply-chain attack surface) minimal.
"""
import re
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

import config

# ─── IOC shape validation ─────────────────────────────────────────────────────
_RE_IPV4   = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_RE_HASH   = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_RE_URL    = re.compile(r"^https?://[^\s]+$", re.I)
# hostname labels, no leading/trailing dots/hyphens, valid TLD-ish
_RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)


def detect_type(ioc: str) -> str:
    if _RE_IPV4.match(ioc):
        return "ipv4"
    if _RE_HASH.match(ioc):
        return "hash"
    if _RE_URL.match(ioc):
        return "url"
    return "domain"


def is_valid(ioc: str) -> bool:
    if not ioc or len(ioc) > config.MAX_IOC_LEN:
        return False
    t = detect_type(ioc)
    if t == "ipv4":
        return bool(_RE_IPV4.match(ioc))
    if t == "hash":
        return bool(_RE_HASH.match(ioc))
    if t == "url":
        # reject control chars / whitespace smuggling
        return bool(_RE_URL.match(ioc)) and "\n" not in ioc and "\r" not in ioc
    return bool(_RE_DOMAIN.match(ioc))


def clean_iocs(raw: list[str]) -> tuple[list[str], list[dict]]:
    """Split a raw IOC list into (accepted, rejected). De-dupes, preserves order."""
    accepted: list[str] = []
    rejected: list[dict] = []
    seen: set[str] = set()
    for item in raw:
        ioc = (item or "").strip()
        if not ioc or ioc in seen:
            continue
        seen.add(ioc)
        if is_valid(ioc):
            accepted.append(ioc)
        else:
            rejected.append({"ioc": ioc[:128], "reason": "not a recognised IOC format"})
    return accepted, rejected


# ─── Rate limiter ─────────────────────────────────────────────────────────────
_hits: dict[str, deque] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    # Honour a single proxy hop if present; fall back to socket peer.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def rate_limit(request: Request) -> None:
    ip = _client_ip(request)
    now = time.monotonic()
    window = config.RATE_LIMIT_WINDOW
    dq = _hits[ip]
    while dq and now - dq[0] > window:
        dq.popleft()
    if len(dq) >= config.RATE_LIMIT_MAX:
        retry = int(window - (now - dq[0])) + 1
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Slow down.",
            headers={"Retry-After": str(retry)},
        )
    dq.append(now)
