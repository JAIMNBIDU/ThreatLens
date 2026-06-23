"""
Keyless threat-intel sources from abuse.ch.

ThreatFox: per-IOC lookup. Queries are anonymous (no Auth-Key needed for reads),
returns malware-family attribution + threat classification + confidence. This is
high-precision signal: a hit means a researcher confirmed the IOC as malicious.

Feodo Tracker: a public CSV of active botnet C2 IPs. It's a list, not a per-IOC
API, so we pull it once, cache it in memory, refresh on an interval, and do O(1)
membership checks. Zero API budget consumed for either source.
"""
import asyncio
import csv
import io
from datetime import datetime, timezone

import httpx

import config


def _parse_dt(s):
    """ThreatFox / Feodo give 'YYYY-MM-DD HH:MM:SS UTC' or ISO. Normalise to ISO."""
    if not s:
        return None
    s = s.strip().replace(" UTC", "").replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s).isoformat()
    except ValueError:
        return None


# ─── ThreatFox ────────────────────────────────────────────────────────────────
async def threatfox_lookup(ioc: str, ioc_type: str, client: httpx.AsyncClient) -> dict:
    if ioc_type == "hash":
        body = {"query": "search_hash", "hash": ioc}
    else:
        body = {"query": "search_ioc", "search_term": ioc}

    try:
        resp = await client.post(config.THREATFOX_BASE, json=body, timeout=config.HTTP_TIMEOUT)
        if resp.status_code == 429:
            return {"available": False, "error": "rate limited"}
        resp.raise_for_status()
        body = resp.json()
    except httpx.TimeoutException:
        return {"available": False, "error": "timeout"}
    except Exception:
        return {"available": False, "error": "lookup failed"}

    if body.get("query_status") != "ok" or not body.get("data"):
        return {"available": True, "listed": False}

    # Take the highest-confidence match.
    rows = body["data"] if isinstance(body["data"], list) else [body["data"]]
    rows.sort(key=lambda r: r.get("confidence_level", 0) or 0, reverse=True)
    top = rows[0]

    raw_tags = top.get("tags") or []
    tags = [t.split("|")[0] for t in raw_tags] if isinstance(raw_tags, list) else []

    return {
        "available": True,
        "listed": True,
        "malware": top.get("malware", ""),
        "malware_printable": top.get("malware_printable", ""),
        "threat_type": top.get("threat_type", ""),
        "threat_type_desc": top.get("threat_type_desc", "")
        or top.get("threat_type_description", ""),
        "confidence": int(top.get("confidence_level", 0) or 0),
        "first_seen": _parse_dt(top.get("first_seen") or top.get("first_seen_utc")),
        "last_seen": _parse_dt(top.get("last_seen") or top.get("last_seen_utc")),
        "tags": tags[:8],
        "match_count": len(rows),
    }


# ─── Feodo Tracker (cached blocklist) ─────────────────────────────────────────
class FeodoBlocklist:
    """In-memory cache of active botnet C2 IPs from Feodo Tracker."""

    def __init__(self) -> None:
        self._ips: dict[str, dict] = {}
        self._refreshed_at: datetime | None = None
        self._lock = asyncio.Lock()

    @property
    def loaded(self) -> bool:
        return self._refreshed_at is not None

    @property
    def size(self) -> int:
        return len(self._ips)

    def _stale(self) -> bool:
        if self._refreshed_at is None:
            return True
        age_h = (datetime.now(timezone.utc) - self._refreshed_at).total_seconds() / 3600
        return age_h >= config.FEODO_REFRESH_HOURS

    async def refresh(self, client: httpx.AsyncClient, force: bool = False) -> None:
        if not force and not self._stale():
            return
        async with self._lock:
            if not force and not self._stale():
                return
            try:
                resp = await client.get(config.FEODO_CSV_URL, timeout=config.HTTP_TIMEOUT)
                resp.raise_for_status()
            except Exception:
                # Best-effort: keep whatever we had; never fatal to enrichment.
                return
            parsed: dict[str, dict] = {}
            reader = csv.reader(io.StringIO(resp.text))
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                # Columns: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
                if len(row) < 6:
                    continue
                ip = row[1].strip().strip('"')
                if not ip:
                    continue
                parsed[ip] = {
                    "port": row[2].strip().strip('"'),
                    "status": row[3].strip().strip('"'),
                    "last_online": _parse_dt(row[4].strip().strip('"')),
                    "malware": row[5].strip().strip('"'),
                    "first_seen": _parse_dt(row[0].strip().strip('"')),
                }
            if parsed:
                self._ips = parsed
                self._refreshed_at = datetime.now(timezone.utc)

    def check(self, ip: str) -> dict:
        hit = self._ips.get(ip)
        if not hit:
            return {"available": True, "listed": False}
        return {"available": True, "listed": True, **hit}


feodo = FeodoBlocklist()
