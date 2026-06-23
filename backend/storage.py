"""
SQLite-backed cache + lookup history.

Why stdlib sqlite3 instead of an async driver: fewer dependencies (supply-chain
hygiene), and a local file DB is fast enough that the only real concern is not
blocking the event loop — which we solve with asyncio.to_thread. WAL mode keeps
concurrent reads/writes from tripping over each other.

The same table doubles as cache (TTL freshness) and history (first_seen,
last_seen, lookup_count), which is what makes "have I seen this IOC before?"
a free feature.
"""
import asyncio
import json
import os
import sqlite3
from datetime import datetime, timezone

import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    ioc          TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    result_json  TEXT NOT NULL,
    decayed      REAL,
    severity     TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    fetched_at   TEXT NOT NULL,
    lookup_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(config.DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def _init_sync() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def _get_sync(ioc: str):
    with _connect() as conn:
        row = conn.execute("SELECT * FROM iocs WHERE ioc = ?", (ioc,)).fetchone()
        return dict(row) if row else None


def _touch_sync(ioc: str) -> int:
    """Record a cache hit: bump lookup_count + last_seen, return new count."""
    with _connect() as conn:
        conn.execute(
            "UPDATE iocs SET lookup_count = lookup_count + 1, last_seen = ? WHERE ioc = ?",
            (_now(), ioc),
        )
        row = conn.execute("SELECT lookup_count FROM iocs WHERE ioc = ?", (ioc,)).fetchone()
        return row["lookup_count"] if row else 1


def _upsert_sync(ioc: str, ioc_type: str, result: dict) -> dict:
    now = _now()
    payload = json.dumps(result, separators=(",", ":"))
    decayed = result.get("score", {}).get("decayed")
    severity = result.get("score", {}).get("severity")
    with _connect() as conn:
        existing = conn.execute(
            "SELECT first_seen, lookup_count FROM iocs WHERE ioc = ?", (ioc,)
        ).fetchone()
        if existing:
            first_seen = existing["first_seen"]
            count = existing["lookup_count"] + 1
            conn.execute(
                """UPDATE iocs SET type=?, result_json=?, decayed=?, severity=?,
                   last_seen=?, fetched_at=?, lookup_count=? WHERE ioc=?""",
                (ioc_type, payload, decayed, severity, now, now, count, ioc),
            )
        else:
            first_seen = now
            count = 1
            conn.execute(
                """INSERT INTO iocs (ioc, type, result_json, decayed, severity,
                   first_seen, last_seen, fetched_at, lookup_count)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (ioc, ioc_type, payload, decayed, severity, first_seen, now, now, count),
            )
    return {"first_seen": first_seen, "lookup_count": count}


def _stats_sync() -> dict:
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM iocs").fetchone()["c"]
        by_sev = {
            r["severity"]: r["c"]
            for r in conn.execute(
                "SELECT severity, COUNT(*) c FROM iocs GROUP BY severity"
            ).fetchall()
            if r["severity"]
        }
        return {"cached_iocs": total, "by_severity": by_sev}


# ─── Async wrappers ───────────────────────────────────────────────────────────
async def init_db() -> None:
    await asyncio.to_thread(_init_sync)


async def get_cached(ioc: str, ttl_hours: int):
    """Return (result_dict, meta) if a *fresh* cache entry exists, else None."""
    row = await asyncio.to_thread(_get_sync, ioc)
    if not row:
        return None
    try:
        fetched = datetime.fromisoformat(row["fetched_at"])
    except ValueError:
        return None
    age_h = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600
    if age_h > ttl_hours:
        return None
    count = await asyncio.to_thread(_touch_sync, ioc)
    result = json.loads(row["result_json"])
    return result, {"first_seen": row["first_seen"], "lookup_count": count}


async def seen_before(ioc: str):
    """Return history meta if the IOC was ever looked up, ignoring freshness."""
    row = await asyncio.to_thread(_get_sync, ioc)
    if not row:
        return None
    return {"first_seen": row["first_seen"], "lookup_count": row["lookup_count"]}


async def save(ioc: str, ioc_type: str, result: dict) -> dict:
    return await asyncio.to_thread(_upsert_sync, ioc, ioc_type, result)


async def stats() -> dict:
    return await asyncio.to_thread(_stats_sync)
