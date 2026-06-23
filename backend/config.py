"""
Central configuration. Everything is environment-driven.
No secrets in code, no secrets in the image.
"""
import os


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


# ─── API keys ─────────────────────────────────────────────────────────────────
VT_KEY     = _env("VIRUSTOTAL_API_KEY")
ABUSE_KEY  = _env("ABUSEIPDB_API_KEY")
SHODAN_KEY = _env("SHODAN_API_KEY")

# ─── Scoring ──────────────────────────────────────────────────────────────────
HALF_LIFE_DAYS    = _env_int("HALF_LIFE_DAYS", 30)
CLUSTER_THRESHOLD = float(_env("CLUSTER_THRESHOLD", "0.65"))
# Base weights — must sum to 1.0.
# VT is the broadest signal; AbuseIPDB is IP-only but highly reliable;
# Shodan fills in infra context. When a source is unavailable its weight
# is redistributed proportionally across the active sources at score time.
SOURCE_WEIGHTS = {"virustotal": 0.50, "abuseipdb": 0.30, "shodan": 0.20}

# ─── Upstream bases ───────────────────────────────────────────────────────────
VT_BASE     = "https://www.virustotal.com/api/v3"
ABUSE_BASE  = "https://api.abuseipdb.com/api/v2"
SHODAN_BASE = "https://api.shodan.io"

# ─── Cache / persistence ──────────────────────────────────────────────────────
DB_PATH        = _env("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "threatlens.db"))
CACHE_TTL_HOURS = _env_int("CACHE_TTL_HOURS", 24)

# ─── Limits ───────────────────────────────────────────────────────────────────
MAX_IOCS           = _env_int("MAX_IOCS", 50)
MAX_IOC_LEN        = _env_int("MAX_IOC_LEN", 2048)
RATE_LIMIT_MAX     = _env_int("RATE_LIMIT_MAX", 60)
RATE_LIMIT_WINDOW  = _env_int("RATE_LIMIT_WINDOW", 60)
HTTP_TIMEOUT       = _env_int("HTTP_TIMEOUT", 15)
ENRICH_CONCURRENCY = _env_int("ENRICH_CONCURRENCY", 5)

# ─── Surface ──────────────────────────────────────────────────────────────────
CORS_ORIGINS = [
    o.strip() for o in _env(
        "CORS_ORIGINS",
        "http://localhost:5173,http://localhost:3000,http://localhost:8080",
    ).split(",") if o.strip()
]
ENABLE_DOCS = _env_bool("ENABLE_DOCS", True)
