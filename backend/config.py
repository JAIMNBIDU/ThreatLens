"""
Central configuration. Everything is environment-driven so nothing
sensitive lives in code or in the image. Sane localhost defaults for dev.
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


# ─── API keys (injected at runtime, never baked into the image) ───────────────
VT_KEY     = _env("VIRUSTOTAL_API_KEY")
ABUSE_KEY  = _env("ABUSEIPDB_API_KEY")
SHODAN_KEY = _env("SHODAN_API_KEY")

# ─── Scoring engine ───────────────────────────────────────────────────────────
HALF_LIFE_DAYS    = _env_int("HALF_LIFE_DAYS", 30)
CLUSTER_THRESHOLD = float(_env("CLUSTER_THRESHOLD", "0.65"))
SOURCE_WEIGHTS    = {"virustotal": 0.45, "abuseipdb": 0.35, "shodan": 0.20}

# ─── Upstream bases ───────────────────────────────────────────────────────────
VT_BASE        = "https://www.virustotal.com/api/v3"
ABUSE_BASE     = "https://api.abuseipdb.com/api/v2"
SHODAN_BASE    = "https://api.shodan.io"
THREATFOX_BASE = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_CSV_URL  = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

# ─── Caching / persistence ────────────────────────────────────────────────────
DB_PATH            = _env("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "threatlens.db"))
CACHE_TTL_HOURS    = _env_int("CACHE_TTL_HOURS", 24)
FEODO_REFRESH_HOURS = _env_int("FEODO_REFRESH_HOURS", 6)

# ─── Limits / abuse protection ────────────────────────────────────────────────
MAX_IOCS        = _env_int("MAX_IOCS", 50)
MAX_IOC_LEN     = _env_int("MAX_IOC_LEN", 2048)
RATE_LIMIT_MAX  = _env_int("RATE_LIMIT_MAX", 60)       # requests
RATE_LIMIT_WINDOW = _env_int("RATE_LIMIT_WINDOW", 60)  # seconds
HTTP_TIMEOUT    = _env_int("HTTP_TIMEOUT", 15)
ENRICH_CONCURRENCY = _env_int("ENRICH_CONCURRENCY", 5)

# ─── Surface controls ─────────────────────────────────────────────────────────
# Comma-separated allowlist. No "*" default — that was a flaw, not a feature.
CORS_ORIGINS = [
    o.strip() for o in _env(
        "CORS_ORIGINS",
        "http://localhost:5173,http://localhost:3000,http://localhost:8080",
    ).split(",") if o.strip()
]
ENABLE_DOCS = _env_bool("ENABLE_DOCS", True)
