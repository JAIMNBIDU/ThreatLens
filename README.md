# ThreatLens

A threat-intelligence aggregator and risk-scoring engine. Paste indicators of compromise — IPv4s, domains, URLs, MD5/SHA256 hashes — and get back enriched, scored, and clustered results from multiple intel sources in one shot.

```bash
cp backend/.env.example backend/.env   # add your keys
docker compose up --build
```

Open **http://localhost:8080**

---

## Sources

| Source | Type | Adds |
|--------|------|------|
| VirusTotal | Key-gated | Detection ratio, categories, reputation, CVEs, PoC flags |
| AbuseIPDB | Key-gated | Abuse confidence score, report volume, geo, ISP, Tor flag |
| Shodan | Key-gated (paid tier for host lookups) | Open ports, service banners, CVEs ranked by CVSS |

All three keys are optional — the tool scores with whatever's available.

---

## Scoring model

Each source produces a normalised 0–100 signal. The final score is a **weighted blend with dynamic redistribution**: base weights are VT 50%, AbuseIPDB 30%, Shodan 20%. When a source is unavailable, its weight redistributes proportionally across the sources that did return data — so a two-source result isn't artificially capped.

Time decay applies a 30-day half-life so stale intel doesn't carry the same weight as a fresh hit:

```
decayed = raw × e^(−ln2 × days_ago / 30)
```

Severity tiers: **critical** ≥75 · **high** ≥50 · **medium** ≥25 · **low** <25

---

## Features

- Multi-source enrichment with per-source breakdown and score components
- SQLite cache with configurable TTL — repeat lookups are instant, quota is preserved
- Lookup history (`first_seen`, `last_seen`, `lookup_count`) per IOC
- Behavioural clustering via Jaccard similarity over extracted tags
- Light/dark theme toggle, persisted to localStorage
- JSON and CSV export
- Per-IP rate limiting, strict IOC input validation, non-root container

---

## Architecture

```
┌─────────────────┐    /api (same-origin)    ┌──────────────┐
│  React + Vite   │  ──────────────────────▶ │   FastAPI    │ ──▶ VirusTotal
│  served by      │  nginx proxies /api to   │   backend    │ ──▶ AbuseIPDB
│  nginx :8080    │  backend on internal net  │   :8000      │ ──▶ Shodan
└─────────────────┘                          └──────┬───────┘
                                                    │
                                             ┌──────▼──────┐
                                             │   SQLite    │ cache + history
                                             └─────────────┘
```

The browser never makes a cross-origin request — nginx proxies `/api` to the backend over the Docker internal network. CORS is not in the request path.

---

## Setup

### Docker (recommended)

Prerequisites: Docker Desktop (Windows/macOS) or Docker Engine + Compose plugin (Linux).

```bash
cp backend/.env.example backend/.env
# paste your API keys into backend/.env
docker compose up --build
```

### Local dev

```bash
# Terminal 1 — backend
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Terminal 2 — frontend
cd threatlens-ui
npm install && npm run dev
```

See **[SETUP.md](SETUP.md)** for full instructions, Windows/PowerShell commands, and troubleshooting.

---

## API

| Method | Route | Purpose |
|--------|-------|---------|
| `POST` | `/enrich` | Enrich + cluster a list of IOCs |
| `POST` | `/score` | Scores only — no full source payloads |
| `GET` | `/enrich/{ioc}` | Single IOC lookup |
| `GET` | `/stats` | Cache corpus stats |
| `GET` | `/health` | Liveness |
| `GET` | `/` | Key status |

```bash
curl -X POST http://localhost:8080/api/enrich \
  -H "Content-Type: application/json" \
  -d '{"iocs": ["185.220.101.45", "example.com"]}'
```

---

## Configuration

All via `backend/.env`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `VIRUSTOTAL_API_KEY` | — | VirusTotal key |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB key |
| `SHODAN_API_KEY` | — | Shodan key (paid tier for host lookups) |
| `CORS_ORIGINS` | localhost set | Allowed origins, comma-separated |
| `CACHE_TTL_HOURS` | 24 | Cache freshness window |
| `MAX_IOCS` | 50 | Max IOCs per request |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | 60 / 60 | Per-IP requests per window |
| `ENABLE_DOCS` | true | Expose `/docs` |

---

## Security

| Flaw | Fix |
|------|-----|
| Old pydantic broke on Python 3.13 (Rust source build crash) | `pydantic>=2.9` with prebuilt wheels; Docker pins Python 3.12 |
| `CORS allow_origins=["*"]` | Env-driven allowlist; same-origin proxy in Docker removes CORS from the path |
| No rate limiting | Per-IP sliding-window limiter on every route |
| Arbitrary strings into upstream API URLs | Strict per-type IOC validation + length cap |
| Raw exceptions returned to clients | Server-side logging only; sanitized client responses |
| `.env` in project tree | `.gitignore` + `.dockerignore` excluded; keys injected at runtime |
| Container running as root | Non-root `appuser` |
| `/docs` always public | Toggle with `ENABLE_DOCS=false` |

---

## Stack

**Backend** — Python · FastAPI · httpx · SQLite (stdlib)
**Frontend** — React · Vite · CSS custom properties (no UI framework)
**Deploy** — Docker · Docker Compose · nginx

---

## Roadmap

- Detection export: Sigma rule stubs, STIX 2.1 bundles, plain blocklists
- MITRE ATT&CK tag mapping
- Force-refresh endpoint to bypass cache on demand
