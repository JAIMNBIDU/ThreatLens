# ThreatLens

A threat-intelligence aggregator and risk-scoring engine. Paste indicators of compromise (IPs, domains, URLs, file hashes) and get back enriched, scored, and clustered results that draw on multiple intel sources at once.

ThreatLens pulls from **VirusTotal**, **AbuseIPDB**, **Shodan**, and the keyless **abuse.ch** feeds (**ThreatFox** + **Feodo Tracker**), applies a transparent risk model with time decay and a confirmed-intel floor, groups related indicators by behaviour, and caches everything so repeat lookups don't burn API quota.

> **Runs with zero API keys.** The abuse.ch feeds need no credentials, so ThreatLens is useful the moment it starts. Adding VirusTotal / AbuseIPDB / Shodan keys just deepens the picture.

---

## Why this rewrite

The first version worked but was painful to stand up: a long chain of manual steps, and a dependency stack that broke outright on newer Python (an old `pydantic` with no prebuilt wheel for Python 3.13 would fall back to a Rust source build and fail). Getting it running was the hard part — not using it.

This version fixes that. **Setup is one command.** The interpreter and every dependency are pinned and containerised, so "works on my machine" is now "works on every machine."

```bash
cp backend/.env.example backend/.env
docker compose up --build
```

Open **http://localhost:8080**. That's the whole setup.

---

## Features

**Multi-source enrichment**
- VirusTotal — detection ratio, categories, reputation, crowdsourced CVEs
- AbuseIPDB — abuse confidence score, report volume, geo/ISP, Tor flag
- Shodan — open ports, service banners, host vulnerabilities (CVSS-ranked)
- ThreatFox *(keyless)* — malware-family attribution and threat classification
- Feodo Tracker *(keyless)* — active botnet C2 blocklist membership

**Risk scoring**
- Weighted blend of source signals, normalised 0–100
- **Time decay** — a 30-day half-life discounts stale intel (`decayed = raw × e^(−ln2·t/30)`)
- **Intel floor** — a confirmed threat can't be downgraded by a cold reputation score (details below)
- Four-tier severity (low / medium / high / critical) with a full component breakdown

**Behavioural clustering**
- Jaccard similarity over behavioural tags groups indicators that look like the same campaign or toolkit

**Caching & history**
- SQLite-backed cache with a configurable TTL — repeat lookups are instant and free
- Tracks `first_seen`, `last_seen`, and `lookup_count` per indicator ("have I seen this before?")

**Interface**
- Single-page React dashboard, light/dark theme (persisted, respects system preference)
- Expandable per-IOC cards: source data, score breakdown, live decay curve
- Per-source cards, clustering view, summary stats, and JSON/CSV export

---

## What's new since v1

| Area | v1 | Now |
|------|----|-----|
| Setup | Many manual steps, version conflicts | One command via Docker Compose |
| Dependencies | Broke on Python 3.13 (pydantic source build) | Pinned, prebuilt wheels, Python 3.12 base image |
| Intel sources | 3 (all key-gated) | 5, including 2 keyless feeds — works with no keys at all |
| Scoring | Weighted blend only | Adds an intel-confirmation floor + malware-family attribution |
| Persistence | None (stateless, every lookup hit the APIs) | SQLite cache + lookup history; API quota preserved |
| Backend layout | Single ~570-line file | Split into focused modules (`config`, `storage`, `intel`, `security`, `main`) |
| Security | Wildcard CORS, no rate limiting, no input validation | Hardened across the board (see below) |
| Deployment | Run two dev servers by hand | `docker compose up` — backend + frontend, networked, healthchecked |

---

## How it works

### The scoring model

A base score is a weighted blend of the source signals (VirusTotal 0.45, AbuseIPDB 0.35, Shodan 0.20), each normalised to 0–100. Time decay then discounts that score based on the most recent signal date — month-old intel shouldn't carry the same weight as something seen yesterday.

The key design decision is the **intel floor**. Confirmed intelligence (a ThreatFox malware match or a Feodo active-C2 listing) doesn't get *averaged in* — it sets a *minimum*:

```
raw = max(weighted_source_score, intel_score)
```

Why: a known botnet C2 should read as critical even if VirusTotal hasn't caught up to it yet. Averaging would let a cold reputation score drag a confirmed threat down to "low." The floor prevents that. Every response exposes `base_raw`, `intel_score`, `boosted`, and `boosted_by`, so the reasoning is fully auditable — and the UI shows an **INTEL-CONFIRMED** badge with the math spelled out.

### Architecture

```
┌──────────────┐      /api       ┌──────────────┐      ┌─ VirusTotal
│  Frontend    │  ───────────▶   │   Backend    │ ───▶ ├─ AbuseIPDB
│  React+Vite  │   (same-origin  │   FastAPI    │      ├─ Shodan
│  served by   │    via nginx    │              │      ├─ ThreatFox    (keyless)
│  nginx :8080 │    proxy)       │   :8000      │      └─ Feodo Tracker (keyless)
└──────────────┘                 └──────┬───────┘
                                        │
                                   ┌────▼─────┐
                                   │  SQLite  │  cache + lookup history
                                   └──────────┘
```

The browser only ever talks to the frontend's own origin; nginx proxies `/api` to the backend over the internal Docker network. Same-origin means CORS never enters the request path in the default deployment.

---

## Setup

The quickstart above is all most people need. For prerequisites, a no-Docker local-dev workflow, Windows/PowerShell commands, and troubleshooting, see **[SETUP.md](SETUP.md)**.

### API keys (all optional)

| Source | Free key from | Adds |
|--------|---------------|------|
| VirusTotal | virustotal.com | detections, categories, CVEs |
| AbuseIPDB | abuseipdb.com | IP abuse score, reports, geo |
| Shodan | shodan.io | ports, banners, host vulns |
| ThreatFox | — none — | malware family + threat type |
| Feodo Tracker | — none — | active C2 list |

Put whatever keys you have into `backend/.env` (copied from `backend/.env.example`). Leave the rest blank.

---

## API

| Method | Route | Purpose |
|--------|-------|---------|
| `POST` | `/enrich` | Enrich + cluster a list of IOCs (up to `MAX_IOCS`) |
| `POST` | `/score` | Scores only — no full source payloads |
| `GET` | `/enrich/{ioc}` | Single-IOC lookup |
| `GET` | `/stats` | Cached-corpus stats |
| `GET` | `/health` | Liveness probe |
| `GET` | `/` | Configured keys + intel-feed status |

Interactive docs at `/docs` when `ENABLE_DOCS=true`.

```bash
curl -X POST http://localhost:8080/api/enrich \
  -H "Content-Type: application/json" \
  -d '{"iocs": ["185.220.101.45", "example.com"]}'
```

---

## Security

The rewrite treated the build and deploy path as part of the attack surface. Each item below was a real weakness in v1 or its tooling, and what replaced it:

| Flaw | Fix |
|------|-----|
| `pydantic` too old for Python 3.13 → failed Rust source build | Bumped to a version with prebuilt wheels; Docker pins Python 3.12 so it can't recur |
| `CORS allow_origins=["*"]` — any site could call the API | Env-driven origin allowlist, no wildcard; same-origin proxy in Docker removes CORS from the path entirely |
| No rate limiting | Per-IP sliding-window limiter on every route |
| Arbitrary strings flowed into upstream API URLs | Strict per-type IOC validation + length cap; junk rejected before any outbound call; inputs de-duplicated |
| Raw exception strings returned to clients | Errors logged server-side; clients get sanitized messages |
| `.env` sat inside the project tree | Excluded via `.gitignore` / `.dockerignore`; keys injected at runtime, never baked into the image |
| Container ran as root | Runs as a non-root user |
| `/docs` always public | Toggleable with `ENABLE_DOCS=false` |
| No image hygiene | Pinned base images, no pip cache, healthchecks, backend not published to the host |

**Not yet included** (the honest next steps for a public-internet deployment): TLS termination via a reverse proxy, and `pip --require-hashes` for fully reproducible installs.

If an API key has ever been committed or shared anywhere, rotate it — exposure burns a key regardless of later cleanup.

---

## Configuration

All via `backend/.env` (see `.env.example` for the complete list):

| Variable | Default | Purpose |
|----------|---------|---------|
| `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` / `SHODAN_API_KEY` | — | Source credentials (optional) |
| `CORS_ORIGINS` | localhost set | Allowed frontend origins (comma-separated) |
| `CACHE_TTL_HOURS` | 24 | Cache freshness window |
| `FEODO_REFRESH_HOURS` | 6 | How often the C2 blocklist refreshes |
| `MAX_IOCS` | 50 | Max indicators per request |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | 60 / 60 | Per-IP requests per window (seconds) |
| `ENRICH_CONCURRENCY` | 5 | Concurrent upstream lookups |
| `ENABLE_DOCS` | true | Expose `/docs` and the OpenAPI schema |

---

## Tech stack

**Backend** — Python · FastAPI · httpx (async) · SQLite (stdlib, off-thread)
**Frontend** — React · Vite · CSS-variable theming, no UI framework
**Deploy** — Docker · Docker Compose · nginx

---

## Roadmap

- **Detection export** — emit Sigma rules, STIX 2.1 bundles, and plain blocklists (firewall / pi-hole / hosts) from results, so ThreatLens produces deployable detections, not just scores
- **MITRE ATT&CK mapping** — map behavioural tags to technique IDs
- Optional GeoIP enrichment via a local MaxMind database (offline, no quota)

---

## License

Add a license file before publishing — `MIT` is the usual choice for a project like this. Without one, others can view the code but have no legal right to use it.
