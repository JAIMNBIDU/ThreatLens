# ThreatLens v2 — Setup & Run Guide

Two ways to run it. Pick one.

- **Docker** — one command, nothing to install except Docker. Use this unless you're actively editing code.
- **Local dev** — run the backend and frontend yourself with hot-reload. Use this when you're hacking on it.

ThreatLens runs with **zero API keys** out of the box (the abuse.ch feeds are keyless). Keys for VirusTotal / AbuseIPDB / Shodan just add depth.

---

## 0. Get the code

Unzip `ThreatLens-v2.zip` somewhere sane. Everything below runs from inside the `ThreatLens-v2/` folder:

```bash
unzip ThreatLens-v2.zip
cd ThreatLens-v2
```

Folder layout:

```
ThreatLens-v2/
├── docker-compose.yml
├── backend/            FastAPI + scoring + cache + intel feeds
│   └── .env.example    copy this to .env
└── threatlens-ui/      React + Vite frontend
```

---

## 1. API keys (optional, but recommended)

| Source | Where to get a free key | What it adds |
|--------|-------------------------|--------------|
| VirusTotal | virustotal.com → sign up → profile → API key | Detections, categories, CVEs |
| AbuseIPDB | abuseipdb.com → account → API | IP abuse score, reports, geo |
| Shodan | shodan.io → account | Open ports, banners, vulns |
| ThreatFox | none needed | Malware family + threat type |
| Feodo Tracker | none needed | Active botnet C2 list |

You can skip all three paid ones and ThreatLens still works — every IP gets checked against the keyless abuse.ch feeds.

---

## 2. Create your `.env`

This step is required for Docker (compose reads `backend/.env`). The repo ships `.env.example`; copy it and fill in whatever keys you have.

**Ubuntu / macOS:**
```bash
cp backend/.env.example backend/.env
```

**Windows (PowerShell):**
```powershell
Copy-Item backend\.env.example backend\.env
```

Open `backend/.env` and paste your keys after the `=`. Leave any you don't have blank — that's fine:

```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=your_key_here
```

> `.env` is gitignored. Never commit it. If a key ever lands in a commit, rotate it — it's burned.

---

## Option A — Run with Docker (recommended)

### Prerequisites
- Docker Desktop (Windows/macOS) or Docker Engine + the Compose plugin (Linux). Verify:
  ```bash
  docker --version
  docker compose version
  ```

### Run
From the `ThreatLens-v2/` folder:
```bash
docker compose up --build
```

First build takes a couple minutes (pulls base images, installs deps, builds the frontend). When you see the backend report it's healthy and nginx start, open:

**http://localhost:8080**

### Stop
`Ctrl+C` in the terminal, then:
```bash
docker compose down
```

Your cached IOC data survives `down` — it lives in a named volume (`threatlens-data`), not in the containers.

### Useful Docker commands
```bash
docker compose up -d --build     # run in the background
docker compose logs -f backend   # tail backend logs
docker compose down -v           # stop AND wipe the cached data volume
docker compose up --build        # rebuild after you change code
```

Only port **8080** is exposed to your machine. The backend sits on the internal Docker network — the browser reaches it through nginx at `/api`, so there's no CORS to deal with.

---

## Option B — Run locally for development

Two terminals: one for the backend, one for the frontend.

### Prerequisites
- **Python 3.11, 3.12, or 3.13** (`python --version`)
- **Node.js 18+** and npm (`node --version`)

### Terminal 1 — backend

**Ubuntu / macOS:**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Windows (PowerShell):**
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Backend is now on `http://localhost:8000`. Quick check — open `http://localhost:8000/docs`.

> If PowerShell blocks the activate script with an execution-policy error:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then re-run the activate line.

### Terminal 2 — frontend
```bash
cd threatlens-ui
npm install
npm run dev
```

Vite prints a local URL (usually `http://localhost:5173`). Open it. In dev mode the frontend talks to `http://localhost:8000` directly, so both terminals need to be running.

---

## 3. Confirm it works

1. Open the UI (`:8080` for Docker, the Vite URL for local dev).
2. Click **Load demo**, then **Analyze IOCs**.
3. You should get scored cards. Click one to expand it — sources, score breakdown, decay chart.
4. Toggle light/dark with the sun/moon button, top-right.

The demo includes `185.220.101.45`, a known-bad IP — if the abuse.ch feeds loaded, expect it to come back high/critical with an **INTEL-CONFIRMED** badge.

---

## Troubleshooting

**`docker compose up` errors about a missing env file**
You skipped step 2. `cp backend/.env.example backend/.env` and retry.

**Frontend loads but every lookup errors / "failed to fetch"**
Backend isn't reachable. Docker: check `docker compose logs backend`. Local dev: make sure Terminal 1 (uvicorn) is actually running on port 8000.

**Local backend install fails building `pydantic-core` with a Rust/cargo error**
You're on an old pinned pydantic against a newer Python. This build already pins `pydantic>=2.9`, which ships prebuilt wheels — so make sure you installed from *this* `requirements.txt` in a fresh venv. If it persists, your Python is bleeding-edge; use 3.12.

**Everything comes back "not configured" / low scores**
No API keys set. Either add keys to `backend/.env` (then `docker compose up --build` again), or rely on the keyless feeds — only IPs get enriched by those.

**Port 8080 or 8000 already in use**
Something else is on that port. Docker: change the left number in `docker-compose.yml` under `ports` (e.g. `"8090:8080"`). Local: run uvicorn on a different `--port`.

**Changed code but don't see it (Docker)**
Docker serves a built image. Rebuild: `docker compose up --build`. (Local dev hot-reloads automatically.)

---

## Configuration knobs

All live in `backend/.env` (see `.env.example` for the full list). The ones you'll actually touch:

| Variable | Default | What it does |
|----------|---------|--------------|
| `CACHE_TTL_HOURS` | 24 | How long a cached lookup stays fresh |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | 60 / 60 | Requests per IP per window (seconds) |
| `MAX_IOCS` | 50 | Max IOCs per request |
| `CORS_ORIGINS` | localhost set | Allowed frontend origins (comma-separated) |
| `ENABLE_DOCS` | true | Set `false` to hide `/docs` in production |

After changing `.env` under Docker, re-run `docker compose up --build` for it to take effect.
