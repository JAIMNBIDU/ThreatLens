# ThreatLens — Setup & Run Guide

Two ways to run it. Docker is the one command path. Local dev is for when you're editing code.

---

## 0. Get the code

Clone the repo or unzip into a folder. Everything below runs from inside `ThreatLens/`:

```bash
cd ThreatLens
```

Layout:
```
ThreatLens/
├── docker-compose.yml
├── backend/
│   └── .env.example    ← copy this to .env
└── threatlens-ui/
```

---

## 1. API keys

All optional. The tool scores with whatever's available.

| Source | Free key from | Adds |
|--------|---------------|------|
| VirusTotal | virustotal.com | Detections, categories, CVEs |
| AbuseIPDB | abuseipdb.com | IP abuse score, reports, geo |
| Shodan | shodan.io | Open ports, banners, vulns (requires paid plan for host lookups) |

---

## 2. Create your `.env`

**Ubuntu / macOS:**
```bash
cp backend/.env.example backend/.env
```

**Windows (PowerShell):**
```powershell
Copy-Item backend\.env.example backend\.env
```

Open `backend/.env` and paste in your keys. Leave blank whatever you don't have:

```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=
```

> `.env` is gitignored. Never commit it. If a key ever lands in a commit, rotate it immediately.

---

## Option A — Docker (recommended)

### Prerequisites
Docker Desktop (Windows/macOS) or Docker Engine + Compose plugin (Linux):
```bash
docker --version
docker compose version
```

### Run
```bash
docker compose up --build
```

First build takes a couple minutes. When it's ready, open **http://localhost:8080**.

### Stop
```bash
docker compose down
```

Cached IOC data persists in the `threatlens-data` volume across restarts. To wipe it:
```bash
docker compose down -v
```

### Common commands
```bash
docker compose up -d --build     # run in background
docker compose logs -f backend   # tail backend logs
docker compose up --build        # rebuild after code changes
```

---

## Option B — Local dev

Two terminals.

### Prerequisites
- Python 3.11, 3.12, or 3.13
- Node.js 18+

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

> If PowerShell blocks the activate script: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

Backend is live at `http://localhost:8000/docs`.

### Terminal 2 — frontend
```bash
cd threatlens-ui
npm install
npm run dev
```

Vite prints a local URL (usually `http://localhost:5173`). Both terminals need to be running.

---

## 3. Confirm it works

1. Open the UI
2. Click **Load demo** → **Analyze IOCs**
3. Results appear with severity scores, tags, source breakdown
4. Click any card to expand the full breakdown — source cards, score components, decay curve
5. Toggle light/dark with the button top-right

The demo IP `185.220.101.45` is a known Tor exit node — with AbuseIPDB active it should score medium/high.

---

## Troubleshooting

**`env file not found`**
You skipped step 2. Copy `.env.example` to `.env`.

**Frontend loads but lookups fail / "failed to fetch"**
Backend isn't running or isn't reachable. Docker: check `docker compose logs backend`. Local: make sure Terminal 1 is running.

**Everything scores zero after adding keys**
Results are cached from a previous run with broken keys. Wipe and restart: `docker compose down -v && docker compose up --build`

**Shodan returns "invalid key or plan restriction"**
The free Shodan tier doesn't include the host lookup API. You need a paid membership for Shodan data.

**Port 8080 or 8000 already in use**
Docker: change the left number in `docker-compose.yml` under `ports`. Local: run uvicorn on a different `--port`.

**Changed code but not seeing it (Docker)**
Docker serves a built image. Rebuild: `docker compose up --build`

---

## Configuration

All in `backend/.env`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CACHE_TTL_HOURS` | 24 | How long a cached result stays fresh |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | 60 / 60 | Per-IP requests per window (seconds) |
| `MAX_IOCS` | 50 | Max IOCs per request |
| `CORS_ORIGINS` | localhost set | Allowed frontend origins, comma-separated |
| `ENABLE_DOCS` | true | Set `false` to hide `/docs` in production |
