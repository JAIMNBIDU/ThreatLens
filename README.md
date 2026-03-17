# ThreatLens 

A personal threat intelligence aggregator and risk scoring engine. Pulls raw indicator data from VirusTotal, AbuseIPDB, and Shodan, correlates it, applies time-decayed risk scoring, and clusters similar threats by behavior... turning noisy threat feeds into actionable signal :)

> Built for personal research use. Again as said for someone who utilizes tools...
> this is going to be useful.
> Not a commercial product.

---

## What it does

- **Enriches IOCs** (IPs, domains, file hashes, URLs) across three sources simultaneously
- **Scores each IOC** using a weighted formula with exponential time decay — old threats matter less
- **Clusters similar threats** using Jaccard similarity on behavioral tag sets
- **Exports reports** as JSON or CSV for further analysis
- **Clean dashboard UI** built in React — filter by severity, type, sort by score or recency

---

## Architecture

```
React Frontend (Vite)
        │
        │  HTTP (localhost:8000)
        ▼
FastAPI Backend (Python)
        │
        ├──▶ VirusTotal API   (detections, categories, CVEs, PoC flags)
        ├──▶ AbuseIPDB API    (abuse score, reports, ISP, Tor detection)
        └──▶ Shodan API       (open ports, CVEs with CVSS, banners, OS)
```

All API calls happen server-side. Keys never touch the browser.

---

## Screenshots
<img width="1920" height="1200" alt="Screenshot 2026-03-18 005706" src="https://github.com/user-attachments/assets/0000da4f-def1-4feb-8b18-65170e2d1490" />

<img width="1920" height="1200" alt="Screenshot 2026-03-18 005643" src="https://github.com/user-attachments/assets/b332d409-6b2c-4eac-bebd-adbe36a7dc65" />

---

## Tech Stack

| Layer    | Technology          |
|----------|---------------------|
| Frontend | React 18, Vite      |
| Backend  | Python 3.11+, FastAPI, uvicorn |
| HTTP     | httpx (async)       |
| Config   | python-dotenv       |

---

## Project Structure

```
ThreatLens/
├── backend/
│   ├── main.py              # FastAPI app — all scoring, enrichment, clustering logic
│   ├── requirements.txt     # Python dependencies
│   ├── .env.example         # API key template (copy to .env)
│   ├── .env                 # Your actual keys — never commit this
│   └── .gitignore
└── frontend/
    └── threat-intel-dashboard.jsx   # React single-file dashboard component
```

---

## Prerequisites

- Python 3.10 or higher
- Node.js 16 or higher
- API keys for:
  - [VirusTotal](https://virustotal.com/gui/my-apikey) — 500 req/day free
  - [AbuseIPDB](https://abuseipdb.com/account/api) — 1000 req/day free
  - [Shodan](https://account.shodan.io) — 100 req/month free

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/JAIMNBIDU/ThreatLens.git
cd ThreatLens
```

### 2. Backend

```bash
cd backend

# Create and activate virtual environment
python -m venv .venv

# Mac/Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

```bash
# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env   # Windows: copy .env.example .env
```

Edit `.env` with your keys:
```
VIRUSTOTAL_API_KEY=put_the_api_key_from_your_account
ABUSEIPDB_API_KEY=put_the_api_key_from_your_account
SHODAN_API_KEY=put_the_api_key_from_your_account
```

```bash
# Start the backend
uvicorn main:app --reload --port 8000
```

Verify it's running — open `http://localhost:8000` in your browser:
```json
{
  "service": "ThreatLens API",
  "keys_configured": {
    "virustotal": true,
    "abuseipdb": true,
    "shodan": true
  }
}
```

All three must show `true`. If any show `false`, check your `.env` file. (If not in individual lines, then in a single line for those who are just using without reading the code)

Interactive API docs will be available at `http://localhost:8000/docs`.

### 3. Frontend

Open a second terminal (keep the backend running):

```bash
cd frontend

# Scaffold a Vite React app
npm create vite@latest threatintel-ui -- --template react
cd threatintel-ui
npm install

# Copy the dashboard component in
# Mac/Linux
cp ../threat-intel-dashboard.jsx src/

# Windows (PowerShell)
copy ..\threat-intel-dashboard.jsx src\
```

Replace `src/App.jsx` with:
```jsx
import ThreatLensDashboard from './threat-intel-dashboard'
import './App.css'

export default function App() {
  return <ThreatLensDashboard />
}
```

Clear `src/index.css` completely (delete all default Vite styles).

```bash
npm run dev
```

Open `http://localhost:5173`. Click **Check Backend** in the top right to confirm the connection.

---

## Usage

1. Paste IOCs into the input box — one per line
2. Click **Analyze IOCs**
3. Click any result card to expand full source details, score breakdown, and the decay curve
4. Switch to the **Clusters** tab to see behaviorally similar IOCs grouped together
5. Export results as **JSON** or **CSV** using the buttons in the header

### Supported IOC types

| Type            | Auto-detected by     | VT | AbuseIPDB | Shodan |
|-----------------|----------------------|----|-----------|--------|
| IPv4 address    | Regex `x.x.x.x`      | ✓  | ✓         | ✓      |
| Domain          | Fallback             | ✓  | —         | —      |
| MD5 / SHA256    | Hex string length    | ✓  | —         | —      |
| URL             | `http://` / `https://` | ✓ | —        | —      |

### Test IOCs

```
185.220.101.45
91.92.109.174
194.165.16.11
malware-c2.ru
emotet-cdn.xyz
44d88612fea8a8f36de82e1278abb02f
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
http://malware-delivery.xyz/payload.exe
https://phishing-login.ru/microsoft/verify
cobalt-strike-c2.online
```

The hash `44d88612fea8a8f36de82e1278abb02f` is the EICAR test string — every AV engine flags it, good for verifying VirusTotal is working.

---

## API Reference

### `POST /enrich`
Enrich up to 50 IOCs. Returns full source data, risk scores, and cluster analysis.

```bash
curl -X POST http://localhost:8000/enrich \
  -H "Content-Type: application/json" \
  -d '{"iocs": ["185.220.101.45", "malware.xyz", "44d88612fea8a8f36de82e1278abb02f"]}'
```

**Response shape:**
```json
{
  "results": [...],
  "clusters": [...],
  "summary": {
    "total": 3,
    "avg_decayed_score": 42.5,
    "severity_counts": { "critical": 1, "high": 1, "medium": 1, "low": 0 },
    "cluster_count": 1
  },
  "errors": []
}
```

### `GET /enrich/{ioc}`
Quick single-IOC lookup.
```bash
curl http://localhost:8000/enrich/185.220.101.45
```

### `POST /score`
Fast path — returns scores and tags only, skips full source data.
```bash
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{"iocs": ["185.220.101.45"]}'
```

### `GET /health`
Liveness check.

### `GET /`
Shows service info and which API keys are configured.

---

## Scoring Model

### Formula

```
vt_score     = (malicious + suspicious detections / total engines) × 100
abuse_score  = AbuseIPDB confidence score (0–100)
shodan_score = Σ(CVSSv3 × 5) + (open port count × 2), capped at 100

raw_score    = vt_score × 0.45
             + abuse_score × 0.35
             + shodan_score × 0.20

decay_factor = e^(−ln2 × days_since_last_seen / 30)

final_score  = raw_score × decay_factor
```

For non-IP types (domain, hash, URL) where AbuseIPDB and Shodan don't apply, VirusTotal carries 100% of the raw score.

### Severity thresholds

| Severity | Decayed Score |
|----------|---------------|
| Critical | ≥ 75          |
| High     | ≥ 50          |
| Medium   | ≥ 25          |
| Low      | < 25          |

### Time decay

Uses a 30-day half-life. A threat last seen 30 days ago has 50% of its original score weight. At 60 days, 25%. At 90 days, ~12.5%. This ensures recently active threats surface above stale historical data.

---

## Clustering

Groups IOCs by behavioral similarity using Jaccard similarity on tag sets.

```
similarity = |tags_A ∩ tags_B| / |tags_A ∪ tags_B|
```

IOCs with similarity ≥ 0.65 are placed in the same cluster. Tags are derived from VirusTotal categories, Shodan port signatures, and AbuseIPDB metadata (Tor, mass-reported, etc.).

Singletons (IOCs with no similar peers) are shown but labeled separately.

---

## Known Limitations

- **Shodan free tier**: 100 queries/month. Burns fast on large IP batches. Use the paid tier or be selective.
- **VirusTotal rate limit**: 4 requests/minute on free tier. The backend semaphore caps concurrency at 5, but large batches will queue.
- **No persistence**: Results are in-memory only. Refresh the page and they're gone. A database layer would fix this and might implement it in the future on some related projects.
- **CORS**: Currently set to `allow_origins=["*"]`. Tighten this before any public deployment.

---

## Security

- Never commit `.env` — it's in `.gitignore`
- API keys live server-side only, never sent to the browser
- Add rate limiting (`slowapi`) before any public-facing deployment
- Tighten `allow_origins` in `main.py` to your specific frontend URL in production

---

## License

MIT — do whatever you want with it.
