"""
ThreatLens — FastAPI Backend
Aggregates threat intelligence from VirusTotal, AbuseIPDB, and Shodan.
Risk scoring with time decay + behavioral clustering.
"""

import asyncio
import math
import re
import os
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from dotenv import load_dotenv

load_dotenv()

# ─── Config ───────────────────────────────────────────────────────────────────
VT_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_KEY    = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_KEY   = os.getenv("SHODAN_API_KEY", "")

HALF_LIFE_DAYS   = 30
CLUSTER_THRESHOLD = 0.65
SOURCE_WEIGHTS   = {"virustotal": 0.45, "abuseipdb": 0.35, "shodan": 0.20}

VT_BASE     = "https://www.virustotal.com/api/v3"
ABUSE_BASE  = "https://api.abuseipdb.com/api/v2"
SHODAN_BASE = "https://api.shodan.io"

app = FastAPI(title="ThreatLens API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten to your frontend URL in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Models ───────────────────────────────────────────────────────────────────
class IOCRequest(BaseModel):
    iocs: list[str]

    @field_validator("iocs")
    @classmethod
    def limit_iocs(cls, v):
        if len(v) > 50:
            raise ValueError("Max 50 IOCs per request")
        return [i.strip() for i in v if i.strip()]


class BulkRequest(BaseModel):
    iocs: list[str]

    @field_validator("iocs")
    @classmethod
    def limit_bulk(cls, v):
        if len(v) > 50:
            raise ValueError("Max 50 IOCs per request")
        return [i.strip() for i in v if i.strip()]


# ─── IOC Type Detection ───────────────────────────────────────────────────────
def detect_type(ioc: str) -> str:
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ioc):
        return "ipv4"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc) or re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "hash"
    if re.match(r"^https?://", ioc, re.I):
        return "url"
    return "domain"


# ─── Time Decay ───────────────────────────────────────────────────────────────
def time_decay(days_ago: int) -> float:
    return math.exp(-math.log(2) * days_ago / HALF_LIFE_DAYS)


def days_since(dt_str: Optional[str]) -> int:
    if not dt_str:
        return 0
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - dt
        return max(0, delta.days)
    except Exception:
        return 0


# ─── VirusTotal ───────────────────────────────────────────────────────────────
async def fetch_virustotal(ioc: str, ioc_type: str, client: httpx.AsyncClient) -> dict:
    if not VT_KEY:
        return {"error": "No VirusTotal API key configured", "available": False}

    headers = {"x-apikey": VT_KEY}
    endpoint_map = {
        "ipv4":   f"{VT_BASE}/ip_addresses/{ioc}",
        "domain": f"{VT_BASE}/domains/{ioc}",
        "hash":   f"{VT_BASE}/files/{ioc}",
        "url":    None,  # URLs need encoding step first
    }

    try:
        if ioc_type == "url":
            # Submit URL for analysis, then fetch report
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            url = f"{VT_BASE}/urls/{url_id}"
        else:
            url = endpoint_map[ioc_type]

        resp = await client.get(url, headers=headers, timeout=15)

        if resp.status_code == 404:
            return {"available": True, "detections": 0, "total": 0, "ratio": 0.0,
                    "categories": [], "tags": [], "last_analysis_date": None,
                    "cvss": 0.0, "has_poc": False, "reputation": 0}

        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit hit", "available": False}

        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values()) or 1

        # Extract CVE / vulnerability data
        popular_threat_classification = data.get("popular_threat_classification", {})
        tags = data.get("tags", [])
        categories = list(data.get("categories", {}).values())[:5]

        # Shodan vuln data sometimes surfaces in VT for IPs
        crowdsourced_ids = data.get("crowdsourced_ids_results", [])
        cves = list({
            rule.get("rule_id") for entry in crowdsourced_ids
            for rule in entry.get("rule_details", [])
            if rule.get("rule_id", "").startswith("CVE-")
        })

        has_poc = bool(data.get("crowdsourced_context")) or "exploit" in " ".join(tags).lower()

        last_analysis_date = data.get("last_analysis_date")
        if last_analysis_date:
            last_analysis_date = datetime.fromtimestamp(
                last_analysis_date, tz=timezone.utc
            ).isoformat()

        return {
            "available": True,
            "detections": malicious + suspicious,
            "total": total,
            "ratio": round((malicious + suspicious) / total, 4),
            "categories": categories[:5],
            "tags": tags[:8],
            "last_analysis_date": last_analysis_date,
            "cvss": float(data.get("crowdsourced_ids_stats", {}).get("high", 0)) or 0.0,
            "has_poc": has_poc,
            "reputation": data.get("reputation", 0),
            "cves": cves[:5],
        }

    except httpx.TimeoutException:
        return {"error": "VirusTotal timeout", "available": False}
    except Exception as e:
        return {"error": str(e), "available": False}


# ─── AbuseIPDB ────────────────────────────────────────────────────────────────
async def fetch_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict:
    if not ABUSE_KEY:
        return {"error": "No AbuseIPDB API key configured", "available": False}

    try:
        resp = await client.get(
            f"{ABUSE_BASE}/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=15,
        )
        if resp.status_code == 429:
            return {"error": "AbuseIPDB rate limit hit", "available": False}
        resp.raise_for_status()
        d = resp.json().get("data", {})

        return {
            "available": True,
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt"),
            "country": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "usage_type": d.get("usageType", ""),
            "is_tor": d.get("isTor", False),
            "is_public": d.get("isPublic", True),
            "distinct_users": d.get("numDistinctUsers", 0),
        }

    except httpx.TimeoutException:
        return {"error": "AbuseIPDB timeout", "available": False}
    except Exception as e:
        return {"error": str(e), "available": False}


# ─── Shodan ───────────────────────────────────────────────────────────────────
async def fetch_shodan(ip: str, client: httpx.AsyncClient) -> dict:
    if not SHODAN_KEY:
        return {"error": "No Shodan API key configured", "available": False}

    try:
        resp = await client.get(
            f"{SHODAN_BASE}/shodan/host/{ip}",
            params={"key": SHODAN_KEY},
            timeout=15,
        )
        if resp.status_code == 404:
            return {"available": True, "open_ports": [], "vulns": [], "os": None,
                    "org": "", "hostnames": [], "country": "", "tags": []}
        if resp.status_code == 429:
            return {"error": "Shodan rate limit hit", "available": False}
        resp.raise_for_status()
        d = resp.json()

        open_ports = sorted(set(d.get("ports", [])))
        vulns_raw  = d.get("vulns", {})

        # Build structured vuln list with CVSS if available
        vulns = []
        for cve_id, vuln_data in (vulns_raw.items() if isinstance(vulns_raw, dict) else {}.items()):
            vulns.append({
                "cve": cve_id,
                "cvss": vuln_data.get("cvss", 0.0) if isinstance(vuln_data, dict) else 0.0,
                "summary": (vuln_data.get("summary", "")[:120] if isinstance(vuln_data, dict) else ""),
            })
        vulns.sort(key=lambda x: x["cvss"], reverse=True)

        tags = d.get("tags", [])

        return {
            "available": True,
            "open_ports": open_ports[:20],
            "vulns": vulns[:10],
            "os": d.get("os"),
            "org": d.get("org", ""),
            "hostnames": d.get("hostnames", [])[:5],
            "country": d.get("country_code", ""),
            "last_update": d.get("last_update"),
            "tags": tags,
            "banners": [
                {"port": s.get("port"), "transport": s.get("transport", "tcp"),
                 "product": s.get("product", ""), "version": s.get("version", "")}
                for s in d.get("data", [])[:5]
                if s.get("product")
            ],
        }

    except httpx.TimeoutException:
        return {"error": "Shodan timeout", "available": False}
    except Exception as e:
        return {"error": str(e), "available": False}


# ─── Risk Scoring Engine ──────────────────────────────────────────────────────
def compute_risk_score(vt: dict, abuse: dict, shodan: dict, ioc_type: str) -> dict:
    # VirusTotal component
    vt_score = 0.0
    if vt.get("available"):
        vt_score = min(100.0, vt.get("ratio", 0) * 100)
        if vt.get("has_poc"):
            vt_score = min(100.0, vt_score * 1.25)
        if vt.get("reputation", 0) < -20:
            vt_score = min(100.0, vt_score + 10)

    # AbuseIPDB component
    abuse_score = 0.0
    if abuse.get("available") and ioc_type == "ipv4":
        abuse_score = float(abuse.get("abuse_score", 0))
        if abuse.get("is_tor"):
            abuse_score = min(100.0, abuse_score + 15)
        if abuse.get("distinct_users", 0) > 10:
            abuse_score = min(100.0, abuse_score + 5)

    # Shodan component
    shodan_score = 0.0
    if shodan.get("available") and ioc_type == "ipv4":
        vuln_score = sum(
            min(v.get("cvss", 5.0), 10.0) * 5
            for v in shodan.get("vulns", [])
        )
        port_score = len(shodan.get("open_ports", [])) * 2
        shodan_score = min(100.0, vuln_score + port_score)
        critical_ports = {21, 23, 445, 3389, 5900, 27017, 6379}
        if set(shodan.get("open_ports", [])) & critical_ports:
            shodan_score = min(100.0, shodan_score + 15)

    # If only VT available (for non-IP types), weight it fully
    if not abuse.get("available") and not shodan.get("available"):
        raw = vt_score
    else:
        raw = (
            vt_score    * SOURCE_WEIGHTS["virustotal"] +
            abuse_score * SOURCE_WEIGHTS["abuseipdb"] +
            shodan_score * SOURCE_WEIGHTS["shodan"]
        )

    # Time decay — use most recent signal date
    dates = [
        vt.get("last_analysis_date"),
        abuse.get("last_reported"),
        shodan.get("last_update"),
    ]
    days_ago = min((days_since(d) for d in dates if d), default=0)
    decay    = time_decay(days_ago)
    decayed  = round(raw * decay, 1)
    raw      = round(raw, 1)

    severity = (
        "critical" if decayed >= 75 else
        "high"     if decayed >= 50 else
        "medium"   if decayed >= 25 else
        "low"
    )

    return {
        "raw": raw,
        "decayed": decayed,
        "decay_factor": round(decay, 4),
        "days_ago": days_ago,
        "severity": severity,
        "components": {
            "virustotal": round(vt_score, 1),
            "abuseipdb":  round(abuse_score, 1),
            "shodan":     round(shodan_score, 1),
        },
    }


# ─── Behavioral Tag Extraction ────────────────────────────────────────────────
def extract_tags(vt: dict, abuse: dict, shodan: dict) -> list[str]:
    tags = set()
    tags.update(vt.get("tags", []))
    tags.update(t.lower().replace(" ", "-") for t in vt.get("categories", []))

    if shodan.get("available"):
        tags.update(shodan.get("tags", []))
        ports = set(shodan.get("open_ports", []))
        if ports & {22}:       tags.add("ssh")
        if ports & {23}:       tags.add("telnet")
        if ports & {3389}:     tags.add("rdp")
        if ports & {445}:      tags.add("smb")
        if ports & {6379}:     tags.add("redis-exposed")
        if ports & {27017}:    tags.add("mongodb-exposed")
        if ports & {5900}:     tags.add("vnc-exposed")
        if ports & {21}:       tags.add("ftp")
        if shodan.get("vulns"):tags.add("cve-present")

    if abuse.get("available"):
        if abuse.get("is_tor"):       tags.add("tor-exit")
        if abuse.get("abuse_score", 0) > 80: tags.add("high-abuse")
        if abuse.get("total_reports", 0) > 100: tags.add("mass-reported")

    return sorted(tags)[:12]


# ─── Jaccard Clustering ───────────────────────────────────────────────────────
def jaccard(a: list, b: list) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    union = sa | sb
    return len(sa & sb) / len(union) if union else 0.0


def cluster_iocs(enriched: list[dict]) -> list[dict]:
    n = len(enriched)
    assigned = [-1] * n
    clusters = []

    for i in range(n):
        if assigned[i] != -1:
            continue
        cid = len(clusters)
        assigned[i] = cid
        members = [i]
        centroid_tags = list(enriched[i]["tags"])

        for j in range(i + 1, n):
            if assigned[j] != -1:
                continue
            sim = jaccard(enriched[i]["tags"], enriched[j]["tags"])
            if sim >= CLUSTER_THRESHOLD:
                assigned[j] = cid
                members.append(j)
                for t in enriched[j]["tags"]:
                    if t not in centroid_tags:
                        centroid_tags.append(t)

        clusters.append({
            "id": cid,
            "members": members,
            "centroid_tags": centroid_tags,
            "size": len(members),
            "is_singleton": len(members) == 1,
        })

    return clusters


# ─── Core Enrichment ──────────────────────────────────────────────────────────
async def _not_applicable() -> dict:
    """Placeholder for sources that don't apply to a given IOC type."""
    return {"available": False, "skipped": True}


async def enrich_ioc(ioc: str) -> dict:
    ioc_type = detect_type(ioc)

    async with httpx.AsyncClient() as client:
        tasks = [fetch_virustotal(ioc, ioc_type, client)]

        if ioc_type == "ipv4":
            tasks.append(fetch_abuseipdb(ioc, client))
            tasks.append(fetch_shodan(ioc, client))
        else:
            tasks.append(_not_applicable())
            tasks.append(_not_applicable())

        results = await asyncio.gather(*tasks, return_exceptions=True)

    vt     = results[0] if not isinstance(results[0], Exception) else {"available": False, "error": str(results[0])}
    abuse  = results[1] if not isinstance(results[1], Exception) else {"available": False, "error": str(results[1])}
    shodan = results[2] if not isinstance(results[2], Exception) else {"available": False, "error": str(results[2])}

    tags  = extract_tags(vt, abuse, shodan)
    score = compute_risk_score(vt, abuse, shodan, ioc_type)

    return {
        "ioc": ioc,
        "type": ioc_type,
        "tags": tags,
        "score": score,
        "sources": {
            "virustotal": vt,
            "abuseipdb":  abuse,
            "shodan":     shodan,
        },
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service": "ThreatLens API",
        "version": "1.0.0",
        "keys_configured": {
            "virustotal": bool(VT_KEY),
            "abuseipdb":  bool(ABUSE_KEY),
            "shodan":     bool(SHODAN_KEY),
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/enrich")
async def enrich_single(req: IOCRequest):
    """Enrich a list of IOCs. Returns per-IOC results + cluster analysis."""
    if not req.iocs:
        raise HTTPException(400, "No IOCs provided")

    # Enrich all IOCs concurrently (rate-limit friendly: max 5 at a time)
    semaphore = asyncio.Semaphore(5)

    async def bounded_enrich(ioc):
        async with semaphore:
            return await enrich_ioc(ioc)

    results = await asyncio.gather(
        *[bounded_enrich(ioc) for ioc in req.iocs],
        return_exceptions=True
    )

    enriched = []
    errors   = []
    for ioc, res in zip(req.iocs, results):
        if isinstance(res, Exception):
            errors.append({"ioc": ioc, "error": str(res)})
        else:
            enriched.append(res)

    clusters = cluster_iocs(enriched)

    # Summary stats
    severity_counts = defaultdict(int)
    for r in enriched:
        severity_counts[r["score"]["severity"]] += 1

    avg_score = (
        round(sum(r["score"]["decayed"] for r in enriched) / len(enriched), 1)
        if enriched else 0
    )

    return {
        "results": enriched,
        "clusters": clusters,
        "summary": {
            "total": len(enriched),
            "errors": len(errors),
            "avg_decayed_score": avg_score,
            "severity_counts": dict(severity_counts),
            "cluster_count": len([c for c in clusters if not c["is_singleton"]]),
        },
        "errors": errors,
    }


@app.post("/score")
async def score_only(req: IOCRequest):
    """Fast path — returns only risk scores, no full enrichment data."""
    results = await asyncio.gather(
        *[enrich_ioc(ioc) for ioc in req.iocs],
        return_exceptions=True
    )
    return [
        {"ioc": ioc, "score": r["score"], "type": r["type"], "tags": r["tags"]}
        if not isinstance(r, Exception)
        else {"ioc": ioc, "error": str(r)}
        for ioc, r in zip(req.iocs, results)
    ]


@app.get("/enrich/{ioc:path}")
async def enrich_get(ioc: str):
    """Enrich a single IOC via GET — useful for quick lookups."""
    return await enrich_ioc(ioc)
