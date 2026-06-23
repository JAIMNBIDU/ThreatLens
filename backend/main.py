"""
ThreatLens — FastAPI backend

Aggregates VirusTotal, AbuseIPDB, and Shodan.
Risk scoring with time decay and dynamic weight redistribution.
Cache-first against SQLite — repeat lookups cost zero API quota.
"""
import asyncio
import base64
import logging
import math
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

import config
import storage
from security import clean_iocs, detect_type, rate_limit

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("threatlens")

_client: Optional[httpx.AsyncClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _client
    await storage.init_db()
    _client = httpx.AsyncClient(
        timeout=config.HTTP_TIMEOUT,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        headers={"User-Agent": "ThreatLens/2.0"},
    )
    log.info("ThreatLens started. VT=%s AbuseIPDB=%s Shodan=%s",
             bool(config.VT_KEY), bool(config.ABUSE_KEY), bool(config.SHODAN_KEY))
    yield
    await _client.aclose()


app = FastAPI(
    title="ThreatLens API",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs" if config.ENABLE_DOCS else None,
    redoc_url="/redoc" if config.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if config.ENABLE_DOCS else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ─── Models ───────────────────────────────────────────────────────────────────
class IOCRequest(BaseModel):
    iocs: list[str]

    @field_validator("iocs")
    @classmethod
    def cap(cls, v):
        if len(v) > config.MAX_IOCS:
            raise ValueError(f"Max {config.MAX_IOCS} IOCs per request")
        return v


# ─── Time decay ───────────────────────────────────────────────────────────────
def time_decay(days_ago: int) -> float:
    return math.exp(-math.log(2) * days_ago / config.HALF_LIFE_DAYS)


def days_since(dt_str: Optional[str]) -> int:
    if not dt_str:
        return 0
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return 0


# ─── VirusTotal ───────────────────────────────────────────────────────────────
async def fetch_virustotal(ioc: str, ioc_type: str, client: httpx.AsyncClient) -> dict:
    if not config.VT_KEY:
        return {"available": False, "error": "not configured"}
    headers = {"x-apikey": config.VT_KEY}
    try:
        if ioc_type == "url":
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            url = f"{config.VT_BASE}/urls/{url_id}"
        else:
            url = {
                "ipv4":   f"{config.VT_BASE}/ip_addresses/{ioc}",
                "domain": f"{config.VT_BASE}/domains/{ioc}",
                "hash":   f"{config.VT_BASE}/files/{ioc}",
            }[ioc_type]

        resp = await client.get(url, headers=headers)
        if resp.status_code == 404:
            return {"available": True, "detections": 0, "total": 0, "ratio": 0.0,
                    "categories": [], "tags": [], "last_analysis_date": None,
                    "has_poc": False, "reputation": 0, "cves": []}
        if resp.status_code == 429:
            return {"available": False, "error": "rate limited"}
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        stats     = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total     = sum(stats.values()) or 1
        tags      = data.get("tags", [])
        categories = list(data.get("categories", {}).values())[:5]

        crowdsourced_ids = data.get("crowdsourced_ids_results", [])
        cves = list({
            rule.get("rule_id") for entry in crowdsourced_ids
            for rule in entry.get("rule_details", [])
            if rule.get("rule_id", "").startswith("CVE-")
        })
        has_poc = bool(data.get("crowdsourced_context")) or "exploit" in " ".join(tags).lower()

        last = data.get("last_analysis_date")
        if last:
            last = datetime.fromtimestamp(last, tz=timezone.utc).isoformat()

        return {
            "available": True,
            "detections": malicious + suspicious,
            "total": total,
            "ratio": round((malicious + suspicious) / total, 4),
            "categories": categories,
            "tags": tags[:8],
            "last_analysis_date": last,
            "has_poc": has_poc,
            "reputation": data.get("reputation", 0),
            "cves": cves[:5],
        }
    except httpx.TimeoutException:
        return {"available": False, "error": "timeout"}
    except Exception as e:
        log.warning("VT error for %s: %s", ioc, e)
        return {"available": False, "error": "lookup failed"}


# ─── AbuseIPDB ────────────────────────────────────────────────────────────────
async def fetch_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict:
    if not config.ABUSE_KEY:
        return {"available": False, "error": "not configured"}
    try:
        resp = await client.get(
            f"{config.ABUSE_BASE}/check",
            headers={"Key": config.ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        )
        if resp.status_code == 429:
            return {"available": False, "error": "rate limited"}
        resp.raise_for_status()
        d = resp.json().get("data", {})
        return {
            "available": True,
            "abuse_score":    d.get("abuseConfidenceScore", 0),
            "total_reports":  d.get("totalReports", 0),
            "last_reported":  d.get("lastReportedAt"),
            "country":        d.get("countryCode", ""),
            "isp":            d.get("isp", ""),
            "domain":         d.get("domain", ""),
            "usage_type":     d.get("usageType", ""),
            "is_tor":         d.get("isTor", False),
            "is_public":      d.get("isPublic", True),
            "distinct_users": d.get("numDistinctUsers", 0),
        }
    except httpx.TimeoutException:
        return {"available": False, "error": "timeout"}
    except Exception as e:
        log.warning("AbuseIPDB error for %s: %s", ip, e)
        return {"available": False, "error": "lookup failed"}


# ─── Shodan ───────────────────────────────────────────────────────────────────
async def fetch_shodan(ip: str, client: httpx.AsyncClient) -> dict:
    if not config.SHODAN_KEY:
        return {"available": False, "error": "not configured"}
    try:
        resp = await client.get(
            f"{config.SHODAN_BASE}/shodan/host/{ip}",
            params={"key": config.SHODAN_KEY},
        )
        if resp.status_code == 404:
            return {"available": True, "open_ports": [], "vulns": [], "os": None,
                    "org": "", "hostnames": [], "country": "", "tags": [], "banners": []}
        if resp.status_code in (401, 403):
            return {"available": False, "error": "invalid key or plan restriction"}
        if resp.status_code == 429:
            return {"available": False, "error": "rate limited"}
        resp.raise_for_status()
        d = resp.json()
        open_ports = sorted(set(d.get("ports", [])))
        vulns_raw  = d.get("vulns", {})
        vulns = []
        if isinstance(vulns_raw, dict):
            for cve_id, vd in vulns_raw.items():
                vulns.append({
                    "cve":     cve_id,
                    "cvss":    vd.get("cvss", 0.0) if isinstance(vd, dict) else 0.0,
                    "summary": (vd.get("summary", "")[:120] if isinstance(vd, dict) else ""),
                })
        vulns.sort(key=lambda x: x["cvss"], reverse=True)
        return {
            "available":  True,
            "open_ports": open_ports[:20],
            "vulns":      vulns[:10],
            "os":         d.get("os"),
            "org":        d.get("org", ""),
            "hostnames":  d.get("hostnames", [])[:5],
            "country":    d.get("country_code", ""),
            "last_update": d.get("last_update"),
            "tags":       d.get("tags", []),
            "banners": [
                {"port": s.get("port"), "transport": s.get("transport", "tcp"),
                 "product": s.get("product", ""), "version": s.get("version", "")}
                for s in d.get("data", [])[:5] if s.get("product")
            ],
        }
    except httpx.TimeoutException:
        return {"available": False, "error": "timeout"}
    except Exception as e:
        log.warning("Shodan error for %s: %s", ip, e)
        return {"available": False, "error": "lookup failed"}


# ─── Scoring ──────────────────────────────────────────────────────────────────
def compute_risk_score(vt: dict, abuse: dict, shodan: dict, ioc_type: str) -> dict:
    """
    Dynamic weight redistribution: if a source is unavailable its weight is
    spread proportionally across the sources that did return data. This means
    a two-source result isn't artificially capped at 80% of what a three-source
    result would give — the available signals carry their full relative weight.
    """
    vt_score = 0.0
    if vt.get("available"):
        vt_score = min(100.0, vt.get("ratio", 0) * 100)
        if vt.get("has_poc"):
            vt_score = min(100.0, vt_score * 1.25)
        if vt.get("reputation", 0) < -20:
            vt_score = min(100.0, vt_score + 10)

    abuse_score = 0.0
    if abuse.get("available") and ioc_type == "ipv4":
        abuse_score = float(abuse.get("abuse_score", 0))
        if abuse.get("is_tor"):
            abuse_score = min(100.0, abuse_score + 15)
        if abuse.get("distinct_users", 0) > 10:
            abuse_score = min(100.0, abuse_score + 5)

    shodan_score = 0.0
    if shodan.get("available") and ioc_type == "ipv4":
        vuln_score  = sum(min(v.get("cvss", 5.0), 10.0) * 5 for v in shodan.get("vulns", []))
        port_score  = len(shodan.get("open_ports", [])) * 2
        shodan_score = min(100.0, vuln_score + port_score)
        if set(shodan.get("open_ports", [])) & {21, 23, 445, 3389, 5900, 27017, 6379}:
            shodan_score = min(100.0, shodan_score + 15)

    # Build the active-source map and redistribute weights dynamically
    w = config.SOURCE_WEIGHTS.copy()
    active = {
        "virustotal": vt_score    if vt.get("available") else None,
        "abuseipdb":  abuse_score if (abuse.get("available") and ioc_type == "ipv4") else None,
        "shodan":     shodan_score if (shodan.get("available") and ioc_type == "ipv4") else None,
    }
    available_sources = {k: v for k, v in active.items() if v is not None}
    if not available_sources:
        raw = 0.0
    else:
        total_w = sum(w[k] for k in available_sources)
        raw = sum(score * (w[src] / total_w) for src, score in available_sources.items())

    dates = [
        vt.get("last_analysis_date"),
        abuse.get("last_reported"),
        shodan.get("last_update"),
    ]
    days_ago = min((days_since(d) for d in dates if d), default=0)
    decay    = time_decay(days_ago)
    decayed  = round(raw * decay, 1)

    severity = ("critical" if decayed >= 75 else "high" if decayed >= 50
                else "medium" if decayed >= 25 else "low")

    return {
        "raw":          round(raw, 1),
        "decayed":      decayed,
        "decay_factor": round(decay, 4),
        "days_ago":     days_ago,
        "severity":     severity,
        "components": {
            "virustotal": round(vt_score, 1),
            "abuseipdb":  round(abuse_score, 1),
            "shodan":     round(shodan_score, 1),
        },
        "active_sources": list(available_sources.keys()),
    }


# ─── Tags ─────────────────────────────────────────────────────────────────────
def extract_tags(vt: dict, abuse: dict, shodan: dict) -> list[str]:
    tags = set()
    tags.update(vt.get("tags", []))
    tags.update(t.lower().replace(" ", "-") for t in vt.get("categories", []))
    if vt.get("has_poc"):
        tags.add("public-poc")
    if vt.get("cves"):
        tags.add("cve-present")

    if shodan.get("available"):
        tags.update(shodan.get("tags", []))
        ports = set(shodan.get("open_ports", []))
        port_tags = {22: "ssh", 23: "telnet", 3389: "rdp", 445: "smb",
                     6379: "redis-exposed", 27017: "mongodb-exposed",
                     5900: "vnc-exposed", 21: "ftp"}
        for p, t in port_tags.items():
            if p in ports:
                tags.add(t)
        if shodan.get("vulns"):
            tags.add("cve-present")

    if abuse.get("available"):
        if abuse.get("is_tor"):
            tags.add("tor-exit")
        if abuse.get("abuse_score", 0) > 80:
            tags.add("high-abuse")
        if abuse.get("total_reports", 0) > 100:
            tags.add("mass-reported")

    return sorted(t for t in tags if t)[:14]


# ─── Clustering ───────────────────────────────────────────────────────────────
def jaccard(a: list, b: list) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    union = sa | sb
    return len(sa & sb) / len(union) if union else 0.0


def cluster_iocs(enriched: list[dict]) -> list[dict]:
    n        = len(enriched)
    assigned = [-1] * n
    clusters = []
    for i in range(n):
        if assigned[i] != -1:
            continue
        cid      = len(clusters)
        assigned[i] = cid
        members  = [i]
        centroid = list(enriched[i]["tags"])
        for j in range(i + 1, n):
            if assigned[j] != -1:
                continue
            if jaccard(enriched[i]["tags"], enriched[j]["tags"]) >= config.CLUSTER_THRESHOLD:
                assigned[j] = cid
                members.append(j)
                for t in enriched[j]["tags"]:
                    if t not in centroid:
                        centroid.append(t)
        clusters.append({
            "id": cid, "members": members, "centroid_tags": centroid,
            "size": len(members), "is_singleton": len(members) == 1,
        })
    return clusters


# ─── Core enrichment ──────────────────────────────────────────────────────────
async def _enrich_live(ioc: str, ioc_type: str) -> dict:
    tasks = [fetch_virustotal(ioc, ioc_type, _client)]
    if ioc_type == "ipv4":
        tasks += [fetch_abuseipdb(ioc, _client), fetch_shodan(ioc, _client)]

    res = await asyncio.gather(*tasks, return_exceptions=True)

    def safe(r):
        return r if isinstance(r, dict) else {"available": False, "error": "lookup failed"}

    vt = safe(res[0])
    if ioc_type == "ipv4":
        abuse  = safe(res[1])
        shodan = safe(res[2])
    else:
        abuse  = {"available": False, "skipped": True}
        shodan = {"available": False, "skipped": True}

    tags  = extract_tags(vt, abuse, shodan)
    score = compute_risk_score(vt, abuse, shodan, ioc_type)

    return {
        "ioc":  ioc,
        "type": ioc_type,
        "tags": tags,
        "score": score,
        "sources": {"virustotal": vt, "abuseipdb": abuse, "shodan": shodan},
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


async def enrich_ioc(ioc: str) -> dict:
    ioc_type = detect_type(ioc)
    cached   = await storage.get_cached(ioc, config.CACHE_TTL_HOURS)
    if cached:
        result, meta = cached
        result["cached"]  = True
        result["history"] = meta
        return result
    result = await _enrich_live(ioc, ioc_type)
    meta   = await storage.save(ioc, ioc_type, result)
    result["cached"]  = False
    result["history"] = meta
    return result


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service": "ThreatLens API",
        "version": "2.0.0",
        "keys_configured": {
            "virustotal": bool(config.VT_KEY),
            "abuseipdb":  bool(config.ABUSE_KEY),
            "shodan":     bool(config.SHODAN_KEY),
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/stats")
async def stats():
    return await storage.stats()


@app.post("/enrich", dependencies=[Depends(rate_limit)])
async def enrich(req: IOCRequest):
    accepted, rejected = clean_iocs(req.iocs)
    if not accepted:
        raise HTTPException(400, "No valid IOCs provided")

    sem = asyncio.Semaphore(config.ENRICH_CONCURRENCY)

    async def bounded(ioc):
        async with sem:
            return await enrich_ioc(ioc)

    results  = await asyncio.gather(*[bounded(i) for i in accepted], return_exceptions=True)
    enriched = []
    errors   = list(rejected)

    for ioc, r in zip(accepted, results):
        if isinstance(r, Exception):
            log.error("enrich failed for %s: %s", ioc, r)
            errors.append({"ioc": ioc, "reason": "enrichment failed"})
        else:
            enriched.append(r)

    clusters   = cluster_iocs(enriched)
    sev_counts = defaultdict(int)
    for r in enriched:
        sev_counts[r["score"]["severity"]] += 1
    avg        = round(sum(r["score"]["decayed"] for r in enriched) / len(enriched), 1) if enriched else 0
    cache_hits = sum(1 for r in enriched if r.get("cached"))

    return {
        "results":  enriched,
        "clusters": clusters,
        "summary": {
            "total":             len(enriched),
            "errors":            len(errors),
            "avg_decayed_score": avg,
            "severity_counts":   dict(sev_counts),
            "cluster_count":     len([c for c in clusters if not c["is_singleton"]]),
            "cache_hits":        cache_hits,
        },
        "errors": errors,
    }


@app.post("/score", dependencies=[Depends(rate_limit)])
async def score_only(req: IOCRequest):
    accepted, rejected = clean_iocs(req.iocs)
    results = await asyncio.gather(*[enrich_ioc(i) for i in accepted], return_exceptions=True)
    out = [
        {"ioc": i, "score": r["score"], "type": r["type"], "tags": r["tags"]}
        if not isinstance(r, Exception) else {"ioc": i, "error": "enrichment failed"}
        for i, r in zip(accepted, results)
    ]
    return out + [{"ioc": x["ioc"], "error": x["reason"]} for x in rejected]


@app.get("/enrich/{ioc:path}", dependencies=[Depends(rate_limit)])
async def enrich_get(ioc: str):
    accepted, _ = clean_iocs([ioc])
    if not accepted:
        raise HTTPException(400, "Invalid IOC format")
    return await enrich_ioc(accepted[0])
