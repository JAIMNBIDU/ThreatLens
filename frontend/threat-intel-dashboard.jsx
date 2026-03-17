import { useState, useCallback, useRef } from "react";

// ─── Config ───────────────────────────────────────────────────────────────────
const API_BASE = "http://localhost:8000";

// ─── Color Helpers ────────────────────────────────────────────────────────────
const SEV_COLORS = {
  critical: { bg: "#1a0505", border: "#dc2626", text: "#f87171", badge: "#7f1d1d" },
  high:     { bg: "#1a0d00", border: "#ea580c", text: "#fb923c", badge: "#7c2d12" },
  medium:   { bg: "#0d1100", border: "#ca8a04", text: "#facc15", badge: "#713f12" },
  low:      { bg: "#001a08", border: "#16a34a", text: "#4ade80", badge: "#14532d" },
};
const TYPE_ICONS   = { ipv4: "⬡", domain: "◈", hash: "◆", url: "⬟" };
const TYPE_COLORS  = { ipv4: "#38bdf8", domain: "#a78bfa", hash: "#34d399", url: "#fb923c" };
const CLUSTER_COLORS = ["#38bdf8","#a78bfa","#34d399","#fb923c","#f472b6","#facc15"];
const HALF_LIFE_DAYS = 30;

// ─── Export ───────────────────────────────────────────────────────────────────
function exportJSON(data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = "threatintel-report.json"; a.click();
}

function exportCSV(results) {
  const headers = [
    "IOC","Type","Severity","Raw Score","Decayed Score","Decay Factor","Days Ago",
    "Tags","VT Detections","VT Ratio","VT Has PoC","Abuse Score","Abuse Reports",
    "Country","ISP","Open Ports","CVEs","CVSS Max"
  ];
  const rows = results.map(r => {
    const s  = r.score;
    const vt = r.sources.virustotal;
    const ab = r.sources.abuseipdb;
    const sh = r.sources.shodan;
    const maxCvss = sh?.vulns?.reduce((m, v) => Math.max(m, v.cvss || 0), 0) ?? "N/A";
    return [
      r.ioc, r.type, s.severity, s.raw, s.decayed, s.decay_factor, s.days_ago,
      r.tags.join("|"),
      vt?.available ? `${vt.detections}/${vt.total}` : "N/A",
      vt?.available ? vt.ratio : "N/A",
      vt?.available ? (vt.has_poc ? "Yes" : "No") : "N/A",
      ab?.available ? ab.abuse_score : "N/A",
      ab?.available ? ab.total_reports : "N/A",
      ab?.available ? ab.country : "N/A",
      ab?.available ? ab.isp : "N/A",
      sh?.available ? sh.open_ports.join("|") : "N/A",
      sh?.available ? sh.vulns.map(v => v.cve).join("|") : "N/A",
      maxCvss,
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(",");
  });
  const csv  = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = "threatintel-report.csv"; a.click();
}

// ─── Sub-components ───────────────────────────────────────────────────────────
function ScoreMeter({ score, size = 56 }) {
  const r    = size / 2 - 7;
  const circ = 2 * Math.PI * r;
  const pct  = Math.min(score.decayed, 100) / 100;
  const c    = SEV_COLORS[score.severity];
  return (
    <div style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1e2a38" strokeWidth={5} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={c.border}
          strokeWidth={5} strokeDasharray={circ}
          strokeDashoffset={circ * (1 - pct)} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.7s ease" }} />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: c.text, fontFamily: "monospace", lineHeight: 1 }}>{Math.round(score.decayed)}</div>
      </div>
    </div>
  );
}

function DecayChart({ daysAgo, raw }) {
  const pts = Array.from({ length: 91 }, (_, i) => ({
    x: i,
    y: raw * Math.exp(-Math.LN2 * i / HALF_LIFE_DAYS),
  }));
  const W = 220, H = 64, P = 4;
  const sx = x => P + (x / 90) * (W - P * 2);
  const sy = y => H - P - (Math.min(y, 100) / 100) * (H - P * 2);
  const path = pts.map((p, i) => `${i === 0 ? "M" : "L"}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(" ");
  const fill = path + ` L${sx(90)},${H} L${sx(0)},${H} Z`;
  const cx   = sx(daysAgo);
  const cy   = sy(pts[Math.min(daysAgo, 90)].y);
  return (
    <div>
      <div style={{ fontSize: 10, color: "#64748b", marginBottom: 4, letterSpacing: "0.06em", textTransform: "uppercase" }}>
        Time Decay — 30d half-life · decayed score = raw × e^(−ln2·t/30)
      </div>
      <svg width={W} height={H + 14} overflow="visible">
        <defs>
          <linearGradient id="dg" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        <path d={fill} fill="url(#dg)" />
        <path d={path} fill="none" stroke="#3b82f6" strokeWidth="1.5" />
        <line x1={cx} y1={P} x2={cx} y2={H} stroke="#f59e0b" strokeWidth="1" strokeDasharray="3,2" />
        <circle cx={cx} cy={cy} r={3.5} fill="#f59e0b" />
        <text x={cx + 6} y={cy - 4} fill="#f59e0b" fontSize={9} fontFamily="monospace">day {daysAgo}</text>
        {[0, 30, 60, 90].map(d => (
          <text key={d} x={sx(d) - (d === 90 ? 8 : d > 0 ? 6 : 0)} y={H + 12}
            fill="#475569" fontSize={8} fontFamily="monospace">{d}d</text>
        ))}
      </svg>
    </div>
  );
}

function TagPill({ tag }) {
  const map = { scanner:"#1e3a5f","brute-force":"#3b1f5e",c2:"#5e1f1f",botnet:"#5e3b1f",
    phishing:"#1f5e4a",malware:"#4a1f5e",ransomware:"#5e1f2e",backdoor:"#2e1f5e",
    rdp:"#1e3040",ssh:"#1a2e40",smb:"#2e1e40","tor-exit":"#3d1e3d","cve-present":"#4a1f1f" };
  return (
    <span style={{ background: map[tag] || "#1e2a38", color: "#94a3b8",
      fontSize: 10, padding: "2px 7px", borderRadius: 4, fontFamily: "monospace", letterSpacing: "0.03em" }}>
      {tag}
    </span>
  );
}

function SeverityBadge({ severity }) {
  const c = SEV_COLORS[severity];
  return (
    <span style={{ background: c.badge, color: c.text, fontSize: 10, padding: "2px 8px",
      borderRadius: 4, fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase" }}>
      {severity}
    </span>
  );
}

function SourceCard({ title, data, color }) {
  if (!data?.available) return (
    <div style={{ background: "#0d1117", borderRadius: 6, padding: "10px 12px", border: "1px solid #1e2a38", opacity: 0.5 }}>
      <div style={{ fontSize: 10, color: "#475569", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>{title}</div>
      <div style={{ fontSize: 11, color: "#334155" }}>{data?.skipped ? "N/A for this type" : data?.error || "Unavailable"}</div>
    </div>
  );
  return (
    <div style={{ background: "#0d1117", borderRadius: 6, padding: "10px 12px", border: "1px solid #1e2a38" }}>
      <div style={{ fontSize: 10, color: "#64748b", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em" }}>{title}</div>
      {title === "VirusTotal" && (
        <>
          <div style={{ fontSize: 20, fontWeight: 700, fontFamily: "monospace",
            color: data.detections > 30 ? "#f87171" : data.detections > 10 ? "#fb923c" : "#4ade80" }}>
            {data.detections}<span style={{ fontSize: 12, color: "#475569" }}>/{data.total}</span>
          </div>
          <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>detections · ratio {data.ratio}</div>
          {data.has_poc && (
            <div style={{ fontSize: 9, color: "#f87171", background: "#1a0505", padding: "2px 6px",
              borderRadius: 3, display: "inline-block", marginTop: 5, fontFamily: "monospace" }}>
              PUBLIC PoC EXISTS
            </div>
          )}
          {data.cves?.length > 0 && (
            <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 3 }}>
              {data.cves.map(c => (
                <span key={c} style={{ fontSize: 9, color: "#f87171", background: "#1a0505",
                  padding: "1px 5px", borderRadius: 3, fontFamily: "monospace" }}>{c}</span>
              ))}
            </div>
          )}
        </>
      )}
      {title === "AbuseIPDB" && (
        <>
          <div style={{ fontSize: 20, fontWeight: 700, fontFamily: "monospace",
            color: data.abuse_score > 75 ? "#f87171" : data.abuse_score > 40 ? "#fb923c" : "#4ade80" }}>
            {data.abuse_score}%
          </div>
          <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>
            {data.total_reports} reports · {data.country} · {data.distinct_users} users
          </div>
          <div style={{ fontSize: 10, color: "#475569", marginTop: 2 }}>{data.isp}</div>
          <div style={{ fontSize: 10, color: "#475569" }}>{data.usage_type}</div>
          {data.is_tor && <div style={{ fontSize: 9, color: "#a78bfa", marginTop: 4 }}>TOR EXIT NODE</div>}
        </>
      )}
      {title === "Shodan" && (
        <>
          <div style={{ fontSize: 11, color: "#94a3b8", fontFamily: "monospace", marginBottom: 4 }}>
            {data.open_ports?.length > 0 ? data.open_ports.join(", ") : "No open ports"}
          </div>
          {data.os && <div style={{ fontSize: 10, color: "#475569", marginBottom: 4 }}>{data.os} · {data.org}</div>}
          {data.vulns?.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 3, marginTop: 4 }}>
              {data.vulns.slice(0, 4).map(v => (
                <div key={v.cve} style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
                  <span style={{ fontSize: 9, color: "#f87171", background: "#1a0505",
                    padding: "1px 5px", borderRadius: 3, fontFamily: "monospace", whiteSpace: "nowrap" }}>
                    {v.cve}
                  </span>
                  <span style={{ fontSize: 9, color: "#dc2626", fontWeight: 700 }}>
                    {v.cvss ? `CVSS ${v.cvss}` : ""}
                  </span>
                  <span style={{ fontSize: 9, color: "#475569", lineHeight: 1.4 }}>
                    {v.summary?.slice(0, 60)}{v.summary?.length > 60 ? "…" : ""}
                  </span>
                </div>
              ))}
            </div>
          )}
          {data.banners?.length > 0 && (
            <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 3 }}>
              {data.banners.map((b, i) => (
                <span key={i} style={{ fontSize: 9, color: "#64748b", background: "#1e2a38",
                  padding: "1px 5px", borderRadius: 3, fontFamily: "monospace" }}>
                  {b.port}/{b.transport} {b.product} {b.version}
                </span>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function IOCCard({ result, isExpanded, onClick, clusterColor }) {
  const score = result.score;
  const c     = SEV_COLORS[score.severity];
  return (
    <div onClick={onClick} style={{
      background: c.bg, border: `1px solid ${isExpanded ? c.border : "#1e2a38"}`,
      borderLeft: `3px solid ${c.border}`, borderRadius: 8, padding: "14px 16px",
      cursor: "pointer", transition: "border-color 0.2s",
      boxShadow: isExpanded ? `0 0 24px ${c.border}18` : "none",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
        <span style={{ color: TYPE_COLORS[result.type], fontSize: 16, flexShrink: 0 }}>{TYPE_ICONS[result.type]}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: "monospace", fontSize: 12, color: "#e2e8f0", wordBreak: "break-all", fontWeight: 600 }}>
            {result.ioc}
          </div>
          <div style={{ fontSize: 10, color: "#64748b", marginTop: 2, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ color: TYPE_COLORS[result.type], textTransform: "uppercase", letterSpacing: "0.08em" }}>{result.type}</span>
            <span>·</span>
            <span>{score.days_ago}d ago</span>
            <span>·</span>
            <span style={{ color: "#475569" }}>decay ×{score.decay_factor}</span>
            {clusterColor && (
              <span style={{ background: clusterColor + "22", color: clusterColor,
                padding: "1px 6px", borderRadius: 3, fontSize: 9, letterSpacing: "0.04em" }}>
                clustered
              </span>
            )}
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6 }}>
          <SeverityBadge severity={score.severity} />
          <ScoreMeter score={score} size={56} />
        </div>
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
        {result.tags.map(t => <TagPill key={t} tag={t} />)}
      </div>

      {isExpanded && (
        <div style={{ borderTop: "1px solid #1e2a38", paddingTop: 14, marginTop: 12 }}>
          {/* Score breakdown */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginBottom: 14 }}>
            {[
              { label: "Raw Score",     value: score.raw },
              { label: "Decayed Score", value: score.decayed },
              { label: "Decay Factor",  value: score.decay_factor },
            ].map(m => (
              <div key={m.label} style={{ background: "#0d1117", borderRadius: 5, padding: "8px 10px", border: "1px solid #1e2a38" }}>
                <div style={{ fontSize: 9, color: "#475569", textTransform: "uppercase", letterSpacing: "0.06em" }}>{m.label}</div>
                <div style={{ fontSize: 18, fontWeight: 700, fontFamily: "monospace", color: "#94a3b8", marginTop: 2 }}>{m.value}</div>
              </div>
            ))}
          </div>

          {/* Component breakdown */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 10, color: "#475569", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em" }}>Score Components</div>
            <div style={{ display: "flex", gap: 6 }}>
              {Object.entries(score.components).map(([src, val]) => (
                <div key={src} style={{ flex: 1, background: "#0d1117", borderRadius: 5, padding: "6px 8px", border: "1px solid #1e2a38" }}>
                  <div style={{ fontSize: 9, color: "#475569", letterSpacing: "0.05em" }}>{src}</div>
                  <div style={{ fontSize: 14, fontWeight: 700, fontFamily: "monospace", color: val > 50 ? "#f87171" : val > 25 ? "#fb923c" : "#4ade80" }}>{val}</div>
                  <div style={{ fontSize: 9, color: "#334155" }}>×{(Object.values({ virustotal: 0.45, abuseipdb: 0.35, shodan: 0.20 })[Object.keys(score.components).indexOf(src)])}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Source details */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10, marginBottom: 14 }}>
            <SourceCard title="VirusTotal" data={result.sources.virustotal} />
            <SourceCard title="AbuseIPDB"  data={result.sources.abuseipdb} />
            <SourceCard title="Shodan"     data={result.sources.shodan} />
          </div>

          {/* Decay chart */}
          <DecayChart daysAgo={score.days_ago} raw={score.raw} />
        </div>
      )}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function ThreatLensDashboard() {
  const [input,      setInput]      = useState("");
  const [response,   setResponse]   = useState(null);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState("");
  const [expandedIdx,setExpandedIdx]= useState(null);
  const [activeTab,  setActiveTab]  = useState("results");
  const [filterSev,  setFilterSev]  = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [sortBy,     setSortBy]     = useState("score");
  const [apiStatus,  setApiStatus]  = useState(null);
  const abortRef = useRef(false);

  async function checkHealth() {
    try {
      const r = await fetch(`${API_BASE}/`);
      const d = await r.json();
      setApiStatus(d.keys_configured);
    } catch {
      setApiStatus(null);
    }
  }

  async function runAnalysis() {
    const iocs = input.split("\n").map(l => l.trim()).filter(Boolean);
    if (!iocs.length) return;
    setLoading(true);
    setError("");
    setResponse(null);
    setExpandedIdx(null);
    abortRef.current = false;

    try {
      const res = await fetch(`${API_BASE}/enrich`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iocs }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setResponse(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  const getClusterColor = useCallback((idx) => {
    if (!response?.clusters) return null;
    const cluster = response.clusters.find(c => c.members.includes(idx) && c.size > 1);
    return cluster ? CLUSTER_COLORS[cluster.id % CLUSTER_COLORS.length] : null;
  }, [response]);

  const results   = response?.results || [];
  const clusters  = response?.clusters || [];
  const summary   = response?.summary;

  const filtered = results
    .map((r, i) => ({ ...r, idx: i }))
    .filter(r => filterSev  === "all" || r.score.severity === filterSev)
    .filter(r => filterType === "all" || r.type === filterType)
    .sort((a, b) => sortBy === "score"
      ? b.score.decayed - a.score.decayed
      : a.score.days_ago - b.score.days_ago);

  const DEMO = `185.220.101.45\nevildomain.xyz\nhttps://phish.example.com/login\n44d88612fea8a8f36de82e1278abb02f\n194.165.16.11\nmalware-c2.ru`;

  return (
    <div style={{ background: "#060b12", minHeight: "100vh", color: "#c9d1d9", fontFamily: "'DM Sans','Segoe UI',sans-serif", paddingBottom: 60 }}>

      {/* Header */}
      <div style={{ background: "#0a0f1a", borderBottom: "1px solid #1e2a38", padding: "14px 24px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 32, height: 32, background: "linear-gradient(135deg,#1d4ed8,#7c3aed)", borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>⬡</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.02em" }}>ThreatLens</div>
            <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.08em", textTransform: "uppercase" }}>Threat Intel Aggregator · Risk Engine</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button onClick={checkHealth} style={{ background: "#0d1117", border: "1px solid #1e2a38", color: "#64748b", fontSize: 11, padding: "5px 10px", borderRadius: 5, cursor: "pointer" }}>
            {apiStatus
              ? `Backend ✓ VT:${apiStatus.virustotal?"✓":"✗"} AB:${apiStatus.abuseipdb?"✓":"✗"} SH:${apiStatus.shodan?"✓":"✗"}`
              : "Check Backend"}
          </button>
          {results.length > 0 && <>
            <button onClick={() => exportJSON(response)} style={{ background: "#0d1117", border: "1px solid #1e2a38", color: "#94a3b8", fontSize: 11, padding: "5px 10px", borderRadius: 5, cursor: "pointer" }}>↓ JSON</button>
            <button onClick={() => exportCSV(results)}   style={{ background: "#0d1117", border: "1px solid #1e2a38", color: "#94a3b8", fontSize: 11, padding: "5px 10px", borderRadius: 5, cursor: "pointer" }}>↓ CSV</button>
          </>}
        </div>
      </div>

      <div style={{ maxWidth: 960, margin: "0 auto", padding: "24px 16px" }}>

        {/* Input panel */}
        <div style={{ background: "#0a0f1a", border: "1px solid #1e2a38", borderRadius: 10, padding: 20, marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: "#475569", marginBottom: 8, letterSpacing: "0.06em", textTransform: "uppercase" }}>
            IOC Input — one per line · IPv4 · Domain · MD5/SHA256 · URL
          </div>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder={DEMO}
            rows={6}
            style={{ width: "100%", background: "#060b12", border: "1px solid #1e2a38", color: "#94a3b8",
              fontSize: 12, padding: "12px 14px", borderRadius: 7, fontFamily: "monospace",
              resize: "vertical", outline: "none", lineHeight: 1.7 }}
          />
          <div style={{ display: "flex", gap: 10, marginTop: 12, alignItems: "center" }}>
            <button onClick={runAnalysis} disabled={loading || !input.trim()} style={{
              background: loading ? "#1e2a38" : "linear-gradient(135deg,#1d4ed8,#7c3aed)",
              border: "none", color: "#fff", fontSize: 13, fontWeight: 600, padding: "10px 24px",
              borderRadius: 7, cursor: loading ? "default" : "pointer", letterSpacing: "0.02em",
            }}>
              {loading ? "Analyzing…" : "Analyze IOCs"}
            </button>
            <button onClick={() => setInput(DEMO)} style={{ background: "#0d1117", border: "1px solid #1e2a38", color: "#64748b", fontSize: 11, padding: "9px 14px", borderRadius: 6, cursor: "pointer" }}>
              Load Demo
            </button>
            {input && <button onClick={() => { setInput(""); setResponse(null); setError(""); }} style={{ background: "none", border: "none", color: "#334155", fontSize: 11, cursor: "pointer" }}>Clear</button>}
          </div>
        </div>

        {/* Error */}
        {error && (
          <div style={{ background: "#1a0505", border: "1px solid #dc2626", borderRadius: 8, padding: "12px 16px", marginBottom: 16, color: "#f87171", fontSize: 12, fontFamily: "monospace" }}>
            Error: {error}
            {error.includes("fetch") && (
              <div style={{ marginTop: 6, color: "#475569", fontSize: 11 }}>
                Is the backend running? → <code style={{ color: "#64748b" }}>uvicorn main:app --reload</code>
              </div>
            )}
          </div>
        )}

        {/* Summary stats */}
        {summary && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(100px, 1fr))", gap: 10, marginBottom: 20 }}>
            {[
              { label: "Total",     value: summary.total,                              color: "#94a3b8" },
              { label: "Critical",  value: summary.severity_counts?.critical || 0,    color: "#f87171" },
              { label: "High",      value: summary.severity_counts?.high     || 0,    color: "#fb923c" },
              { label: "Medium",    value: summary.severity_counts?.medium   || 0,    color: "#facc15" },
              { label: "Low",       value: summary.severity_counts?.low      || 0,    color: "#4ade80" },
              { label: "Avg Score", value: summary.avg_decayed_score,                 color: "#38bdf8" },
              { label: "Clusters",  value: summary.cluster_count,                     color: "#a78bfa" },
              { label: "Errors",    value: summary.errors,                            color: "#dc2626" },
            ].map(s => (
              <div key={s.label} style={{ background: "#0a0f1a", border: "1px solid #1e2a38", borderRadius: 8, padding: "12px 14px" }}>
                <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 4 }}>{s.label}</div>
                <div style={{ fontSize: 22, fontWeight: 700, color: s.color, fontFamily: "monospace" }}>{s.value}</div>
              </div>
            ))}
          </div>
        )}

        {/* Tabs */}
        {results.length > 0 && (
          <>
            <div style={{ display: "flex", gap: 4, borderBottom: "1px solid #1e2a38", marginBottom: 16 }}>
              {["results","clusters"].map(tab => (
                <button key={tab} onClick={() => setActiveTab(tab)} style={{
                  background: "none", border: "none", color: activeTab === tab ? "#60a5fa" : "#475569",
                  fontSize: 13, padding: "8px 16px", cursor: "pointer", fontWeight: activeTab === tab ? 600 : 400,
                  borderBottom: `2px solid ${activeTab === tab ? "#60a5fa" : "transparent"}`,
                  textTransform: "capitalize", letterSpacing: "0.02em", marginBottom: -1,
                }}>{tab}</button>
              ))}
            </div>

            {/* Filters */}
            {activeTab === "results" && (
              <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
                {[
                  { val: filterSev,  set: setFilterSev,  opts: ["all","critical","high","medium","low"],         label: "Severity" },
                  { val: filterType, set: setFilterType, opts: ["all","ipv4","domain","hash","url"],             label: "Type" },
                  { val: sortBy,     set: setSortBy,      opts: ["score","age"],                                  label: "Sort" },
                ].map(({ val, set, opts, label }) => (
                  <select key={label} value={val} onChange={e => set(e.target.value)}
                    style={{ background: "#0d1117", border: "1px solid #1e2a38", color: "#94a3b8", fontSize: 11, padding: "6px 10px", borderRadius: 6, outline: "none" }}>
                    {opts.map(o => <option key={o} value={o}>{label === "Sort" ? (o === "score" ? "Sort: Score" : "Sort: Recent") : (o === "all" ? `All ${label}s` : o.charAt(0).toUpperCase() + o.slice(1))}</option>)}
                  </select>
                ))}
                <div style={{ fontSize: 11, color: "#334155", marginLeft: "auto" }}>{filtered.length} of {results.length}</div>
              </div>
            )}

            {/* Results */}
            {activeTab === "results" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {filtered.map(r => (
                  <IOCCard key={r.idx} result={r} isExpanded={expandedIdx === r.idx}
                    onClick={() => setExpandedIdx(expandedIdx === r.idx ? null : r.idx)}
                    clusterColor={getClusterColor(r.idx)} />
                ))}
              </div>
            )}

            {/* Clusters */}
            {activeTab === "clusters" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                {clusters.map(cluster => {
                  const color   = CLUSTER_COLORS[cluster.id % CLUSTER_COLORS.length];
                  const members = cluster.members.map(i => results[i]).filter(Boolean);
                  const avgScore = members.length
                    ? +(members.reduce((a, r) => a + r.score.decayed, 0) / members.length).toFixed(1)
                    : 0;
                  return (
                    <div key={cluster.id} style={{ background: "#0a0f1a", border: `1px solid ${color}44`, borderLeft: `3px solid ${color}`, borderRadius: 8, padding: 16 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <div style={{ width: 10, height: 10, borderRadius: "50%", background: color }} />
                          <span style={{ fontSize: 12, fontWeight: 600, color: "#e2e8f0" }}>Cluster {cluster.id + 1}</span>
                          <span style={{ fontSize: 11, color: "#475569" }}>{cluster.size} IOC{cluster.size !== 1 ? "s" : ""}</span>
                          {cluster.is_singleton && <span style={{ fontSize: 10, color: "#334155", background: "#1e2a38", padding: "1px 6px", borderRadius: 3 }}>singleton</span>}
                        </div>
                        <span style={{ fontSize: 12, fontFamily: "monospace", color }}>avg {avgScore}</span>
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 10 }}>
                        {cluster.centroid_tags.map(t => <TagPill key={t} tag={t} />)}
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        {members.map((r, i) => (
                          <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, background: "#060b12", borderRadius: 5, padding: "7px 10px", fontSize: 11 }}>
                            <span style={{ color: TYPE_COLORS[r.type] }}>{TYPE_ICONS[r.type]}</span>
                            <span style={{ fontFamily: "monospace", color: "#94a3b8", flex: 1, wordBreak: "break-all" }}>{r.ioc}</span>
                            <SeverityBadge severity={r.score.severity} />
                            <span style={{ fontFamily: "monospace", color, fontWeight: 700 }}>{r.score.decayed}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}

        {/* Empty state */}
        {!results.length && !loading && !error && (
          <div style={{ textAlign: "center", padding: "60px 20px", color: "#334155" }}>
            <div style={{ fontSize: 40, marginBottom: 12, opacity: 0.3 }}>⬡</div>
            <div style={{ fontSize: 14, color: "#475569", marginBottom: 6 }}>Paste IOCs above to begin</div>
            <div style={{ fontSize: 11 }}>IPv4 · Domains · MD5/SHA256 hashes · URLs</div>
            <div style={{ fontSize: 11, marginTop: 8, color: "#1d4ed8", cursor: "pointer" }} onClick={checkHealth}>
              Ping backend →
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
