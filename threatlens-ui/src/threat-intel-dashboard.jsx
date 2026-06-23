import { useState, useCallback, useRef, useEffect, useLayoutEffect } from "react";

// ─── Config ───────────────────────────────────────────────────────────────────
// Dev: hits the backend directly. Docker: VITE_API_BASE=/api, nginx proxies to backend (same-origin, no CORS).
const API_BASE = (import.meta.env && import.meta.env.VITE_API_BASE) || "http://localhost:8000";
const MONO    = "'JetBrains Mono', ui-monospace, monospace";
const DISPLAY = "'Space Grotesk', sans-serif";
const HALF_LIFE_DAYS = 30;

// ─── Theme helpers ──────────────────────────────────────────────────────────
const sev  = s => ({
  text:  `var(--sev-${s})`,
  edge:  `var(--sev-${s}-edge)`,
  bg:    `var(--sev-${s}-bg)`,
  badge: `var(--sev-${s}-badge)`,
});
const typeColor = t => `var(--type-${t})`;
const TYPE_ICONS = { ipv4: "⬡", domain: "◈", hash: "◆", url: "⬟" };
// severity-keyed accent for numeric thresholds
const heat = (v, hi, mid) => v > hi ? "var(--sev-critical)" : v > mid ? "var(--sev-high)" : "var(--sev-low)";
const CLUSTER_COLORS = ["#3b82f6", "#8b5cf6", "#10b981", "#f59e0b", "#ec4899", "#06b6d4"];

function getInitialTheme() {
  if (typeof window === "undefined") return "dark";
  const saved = localStorage.getItem("tl-theme");
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

// ─── Export ───────────────────────────────────────────────────────────────────
function exportJSON(data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = "threatintel-report.json"; a.click();
  URL.revokeObjectURL(url);
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
  URL.revokeObjectURL(url);
}

// ─── Theme toggle ─────────────────────────────────────────────────────────────
function ThemeToggle({ theme, onToggle }) {
  const dark = theme === "dark";
  return (
    <button
      onClick={onToggle}
      className="tl-btn tl-toggle"
      title={dark ? "Switch to light" : "Switch to dark"}
      aria-label="Toggle color theme"
      style={{
        width: 36, height: 36, borderRadius: 9, display: "grid", placeItems: "center",
        background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-dim)",
      }}
    >
      <svg key={theme} width="17" height="17" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
        style={{ transform: dark ? "rotate(0deg)" : "rotate(40deg)" }}>
        {dark ? (
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        ) : (
          <>
            <circle cx="12" cy="12" r="4.2" />
            {[...Array(8)].map((_, i) => {
              const a = (i * Math.PI) / 4;
              return <line key={i}
                x1={12 + Math.cos(a) * 7} y1={12 + Math.sin(a) * 7}
                x2={12 + Math.cos(a) * 9} y2={12 + Math.sin(a) * 9} />;
            })}
          </>
        )}
      </svg>
    </button>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────
function ScoreMeter({ score, size = 58 }) {
  const r    = size / 2 - 7;
  const circ = 2 * Math.PI * r;
  const target = Math.min(score.decayed, 100) / 100;
  const c    = sev(score.severity);
  const [pct, setPct] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setPct(target));
    return () => cancelAnimationFrame(id);
  }, [target]);
  return (
    <div style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="var(--meter-track)" strokeWidth={5} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={c.edge}
          strokeWidth={5} strokeDasharray={circ}
          strokeDashoffset={circ * (1 - pct)} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.9s cubic-bezier(.2,.7,.3,1)" }} />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: c.text, fontFamily: MONO, lineHeight: 1 }}>{Math.round(score.decayed)}</div>
      </div>
    </div>
  );
}

function DecayChart({ daysAgo, raw }) {
  const pts = Array.from({ length: 91 }, (_, i) => ({
    x: i,
    y: raw * Math.exp(-Math.LN2 * i / HALF_LIFE_DAYS),
  }));
  const W = 240, H = 66, P = 4;
  const sx = x => P + (x / 90) * (W - P * 2);
  const sy = y => H - P - (Math.min(y, 100) / 100) * (H - P * 2);
  const path = pts.map((p, i) => `${i === 0 ? "M" : "L"}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(" ");
  const fill = path + ` L${sx(90)},${H} L${sx(0)},${H} Z`;
  const cx   = sx(daysAgo);
  const cy   = sy(pts[Math.min(daysAgo, 90)].y);
  return (
    <div>
      <div style={{ fontSize: 10, color: "var(--text-faint)", marginBottom: 4, letterSpacing: "0.06em", textTransform: "uppercase", fontFamily: DISPLAY }}>
        Time decay — 30d half-life · decayed = raw × e^(−ln2·t/30)
      </div>
      <svg width={W} height={H + 14} overflow="visible">
        <defs>
          <linearGradient id="dg" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent-1)" stopOpacity="0.30" />
            <stop offset="100%" stopColor="var(--accent-1)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        <path d={fill} fill="url(#dg)" />
        <path d={path} fill="none" stroke="var(--accent-1)" strokeWidth="1.6" />
        <line x1={cx} y1={P} x2={cx} y2={H} stroke="var(--chart-marker)" strokeWidth="1" strokeDasharray="3,2" />
        <circle cx={cx} cy={cy} r={3.5} fill="var(--chart-marker)" />
        <text x={cx + 6} y={cy - 4} fill="var(--chart-marker)" fontSize={9} fontFamily={MONO}>day {daysAgo}</text>
        {[0, 30, 60, 90].map(d => (
          <text key={d} x={sx(d) - (d === 90 ? 8 : d > 0 ? 6 : 0)} y={H + 12}
            fill="var(--text-ghost)" fontSize={8} fontFamily={MONO}>{d}d</text>
        ))}
      </svg>
    </div>
  );
}

function TagPill({ tag }) {
  return (
    <span className="tl-tint" style={{
      background: "var(--tag-bg)", color: "var(--text-dim)", border: "1px solid var(--border-soft)",
      fontSize: 10, padding: "2px 7px", borderRadius: 5, fontFamily: MONO, letterSpacing: "0.02em" }}>
      {tag}
    </span>
  );
}

function SeverityBadge({ severity }) {
  const c = sev(severity);
  return (
    <span style={{ background: c.badge, color: c.text, fontSize: 10, padding: "2px 9px",
      borderRadius: 5, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", fontFamily: DISPLAY }}>
      {severity}
    </span>
  );
}

function SourceCard({ title, data }) {
  const base = {
    background: "var(--inset)", borderRadius: 7, padding: "10px 12px",
    border: "1px solid var(--border)",
  };
  if (!data?.available) return (
    <div className="tl-tint" style={{ ...base, opacity: 0.55 }}>
      <div style={{ fontSize: 10, color: "var(--text-faint)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: DISPLAY }}>{title}</div>
      <div style={{ fontSize: 11, color: "var(--text-ghost)" }}>{data?.skipped ? "N/A for this type" : data?.error || "Unavailable"}</div>
    </div>
  );
  return (
    <div className="tl-tint" style={base}>
      <div style={{ fontSize: 10, color: "var(--text-faint)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: DISPLAY }}>{title}</div>
      {title === "VirusTotal" && (
        <>
          <div style={{ fontSize: 21, fontWeight: 700, fontFamily: MONO, color: heat(data.detections, 30, 10) }}>
            {data.detections}<span style={{ fontSize: 12, color: "var(--text-faint)" }}>/{data.total}</span>
          </div>
          <div style={{ fontSize: 10, color: "var(--text-faint)", marginTop: 2 }}>detections · ratio {data.ratio}</div>
          {data.has_poc && (
            <div style={{ fontSize: 9, color: "var(--sev-critical)", background: "var(--sev-critical-bg)", padding: "2px 6px",
              borderRadius: 4, display: "inline-block", marginTop: 5, fontFamily: MONO }}>
              PUBLIC PoC EXISTS
            </div>
          )}
          {data.cves?.length > 0 && (
            <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 3 }}>
              {data.cves.map(c => (
                <span key={c} style={{ fontSize: 9, color: "var(--sev-critical)", background: "var(--sev-critical-bg)",
                  padding: "1px 5px", borderRadius: 4, fontFamily: MONO }}>{c}</span>
              ))}
            </div>
          )}
        </>
      )}
      {title === "AbuseIPDB" && (
        <>
          <div style={{ fontSize: 21, fontWeight: 700, fontFamily: MONO, color: heat(data.abuse_score, 75, 40) }}>
            {data.abuse_score}%
          </div>
          <div style={{ fontSize: 10, color: "var(--text-faint)", marginTop: 2 }}>
            {data.total_reports} reports · {data.country} · {data.distinct_users} users
          </div>
          <div style={{ fontSize: 10, color: "var(--text-ghost)", marginTop: 2 }}>{data.isp}</div>
          <div style={{ fontSize: 10, color: "var(--text-ghost)" }}>{data.usage_type}</div>
          {data.is_tor && <div style={{ fontSize: 9, color: "var(--type-domain)", marginTop: 4, fontFamily: MONO }}>TOR EXIT NODE</div>}
        </>
      )}
      {title === "Shodan" && (
        <>
          <div style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: MONO, marginBottom: 4 }}>
            {data.open_ports?.length > 0 ? data.open_ports.join(", ") : "No open ports"}
          </div>
          {data.os && <div style={{ fontSize: 10, color: "var(--text-ghost)", marginBottom: 4 }}>{data.os} · {data.org}</div>}
          {data.vulns?.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 3, marginTop: 4 }}>
              {data.vulns.slice(0, 4).map(v => (
                <div key={v.cve} style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
                  <span style={{ fontSize: 9, color: "var(--sev-critical)", background: "var(--sev-critical-bg)",
                    padding: "1px 5px", borderRadius: 4, fontFamily: MONO, whiteSpace: "nowrap" }}>
                    {v.cve}
                  </span>
                  <span style={{ fontSize: 9, color: "var(--sev-critical-edge)", fontWeight: 700, fontFamily: MONO }}>
                    {v.cvss ? `CVSS ${v.cvss}` : ""}
                  </span>
                  <span style={{ fontSize: 9, color: "var(--text-ghost)", lineHeight: 1.4 }}>
                    {v.summary?.slice(0, 60)}{v.summary?.length > 60 ? "…" : ""}
                  </span>
                </div>
              ))}
            </div>
          )}
          {data.banners?.length > 0 && (
            <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 3 }}>
              {data.banners.map((b, i) => (
                <span key={i} style={{ fontSize: 9, color: "var(--text-faint)", background: "var(--tag-bg)",
                  padding: "1px 5px", borderRadius: 4, fontFamily: MONO }}>
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

function IOCCard({ result, isExpanded, onClick, clusterColor, index }) {
  const score = result.score;
  const c     = sev(score.severity);
  return (
    <div onClick={onClick} className="tl-card tl-rise" style={{
      background: c.bg, border: `1px solid ${isExpanded ? c.edge : "var(--border)"}`,
      borderLeft: `3px solid ${c.edge}`, borderRadius: 10, padding: "15px 17px",
      cursor: "pointer", boxShadow: isExpanded ? "var(--shadow-raised)" : "var(--shadow-card)",
      animationDelay: `${Math.min(index, 12) * 35}ms`,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 11, marginBottom: 8 }}>
        <span style={{ color: typeColor(result.type), fontSize: 17, flexShrink: 0 }}>{TYPE_ICONS[result.type]}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: MONO, fontSize: 12.5, color: "var(--text)", wordBreak: "break-all", fontWeight: 600 }}>
            {result.ioc}
          </div>
          <div style={{ fontSize: 10, color: "var(--text-faint)", marginTop: 3, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ color: typeColor(result.type), textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 600 }}>{result.type}</span>
            <span style={{ opacity: 0.4 }}>·</span>
            <span>{score.days_ago}d ago</span>
            <span style={{ opacity: 0.4 }}>·</span>
            <span style={{ color: "var(--text-ghost)" }}>decay ×{score.decay_factor}</span>
            {clusterColor && (
              <span style={{ background: clusterColor + "22", color: clusterColor,
                padding: "1px 7px", borderRadius: 4, fontSize: 9, letterSpacing: "0.04em", fontWeight: 600 }}>
                clustered
              </span>
            )}

          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6 }}>
          <SeverityBadge severity={score.severity} />
          <ScoreMeter score={score} size={58} />
        </div>
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
        {result.tags.map(t => <TagPill key={t} tag={t} />)}
      </div>

      {isExpanded && (
        <div className="tl-expand" style={{ borderTop: "1px solid var(--border)", paddingTop: 14, marginTop: 13 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginBottom: 14 }}>
            {[
              { label: "Raw Score",     value: score.raw },
              { label: "Decayed Score", value: score.decayed },
              { label: "Decay Factor",  value: score.decay_factor },
            ].map(m => (
              <div key={m.label} className="tl-tint" style={{ background: "var(--inset)", borderRadius: 6, padding: "8px 11px", border: "1px solid var(--border)" }}>
                <div style={{ fontSize: 9, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: DISPLAY }}>{m.label}</div>
                <div style={{ fontSize: 18, fontWeight: 700, fontFamily: MONO, color: "var(--text-dim)", marginTop: 2 }}>{m.value}</div>
              </div>
            ))}
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 10, color: "var(--text-faint)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: DISPLAY }}>Score components</div>
            <div style={{ display: "flex", gap: 6 }}>
              {Object.entries(score.components).map(([src, val]) => (
                <div key={src} className="tl-tint" style={{ flex: 1, background: "var(--inset)", borderRadius: 6, padding: "6px 9px", border: "1px solid var(--border)" }}>
                  <div style={{ fontSize: 9, color: "var(--text-faint)", letterSpacing: "0.05em" }}>{src}</div>
                  <div style={{ fontSize: 14, fontWeight: 700, fontFamily: MONO, color: heat(val, 50, 25) }}>{val}</div>
                  <div style={{ fontSize: 9, color: "var(--text-ghost)" }}>×{({ virustotal: 0.50, abuseipdb: 0.30, shodan: 0.20 })[src] ?? ""} (base)</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10, marginBottom: 14 }}>
            <SourceCard title="VirusTotal" data={result.sources.virustotal} />
            <SourceCard title="AbuseIPDB"  data={result.sources.abuseipdb} />
            <SourceCard title="Shodan"     data={result.sources.shodan} />
          </div>

          <DecayChart daysAgo={score.days_ago} raw={score.raw} />
        </div>
      )}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function ThreatLensDashboard() {
  const [theme,      setTheme]      = useState(getInitialTheme);
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

  useLayoutEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("tl-theme", theme);
  }, [theme]);

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

  const ghostBtn = {
    background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-dim)",
    fontSize: 11, padding: "7px 11px", borderRadius: 8, fontWeight: 500,
  };

  return (
    <div style={{ minHeight: "100vh", paddingBottom: 64 }}>

      {/* Header */}
      <header className="tl-tint" style={{
        background: "color-mix(in srgb, var(--surface) 86%, transparent)",
        backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)",
        borderBottom: "1px solid var(--border)", padding: "13px 22px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        flexWrap: "wrap", gap: 10, position: "sticky", top: 0, zIndex: 20,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 34, height: 34, background: "var(--accent-grad)", borderRadius: 9,
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 17, color: "#fff",
            boxShadow: "0 6px 18px -6px var(--accent-glow)" }}>⬡</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: "var(--text)", letterSpacing: "-0.01em", fontFamily: DISPLAY }}>ThreatLens</div>
            <div style={{ fontSize: 9.5, color: "var(--text-faint)", letterSpacing: "0.1em", textTransform: "uppercase", fontFamily: DISPLAY }}>Threat Intel Aggregator · Risk Engine</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button onClick={checkHealth} className="tl-btn tl-ghost-btn" style={{ ...ghostBtn, fontFamily: MONO }}>
            {apiStatus
              ? `backend ✓  VT:${apiStatus.virustotal?"✓":"✗"} AB:${apiStatus.abuseipdb?"✓":"✗"} SH:${apiStatus.shodan?"✓":"✗"}`
              : "Check backend"}
          </button>
          {results.length > 0 && <>
            <button onClick={() => exportJSON(response)} className="tl-btn tl-ghost-btn" style={ghostBtn}>↓ JSON</button>
            <button onClick={() => exportCSV(results)}   className="tl-btn tl-ghost-btn" style={ghostBtn}>↓ CSV</button>
          </>}
          <ThemeToggle theme={theme} onToggle={() => setTheme(t => t === "dark" ? "light" : "dark")} />
        </div>
      </header>

      <div style={{ maxWidth: 980, margin: "0 auto", padding: "26px 16px" }}>

        {/* Input panel */}
        <div className="tl-tint" style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 12, padding: 20, marginBottom: 20, boxShadow: "var(--shadow-card)" }}>
          <div style={{ fontSize: 11, color: "var(--text-faint)", marginBottom: 9, letterSpacing: "0.06em", textTransform: "uppercase", fontFamily: DISPLAY }}>
            IOC input — one per line · IPv4 · Domain · MD5/SHA256 · URL
          </div>
          <textarea
            className="tl-input"
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder={DEMO}
            rows={6}
            style={{ width: "100%", background: "var(--inset)", border: "1px solid var(--border)", color: "var(--text)",
              fontSize: 12.5, padding: "13px 15px", borderRadius: 9, fontFamily: MONO,
              resize: "vertical", outline: "none", lineHeight: 1.7 }}
          />
          <div style={{ display: "flex", gap: 10, marginTop: 13, alignItems: "center", flexWrap: "wrap" }}>
            <button onClick={runAnalysis} disabled={loading || !input.trim()} className="tl-btn tl-primary" style={{
              background: loading ? "var(--surface-2)" : "var(--accent-grad)",
              border: "none", color: loading ? "var(--text-faint)" : "#fff", fontSize: 13, fontWeight: 600,
              padding: "10px 26px", borderRadius: 9, cursor: loading ? "default" : "pointer", letterSpacing: "0.01em",
              display: "flex", alignItems: "center", gap: 9,
            }}>
              {loading && <span className="tl-spin" style={{ width: 13, height: 13, border: "2px solid currentColor", borderTopColor: "transparent", borderRadius: "50%", display: "inline-block" }} />}
              {loading ? "Analyzing…" : "Analyze IOCs"}
            </button>
            <button onClick={() => setInput(DEMO)} className="tl-btn tl-ghost-btn" style={{ ...ghostBtn, padding: "9px 15px" }}>
              Load demo
            </button>
            {input && <button onClick={() => { setInput(""); setResponse(null); setError(""); }} className="tl-btn" style={{ background: "none", border: "none", color: "var(--text-ghost)", fontSize: 11, cursor: "pointer" }}>Clear</button>}
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="tl-rise" style={{ background: "var(--sev-critical-bg)", border: "1px solid var(--sev-critical-edge)", borderRadius: 9, padding: "12px 16px", marginBottom: 16, color: "var(--sev-critical)", fontSize: 12, fontFamily: MONO }}>
            Error: {error}
            {error.toLowerCase().includes("fetch") && (
              <div style={{ marginTop: 6, color: "var(--text-faint)", fontSize: 11 }}>
                Is the backend running? → <code style={{ color: "var(--text-dim)" }}>uvicorn main:app --reload</code>
              </div>
            )}
          </div>
        )}

        {/* Summary stats */}
        {summary && (
          <div className="tl-rise" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(102px, 1fr))", gap: 10, marginBottom: 22 }}>
            {[
              { label: "Total",     value: summary.total,                           color: "var(--text)" },
              { label: "Critical",  value: summary.severity_counts?.critical || 0,  color: "var(--sev-critical)" },
              { label: "High",      value: summary.severity_counts?.high     || 0,  color: "var(--sev-high)" },
              { label: "Medium",    value: summary.severity_counts?.medium   || 0,  color: "var(--sev-medium)" },
              { label: "Low",       value: summary.severity_counts?.low      || 0,  color: "var(--sev-low)" },
              { label: "Avg score", value: summary.avg_decayed_score,               color: "var(--accent-1)" },
              { label: "Clusters",  value: summary.cluster_count,                   color: "var(--accent-2)" },
              { label: "Cached",    value: summary.cache_hits || 0,                 color: "var(--type-hash)" },
              { label: "Errors",    value: summary.errors,                          color: "var(--sev-critical-edge)" },
            ].map(s => (
              <div key={s.label} className="tl-tint" style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 9, padding: "12px 14px", boxShadow: "var(--shadow-card)" }}>
                <div style={{ fontSize: 9.5, color: "var(--text-faint)", letterSpacing: "0.07em", textTransform: "uppercase", marginBottom: 5, fontFamily: DISPLAY }}>{s.label}</div>
                <div style={{ fontSize: 23, fontWeight: 700, color: s.color, fontFamily: MONO, lineHeight: 1 }}>{s.value}</div>
              </div>
            ))}
          </div>
        )}

        {/* Tabs */}
        {results.length > 0 && (
          <>
            <div style={{ display: "flex", gap: 4, borderBottom: "1px solid var(--border)", marginBottom: 16 }}>
              {["results","clusters"].map(tab => (
                <button key={tab} onClick={() => setActiveTab(tab)} className="tl-btn tl-tab" style={{
                  background: "none", border: "none", color: activeTab === tab ? "var(--accent-1)" : "var(--text-faint)",
                  fontSize: 13, padding: "8px 16px", cursor: "pointer", fontWeight: activeTab === tab ? 600 : 500,
                  borderBottom: `2px solid ${activeTab === tab ? "var(--accent-1)" : "transparent"}`,
                  textTransform: "capitalize", letterSpacing: "0.02em", marginBottom: -1, fontFamily: DISPLAY,
                }}>{tab}</button>
              ))}
            </div>

            {/* Filters */}
            {activeTab === "results" && (
              <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
                {[
                  { val: filterSev,  set: setFilterSev,  opts: ["all","critical","high","medium","low"], label: "Severity" },
                  { val: filterType, set: setFilterType, opts: ["all","ipv4","domain","hash","url"],     label: "Type" },
                  { val: sortBy,     set: setSortBy,      opts: ["score","age"],                          label: "Sort" },
                ].map(({ val, set, opts, label }) => (
                  <select key={label} value={val} onChange={e => set(e.target.value)} className="tl-select tl-tint"
                    style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-dim)", fontSize: 11.5, padding: "7px 11px", borderRadius: 8, outline: "none", fontFamily: DISPLAY }}>
                    {opts.map(o => <option key={o} value={o}>{label === "Sort" ? (o === "score" ? "Sort: Score" : "Sort: Recent") : (o === "all" ? `All ${label}s` : o.charAt(0).toUpperCase() + o.slice(1))}</option>)}
                  </select>
                ))}
                <div style={{ fontSize: 11, color: "var(--text-ghost)", marginLeft: "auto", fontFamily: MONO }}>{filtered.length} of {results.length}</div>
              </div>
            )}

            {/* Results */}
            {activeTab === "results" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {filtered.map((r, i) => (
                  <IOCCard key={r.idx} result={r} index={i} isExpanded={expandedIdx === r.idx}
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
                    <div key={cluster.id} className="tl-tint tl-rise" style={{ background: "var(--surface)", border: `1px solid ${color}44`, borderLeft: `3px solid ${color}`, borderRadius: 10, padding: 16, boxShadow: "var(--shadow-card)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, gap: 8, flexWrap: "wrap" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <div style={{ width: 10, height: 10, borderRadius: "50%", background: color }} />
                          <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text)", fontFamily: DISPLAY }}>Cluster {cluster.id + 1}</span>
                          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>{cluster.size} IOC{cluster.size !== 1 ? "s" : ""}</span>
                          {cluster.is_singleton && <span style={{ fontSize: 10, color: "var(--text-faint)", background: "var(--tag-bg)", padding: "1px 6px", borderRadius: 4 }}>singleton</span>}
                        </div>
                        <span style={{ fontSize: 12, fontFamily: MONO, color }}>avg {avgScore}</span>
                      </div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 10 }}>
                        {cluster.centroid_tags.map(t => <TagPill key={t} tag={t} />)}
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        {members.map((r, i) => (
                          <div key={i} className="tl-tint" style={{ display: "flex", alignItems: "center", gap: 10, background: "var(--inset)", borderRadius: 6, padding: "8px 11px", fontSize: 11 }}>
                            <span style={{ color: typeColor(r.type) }}>{TYPE_ICONS[r.type]}</span>
                            <span style={{ fontFamily: MONO, color: "var(--text-dim)", flex: 1, wordBreak: "break-all" }}>{r.ioc}</span>
                            <SeverityBadge severity={r.score.severity} />
                            <span style={{ fontFamily: MONO, color, fontWeight: 700 }}>{r.score.decayed}</span>
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
          <div className="tl-rise" style={{ textAlign: "center", padding: "64px 20px", color: "var(--text-ghost)" }}>
            <div style={{ fontSize: 44, marginBottom: 14, opacity: 0.35 }}>⬡</div>
            <div style={{ fontSize: 14, color: "var(--text-dim)", marginBottom: 6, fontFamily: DISPLAY }}>Paste IOCs above to begin</div>
            <div style={{ fontSize: 11.5 }}>IPv4 · Domains · MD5/SHA256 hashes · URLs</div>
            <div className="tl-btn" style={{ fontSize: 11.5, marginTop: 12, color: "var(--accent-1)", cursor: "pointer", display: "inline-block", fontWeight: 600 }} onClick={checkHealth}>
              Ping backend →
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
