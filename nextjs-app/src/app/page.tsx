"use client";

import { useState, useRef, useCallback, useEffect } from "react";

/* eslint-disable */
type R = Record<string, any>;

type ReconResponse = {
  domain: string;
  timestamp: string;
  modules_run: string[];
  status: string;
  results: Record<string, R>;
};

const MODULES = [
  { id: "subdomains", label: "Subdomains", desc: "Certificate Transparency" },
  { id: "technologies", label: "Technologies", desc: "HTTP Fingerprinting" },
  { id: "security_headers", label: "Security Headers", desc: "Header Analysis" },
  { id: "whois", label: "WHOIS / RDAP", desc: "Domain Registration" },
];

const STEPS = [
  "Validating domain...",
  "Resolving DNS (A, MX, NS, TXT)...",
  "Querying Certificate Transparency...",
  "Fingerprinting technologies...",
  "Analyzing security headers...",
  "Querying WHOIS / RDAP...",
  "Querying Wayback Machine...",
  "Processing results...",
];

export default function Home() {
  const [phase, setPhase] = useState<"input" | "scan" | "results">("input");
  const [domain, setDomain] = useState("");
  const [selectedModules, setSelectedModules] = useState<string[]>(
    MODULES.map((m) => m.id)
  );
  const [currentStep, setCurrentStep] = useState(0);
  const [elapsed, setElapsed] = useState("00:00");
  const [finalElapsed, setFinalElapsed] = useState("");
  const [data, setData] = useState<ReconResponse | null>(null);
  const [error, setError] = useState("");
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startRef = useRef(0);
  const stepRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const startTimer = useCallback(() => {
    startRef.current = Date.now();
    timerRef.current = setInterval(() => {
      const s = Math.floor((Date.now() - startRef.current) / 1000);
      const m = String(Math.floor(s / 60)).padStart(2, "0");
      const sec = String(s % 60).padStart(2, "0");
      setElapsed(`${m}:${sec}`);
    }, 250);
  }, []);

  const stopTimer = useCallback(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (stepRef.current) clearInterval(stepRef.current);
    return ((Date.now() - startRef.current) / 1000).toFixed(1);
  }, []);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (stepRef.current) clearInterval(stepRef.current);
    };
  }, []);

  const toggleModule = (id: string) => {
    setSelectedModules((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const d = domain.trim();
    if (!d || selectedModules.length === 0) return;

    setPhase("scan");
    setCurrentStep(0);
    setElapsed("00:00");
    setError("");
    setData(null);
    startTimer();

    // Animate steps progressively
    let step = 0;
    stepRef.current = setInterval(() => {
      step++;
      if (step < STEPS.length - 1) {
        setCurrentStep(step);
      }
    }, 2500);

    try {
      const res = await fetch("/api/reconnaissance", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: d, modules: selectedModules }),
      });

      setCurrentStep(STEPS.length);

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Reconnaissance failed");
      }

      const result: ReconResponse = await res.json();
      const dur = stopTimer();
      setFinalElapsed(dur);
      setData(result);
      setPhase("results");
    } catch (err: unknown) {
      const dur = stopTimer();
      setFinalElapsed(dur);
      setError(err instanceof Error ? err.message : String(err));
      setPhase("results");
    }
  };

  const handleNewScan = () => {
    setDomain("");
    setPhase("input");
    setData(null);
    setError("");
  };

  // ─── SCAN PHASE ───
  if (phase === "scan") {
    return (
      <div className="text-center py-20">
        <div className="w-12 h-12 border-2 border-neutral-700 border-t-white rounded-full animate-spin mx-auto mb-6" />
        <h2 className="text-sm tracking-widest uppercase mb-1">
          Scanning <span className="font-bold">{domain}</span>
        </h2>
        <p className="text-neutral-600 text-xs">
          Running {selectedModules.length + 2} modules in parallel
        </p>
        <div className="mt-5 text-3xl font-bold text-neutral-500 tracking-widest">
          {elapsed}
        </div>
        <div className="mt-7 inline-flex flex-col gap-1.5 text-left text-xs">
          {STEPS.map((step, i) => (
            <div
              key={i}
              className={
                i < currentStep
                  ? "text-white"
                  : i === currentStep
                  ? "text-neutral-400 animate-pulse"
                  : "text-neutral-700"
              }
            >
              {i < currentStep ? `✓ ${step}` : `○ ${step}`}
            </div>
          ))}
        </div>
      </div>
    );
  }

  // ─── RESULTS PHASE ───
  if (phase === "results") {
    if (error) {
      return (
        <div>
          <ResultsHeader title="ERROR" meta={domain} onNewScan={handleNewScan} />
          <Card title="Error" badge="fail">
            <p className="text-neutral-500 text-sm">{error}</p>
          </Card>
        </div>
      );
    }

    if (!data) return null;

    const r = data.results;
    const dns = r.dns;
    const subs = r.subdomains;
    const wb = r.wayback;
    const techs = r.technologies;
    const secHeaders = r.security_headers;
    const whois = r.whois;

    const arr = (v: any): any[] => (Array.isArray(v) ? v : []);
    const len = (v: any): number => arr(v).length;

    let totalFindings = 0;
    if (dns?.status === "success") totalFindings++;
    if (subs?.status === "success") totalFindings += len(subs.data);
    if (wb?.status === "success") totalFindings += len(wb.data);
    if (techs?.status === "success") totalFindings += len(techs.data);
    if (secHeaders?.status === "success") totalFindings += len(secHeaders.data);
    if (whois?.status === "success") totalFindings += Object.keys(whois.data || {}).length;

    return (
      <div>
        <ResultsHeader
          title="RECONNAISSANCE COMPLETE"
          meta={`${data.domain}  •  ${new Date(data.timestamp).toLocaleString("en-GB")}  •  ${finalElapsed}s`}
          onNewScan={handleNewScan}
        />
        <div className="flex flex-col gap-4">

          {/* ── Summary ── */}
          <Card title="Summary" badge="ok">
            <KV pairs={[
              ["Target", data.domain],
              ["Status", data.status],
              ["Duration", `${finalElapsed} seconds`],
              ["Total Findings", String(totalFindings)],
              ["Modules Executed", data.modules_run.join(", ")],
            ]} />
          </Card>

          {/* ── DNS ── */}
          {dns && (
            <Card title="DNS Resolution" badge={dns.status === "success" ? "ok" : "fail"}>
              {dns.ip ? (
                <div>
                  <KV pairs={[
                    ["IP Address", dns.ip],
                    ...(dns.all_ips && dns.all_ips.length > 1
                      ? [["All IPs", dns.all_ips.join(", ")] as [string, string]]
                      : []),
                  ]} />
                  {dns.mx && dns.mx.length > 0 && (
                    <div className="mt-3">
                      <div className="text-[0.7rem] text-neutral-500 uppercase tracking-wider mb-1.5">
                        MX Records
                      </div>
                      <DataList items={dns.mx} />
                    </div>
                  )}
                  {dns.ns && dns.ns.length > 0 && (
                    <div className="mt-3">
                      <div className="text-[0.7rem] text-neutral-500 uppercase tracking-wider mb-1.5">
                        Nameservers
                      </div>
                      <DataList items={dns.ns} />
                    </div>
                  )}
                  {dns.txt && dns.txt.length > 0 && (
                    <div className="mt-3">
                      <div className="text-[0.7rem] text-neutral-500 uppercase tracking-wider mb-1.5">
                        TXT Records
                      </div>
                      <DataList items={dns.txt} />
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-5 text-neutral-600 text-sm">
                  {dns.error || "Resolution failed"}
                </div>
              )}
            </Card>
          )}

          {/* ── Technologies ── */}
          {techs && <TechCard techs={techs} />}

          {/* ── Security Headers ── */}
          {secHeaders && <SecHeadersCard sec={secHeaders} />}

          {/* ── WHOIS ── */}
          {whois && (
            <Card
              title="WHOIS / RDAP"
              badge={whois.status === "success" || whois.status === "partial" ? "ok" : "fail"}
            >
              {(whois.status === "success" || whois.status === "partial") &&
              whois.data &&
              typeof whois.data === "object" &&
              Object.keys(whois.data).length > 0 ? (
                <KV
                  pairs={Object.entries(whois.data).map(
                    ([k, v]) => [k, String(v)] as [string, string]
                  )}
                />
              ) : (
                <div className="text-center py-5 text-neutral-600 text-sm">
                  {String(whois.error || "WHOIS data not available for this domain.")}
                </div>
              )}
            </Card>
          )}

          {/* ── Subdomains ── */}
          {subs && (
            <Card
              title={
                subs.status === "success" && len(subs.data)
                  ? `Subdomains — ${len(subs.data)} found`
                  : "Subdomains"
              }
              badge={subs.status === "success" && len(subs.data) ? "ok" : "empty"}
            >
              {subs.status === "success" && len(subs.data) ? (
                <>
                  <DataList items={arr(subs.data)} />
                  <div className="text-[0.72rem] text-neutral-600 pt-2 text-right border-t border-neutral-900 mt-2">
                    Source: {String(subs.source)} (Certificate Transparency)
                  </div>
                </>
              ) : (
                <div className="text-center py-5 text-neutral-600 text-sm">
                  {String(subs.error || "No subdomains discovered.")}
                </div>
              )}
            </Card>
          )}

          {/* ── Wayback ── */}
          {wb && (
            <Card
              title={
                wb.status === "success" && len(wb.data)
                  ? `Wayback Machine — ${len(wb.data)} URLs`
                  : "Wayback Machine"
              }
              badge={wb.status === "success" && len(wb.data) ? "ok" : "empty"}
            >
              {wb.status === "success" && len(wb.data) ? (
                <>
                  <DataList items={arr(wb.data)} />
                  <div className="text-[0.72rem] text-neutral-600 pt-2 text-right border-t border-neutral-900 mt-2">
                    Source: Wayback Machine CDX API
                  </div>
                </>
              ) : (
                <div className="text-center py-5 text-neutral-600 text-sm">
                  {String(wb.error || "No historical snapshots found.")}
                </div>
              )}
            </Card>
          )}
        </div>
      </div>
    );
  }

  // ─── INPUT PHASE ───
  return (
    <div>
      <div className="text-center mb-10">
        <h1 className="text-2xl font-bold tracking-[3px] uppercase mb-2">
          Reconnaissance
        </h1>
        <p className="text-neutral-500 text-sm">
          Passive intelligence collection from public data sources — no API keys required.
        </p>
      </div>
      <div className="border border-neutral-700 p-8 max-w-xl mx-auto">
        <form onSubmit={handleSubmit}>
          <label className="block text-[0.75rem] uppercase tracking-wider text-neutral-500 mb-2">
            Target Domain
          </label>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            required
            autoComplete="off"
            spellCheck={false}
            className="w-full bg-black border border-neutral-600 text-white px-3 py-3 font-mono text-sm focus:outline-none focus:border-white"
          />

          <label className="block text-[0.75rem] uppercase tracking-wider text-neutral-500 mb-2 mt-5">
            Modules
          </label>
          <div className="grid grid-cols-2 gap-1.5 mb-7">
            {MODULES.map((mod) => (
              <label
                key={mod.id}
                className="flex items-center gap-2 px-2.5 py-2.5 border border-neutral-800 text-xs cursor-pointer hover:border-neutral-500 transition-colors"
              >
                <input
                  type="checkbox"
                  checked={selectedModules.includes(mod.id)}
                  onChange={() => toggleModule(mod.id)}
                  className="accent-white w-3.5 h-3.5 cursor-pointer"
                />
                <div>
                  <div className="font-bold">{mod.label}</div>
                  <div className="text-neutral-600 text-[0.65rem]">{mod.desc}</div>
                </div>
              </label>
            ))}
          </div>

          <div className="text-[0.68rem] text-neutral-600 mb-4 text-center">
            DNS Resolution + Wayback Machine are always included.
          </div>

          <button
            type="submit"
            className="w-full py-3.5 bg-white text-black font-bold text-xs tracking-wider uppercase hover:bg-neutral-300 transition-colors"
          >
            Execute Reconnaissance
          </button>
        </form>
      </div>
    </div>
  );
}

// ─── Module Cards ───

function TechCard({ techs }: { techs: R }) {
  const data: any[] = Array.isArray(techs.data) ? techs.data : [];
  const ok = techs.status === "success" && data.length > 0;

  // Group by category
  const grouped: Record<string, { name: string; confidence: string }[]> = {};
  if (ok) {
    for (const t of data) {
      const cat = t.category || "Other";
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push({ name: t.name, confidence: t.confidence });
    }
  }

  return (
    <Card
      title={ok ? `Technologies — ${data.length} detected` : "Technologies"}
      badge={ok ? "ok" : techs.status === "error" ? "fail" : "empty"}
    >
      {ok ? (
        <div>
          {Object.entries(grouped).map(([category, items]) => (
            <div key={category} className="mb-3 last:mb-0">
              <div className="text-[0.7rem] text-neutral-500 uppercase tracking-wider mb-1.5 border-b border-neutral-900 pb-1">
                {category}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {items.map((t, i) => (
                  <span
                    key={i}
                    className={`inline-block px-2.5 py-1 text-xs border ${
                      t.confidence === "high"
                        ? "border-white text-white"
                        : "border-neutral-600 text-neutral-400"
                    }`}
                  >
                    {t.name}
                  </span>
                ))}
              </div>
            </div>
          ))}
          <div className="text-[0.72rem] text-neutral-600 pt-2 text-right border-t border-neutral-900 mt-3">
            Source: {String(techs.source)} • {data.length} technologies
          </div>
        </div>
      ) : (
        <div className="text-center py-5 text-neutral-600 text-sm">
          {String(techs.error || "No technologies detected.")}
        </div>
      )}
    </Card>
  );
}

function SecHeadersCard({ sec }: { sec: R }) {
  const data: any[] = Array.isArray(sec.data) ? sec.data : [];
  const ok = sec.status === "success" && data.length > 0;
  const grade = String(sec.grade || "?");
  const missing = data.filter((h) => h.status === "missing").length;

  return (
    <Card
      title={ok ? `Security Headers — Grade ${grade} (${sec.score})` : "Security Headers"}
      badge={ok ? (grade === "A" || grade === "B" ? "ok" : "fail") : "fail"}
    >
      {ok ? (
        <div>
          <div className="flex items-center gap-4 mb-4 pb-3 border-b border-neutral-800">
            <div
              className={`text-4xl font-bold ${
                grade === "A"
                  ? "text-white"
                  : grade === "B"
                  ? "text-neutral-300"
                  : grade === "C"
                  ? "text-neutral-400"
                  : "text-neutral-600"
              }`}
            >
              {grade}
            </div>
            <div className="text-xs text-neutral-500">
              <div>{String(sec.score)} headers present</div>
              <div className="mt-0.5">{missing} missing</div>
            </div>
          </div>
          {data.map((h, i) => (
            <div
              key={i}
              className="flex items-start justify-between py-2 border-b border-neutral-900 last:border-b-0 gap-3"
            >
              <div className="flex-1 min-w-0">
                <div className="text-xs font-bold flex items-center gap-2">
                  <span
                    className={
                      h.status === "present" ? "text-white" : "text-neutral-600"
                    }
                  >
                    {h.status === "present" ? "✓" : "✗"}
                  </span>
                  {h.header}
                </div>
                {h.status === "present" && h.value !== "Not set" && (
                  <div className="text-[0.68rem] text-neutral-500 mt-0.5 break-all">
                    {h.value}
                  </div>
                )}
              </div>
              <span
                className={`text-[0.6rem] px-1.5 py-0.5 border shrink-0 uppercase tracking-wide ${
                  h.severity === "high"
                    ? "border-white text-white"
                    : h.severity === "medium"
                    ? "border-neutral-500 text-neutral-400"
                    : "border-neutral-700 text-neutral-600"
                }`}
              >
                {h.severity}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-5 text-neutral-600 text-sm">
          {String(sec.error || "Could not analyze security headers.")}
        </div>
      )}
    </Card>
  );
}

// ─── Sub-components ───

function ResultsHeader({
  title,
  meta,
  onNewScan,
}: {
  title: string;
  meta: string;
  onNewScan: () => void;
}) {
  return (
    <div className="flex items-center justify-between border-b border-neutral-800 pb-4 mb-6">
      <div>
        <h2 className="text-sm font-bold tracking-widest uppercase">{title}</h2>
        <div className="text-[0.78rem] text-neutral-500 mt-1 tracking-wide">
          {meta}
        </div>
      </div>
      <button
        onClick={onNewScan}
        className="px-6 py-2.5 bg-black text-white border border-white font-mono text-xs tracking-wider uppercase cursor-pointer hover:bg-white hover:text-black transition-colors"
      >
        New Scan
      </button>
    </div>
  );
}

function Card({
  title,
  badge,
  children,
}: {
  title: string;
  badge: "ok" | "fail" | "empty" | "key";
  children: React.ReactNode;
}) {
  const badgeStyles = {
    ok: "border-white text-white",
    fail: "border-neutral-500 text-neutral-500",
    empty: "border-neutral-700 text-neutral-600",
    key: "border-neutral-700 text-neutral-600",
  };
  const badgeLabels = {
    ok: "OK",
    fail: "FAIL",
    empty: "NO DATA",
    key: "API KEY",
  };

  return (
    <div className="border border-neutral-800">
      <div className="flex items-center justify-between px-4 py-3 border-b border-neutral-800 bg-[#0a0a0a]">
        <span className="text-xs font-bold tracking-wider uppercase">
          {title}
        </span>
        <span
          className={`text-[0.65rem] px-2 py-0.5 border tracking-wide uppercase ${badgeStyles[badge]}`}
        >
          {badgeLabels[badge]}
        </span>
      </div>
      <div className="px-4 py-3.5">{children}</div>
    </div>
  );
}

function KV({ pairs }: { pairs: [string, string][] }) {
  return (
    <div>
      {pairs.map(([k, v], i) => (
        <div
          key={i}
          className="flex justify-between py-1.5 border-b border-neutral-900 last:border-b-0 text-sm gap-4"
        >
          <span className="text-neutral-500 shrink-0">{k}</span>
          <span className="font-bold text-right break-all">{v}</span>
        </div>
      ))}
    </div>
  );
}

function DataList({ items }: { items: string[] }) {
  return (
    <ul className="max-h-72 overflow-y-auto">
      {items.map((item, i) => (
        <li
          key={i}
          className="py-1.5 border-b border-neutral-900 last:border-b-0 text-xs break-all"
        >
          {item}
        </li>
      ))}
    </ul>
  );
}
