"use client";

import { useState, useRef, useCallback, useEffect } from "react";

type ModuleResult = {
  source: string;
  status: string;
  data?: string[];
  ip?: string;
  error?: string;
  simulated?: boolean;
  message?: string;
};

type ReconResponse = {
  domain: string;
  timestamp: string;
  modules_run: string[];
  status: string;
  results: Record<string, ModuleResult>;
};

const MODULES = [
  { id: "subdomains", label: "Subdomains" },
  { id: "ports", label: "Ports" },
  { id: "technologies", label: "Technologies" },
  { id: "vulnerabilities", label: "Vulnerabilities" },
  { id: "credentials", label: "Credentials" },
];

const STEPS = [
  "Validating domain...",
  "Resolving DNS...",
  "Querying crt.sh (Certificate Transparency)...",
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
    return ((Date.now() - startRef.current) / 1000).toFixed(1);
  }, []);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
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

    try {
      setCurrentStep(1);

      const res = await fetch("/api/reconnaissance", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: d, modules: selectedModules }),
      });

      setCurrentStep(4);

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

  // --- RENDER ---

  if (phase === "scan") {
    return (
      <div className="text-center py-20">
        <div className="w-12 h-12 border-2 border-neutral-700 border-t-white rounded-full animate-spin mx-auto mb-6" />
        <h2 className="text-sm tracking-widest uppercase mb-1">
          Scanning <span className="font-bold">{domain}</span>
        </h2>
        <p className="text-neutral-600 text-xs">
          Collecting intelligence from public sources
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
                  ? "text-neutral-400"
                  : "text-neutral-700"
              }
            >
              {i < currentStep ? `✓ ${step}` : step}
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (phase === "results") {
    if (error) {
      return (
        <div>
          <ResultsHeader
            title="ERROR"
            meta={domain}
            onNewScan={handleNewScan}
          />
          <Card title="Error" badge="fail">
            <p className="text-neutral-500 text-sm">{error}</p>
          </Card>
        </div>
      );
    }

    if (!data) return null;

    const dns = data.results.dns;
    const subs = data.results.subdomains;
    const wb = data.results.wayback;

    let totalFindings = 0;
    if (dns?.status === "success") totalFindings++;
    if (subs?.status === "success" && subs.data) totalFindings += subs.data.length;
    if (wb?.status === "success" && wb.data) totalFindings += wb.data.length;

    return (
      <div>
        <ResultsHeader
          title="RECONNAISSANCE COMPLETE"
          meta={`${data.domain}  •  ${new Date(data.timestamp).toLocaleString("en-GB")}  •  ${finalElapsed}s`}
          onNewScan={handleNewScan}
        />
        <div className="flex flex-col gap-4">
          {/* Summary */}
          <Card title="Summary" badge="ok">
            <KV pairs={[
              ["Target", data.domain],
              ["Status", data.status],
              ["Duration", `${finalElapsed} seconds`],
              ["Total Findings", String(totalFindings)],
              ["Modules Executed", data.modules_run.join(", ")],
            ]} />
          </Card>

          {/* DNS */}
          {dns && (
            <Card title="DNS Resolution" badge={dns.status === "success" ? "ok" : "fail"}>
              {dns.status === "success" ? (
                <KV pairs={[
                  ["IP Address", dns.ip || "N/A"],
                  ["Source", "Direct DNS Lookup"],
                  ["Status", "Resolved"],
                ]} />
              ) : (
                <div className="text-center py-5 text-neutral-600 text-sm">
                  {dns.error || "Resolution failed"}
                </div>
              )}
            </Card>
          )}

          {/* Subdomains */}
          {subs && (
            <Card
              title={
                subs.status === "success" && subs.data?.length
                  ? `Subdomains — ${subs.data.length} found`
                  : "Subdomains"
              }
              badge={subs.status === "success" && subs.data?.length ? "ok" : "empty"}
            >
              {subs.status === "success" && subs.data?.length ? (
                <>
                  <DataList items={subs.data} />
                  <div className="text-[0.72rem] text-neutral-600 pt-2 text-right border-t border-neutral-900 mt-2">
                    Source: {subs.source}
                  </div>
                </>
              ) : (
                <div className="text-center py-5 text-neutral-600 text-sm">
                  No subdomains discovered via Certificate Transparency.
                </div>
              )}
            </Card>
          )}

          {/* Wayback */}
          {wb && (
            <Card
              title={
                wb.status === "success" && wb.data?.length
                  ? `Wayback Machine — ${wb.data.length} URLs`
                  : "Wayback Machine"
              }
              badge={wb.status === "success" && wb.data?.length ? "ok" : "empty"}
            >
              {wb.status === "success" && wb.data?.length ? (
                <>
                  <DataList items={wb.data} />
                  <div className="text-[0.72rem] text-neutral-600 pt-2 text-right border-t border-neutral-900 mt-2">
                    Source: Wayback Machine CDX API
                  </div>
                </>
              ) : (
                <div className="text-center py-5 text-neutral-600 text-sm">
                  No historical snapshots found.
                </div>
              )}
            </Card>
          )}

          {/* API key modules */}
          {Object.entries(data.results)
            .filter(([key]) => !["dns", "subdomains", "wayback"].includes(key))
            .map(([key, val]) =>
              val.simulated ? (
                <Card key={key} title={capitalize(key)} badge="key">
                  <div className="text-center py-5 text-neutral-600 text-sm">
                    Requires API key. Configure {key.toUpperCase()}_API_KEY in
                    environment to enable.
                  </div>
                </Card>
              ) : null
            )}
        </div>
      </div>
    );
  }

  // --- INPUT PHASE ---
  return (
    <div>
      <div className="text-center mb-10">
        <h1 className="text-2xl font-bold tracking-[3px] uppercase mb-2">
          Reconnaissance
        </h1>
        <p className="text-neutral-500 text-sm">
          Passive intelligence collection from public data sources.
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
                className="flex items-center gap-2 px-2.5 py-2 border border-neutral-800 text-xs cursor-pointer hover:border-neutral-500 transition-colors"
              >
                <input
                  type="checkbox"
                  checked={selectedModules.includes(mod.id)}
                  onChange={() => toggleModule(mod.id)}
                  className="accent-white w-3.5 h-3.5 cursor-pointer"
                />
                {mod.label}
              </label>
            ))}
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

// --- Sub-components ---

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
    fail: "text-neutral-500",
    empty: "text-neutral-600",
    key: "text-neutral-600",
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
          className={`text-[0.65rem] px-2 py-0.5 border border-neutral-600 tracking-wide uppercase ${badgeStyles[badge]}`}
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
          className="flex justify-between py-1.5 border-b border-neutral-900 last:border-b-0 text-sm"
        >
          <span className="text-neutral-500">{k}</span>
          <span className="font-bold">{v}</span>
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

function capitalize(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
