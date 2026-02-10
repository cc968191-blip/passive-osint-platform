import { NextRequest, NextResponse } from "next/server";
import dns from "dns/promises";

export const runtime = "nodejs";
export const maxDuration = 30;

async function queryCrtsh(domain: string) {
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (resp.ok) {
      const data = await resp.json();
      const subdomains = new Set<string>();
      for (const entry of data) {
        const nameValue: string = entry.name_value || "";
        for (const sub of nameValue.split("\n")) {
          const trimmed = sub.trim();
          if (trimmed && trimmed.includes(domain)) {
            subdomains.add(trimmed);
          }
        }
      }
      return { source: "crt.sh", status: "success", data: Array.from(subdomains) };
    }
    return { source: "crt.sh", status: "failed", error: `HTTP ${resp.status}` };
  } catch (e: unknown) {
    return { source: "crt.sh", status: "error", error: String(e) };
  }
}

async function queryWayback(domain: string) {
  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}&output=text&fl=original&collapse=urlkey&limit=50`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(20000) });
    if (resp.ok) {
      const text = await resp.text();
      const lines = text.trim().split("\n").filter(Boolean);
      const unique = Array.from(new Set(lines)).slice(0, 30);
      if (unique.length > 0) {
        return { source: "wayback", status: "success", data: unique };
      }
      return { source: "wayback", status: "no_data", data: [] };
    }
    return { source: "wayback", status: "failed", error: `HTTP ${resp.status}` };
  } catch (e: unknown) {
    return { source: "wayback", status: "error", error: String(e) };
  }
}

async function queryDns(domain: string) {
  try {
    const addresses = await dns.resolve4(domain);
    return { source: "dns", status: "success", ip: addresses[0] };
  } catch (e: unknown) {
    return { source: "dns", status: "error", error: String(e) };
  }
}

function isValidDomain(domain: string): boolean {
  const pattern = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$/;
  return pattern.test(domain);
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const domain = (body.domain || "").trim().toLowerCase();
    const modules: string[] = body.modules || ["subdomains", "technologies"];

    if (!domain) {
      return NextResponse.json({ error: "Domain is required" }, { status: 400 });
    }
    if (!isValidDomain(domain)) {
      return NextResponse.json({ error: "Invalid domain format" }, { status: 400 });
    }

    const results: Record<string, unknown> = {};

    // DNS (always)
    results.dns = await queryDns(domain);

    // Subdomains via crt.sh
    if (modules.includes("subdomains")) {
      results.subdomains = await queryCrtsh(domain);
    }

    // Wayback Machine
    results.wayback = await queryWayback(domain);

    // Stub modules that need API keys
    for (const mod of modules) {
      if (!(mod in results) && mod !== "subdomains") {
        results[mod] = {
          source: mod,
          status: "skipped",
          simulated: true,
          message: `${mod} requires API key configuration.`,
        };
      }
    }

    return NextResponse.json({
      domain,
      timestamp: new Date().toISOString(),
      modules_run: modules,
      status: "COMPLETE",
      results,
    });
  } catch (e: unknown) {
    console.error("Reconnaissance error:", e);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
