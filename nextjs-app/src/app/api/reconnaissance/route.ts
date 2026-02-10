import { NextRequest, NextResponse } from "next/server";
import dns from "dns/promises";

export const runtime = "nodejs";
export const maxDuration = 60;

/* ─── TECHNOLOGY FINGERPRINT SIGNATURES ─── */
const HEADER_SIGNATURES: Record<string, Record<string, string>> = {
  server: {
    nginx: "Nginx",
    apache: "Apache",
    cloudflare: "Cloudflare",
    "microsoft-iis": "Microsoft IIS",
    litespeed: "LiteSpeed",
    openresty: "OpenResty",
    gunicorn: "Gunicorn",
    express: "Express.js",
    cowboy: "Cowboy (Erlang)",
    caddy: "Caddy",
    envoy: "Envoy",
  },
  "x-powered-by": {
    express: "Express.js",
    "asp.net": "ASP.NET",
    php: "PHP",
    "next.js": "Next.js",
    nuxt: "Nuxt.js",
    django: "Django",
    flask: "Flask",
    rails: "Ruby on Rails",
    "wp engine": "WP Engine",
    plesk: "Plesk",
  },
};

const HTML_PATTERNS: [RegExp, string, string][] = [
  [/wp-content|wp-includes|wordpress/i, "WordPress", "CMS"],
  [/sites\/default\/files|drupal/i, "Drupal", "CMS"],
  [/\/media\/jui\/|joomla/i, "Joomla", "CMS"],
  [/shopify\.com|cdn\.shopify/i, "Shopify", "E-Commerce"],
  [/woocommerce/i, "WooCommerce", "E-Commerce"],
  [/squarespace/i, "Squarespace", "CMS"],
  [/wix\.com|parastorage\.com/i, "Wix", "CMS"],
  [/ghost\.org|ghost\.io/i, "Ghost", "CMS"],
  [/react/i, "React", "JavaScript Framework"],
  [/__next|_next\/static/i, "Next.js", "JavaScript Framework"],
  [/__nuxt|_nuxt\//i, "Nuxt.js", "JavaScript Framework"],
  [/ng-version|angular/i, "Angular", "JavaScript Framework"],
  [/vue\.js|vue\.min\.js|vue\.runtime/i, "Vue.js", "JavaScript Framework"],
  [/svelte/i, "Svelte", "JavaScript Framework"],
  [/gatsby/i, "Gatsby", "Static Site Generator"],
  [/jquery|jquery\.min\.js/i, "jQuery", "JavaScript Library"],
  [/bootstrap\.min\.css|bootstrap\.min\.js/i, "Bootstrap", "CSS Framework"],
  [/tailwindcss|tailwind/i, "Tailwind CSS", "CSS Framework"],
  [/font-awesome|fontawesome/i, "Font Awesome", "Icon Library"],
  [/google-analytics|gtag|ga\.js|analytics\.js/i, "Google Analytics", "Analytics"],
  [/googletagmanager/i, "Google Tag Manager", "Tag Manager"],
  [/hotjar/i, "Hotjar", "Analytics"],
  [/segment\.com|segment\.io/i, "Segment", "Analytics"],
  [/cloudflare/i, "Cloudflare", "CDN"],
  [/akamai/i, "Akamai", "CDN"],
  [/fastly/i, "Fastly", "CDN"],
  [/unpkg\.com/i, "unpkg", "CDN"],
  [/cdnjs\.cloudflare\.com/i, "cdnjs", "CDN"],
  [/jsdelivr/i, "jsDelivr", "CDN"],
  [/recaptcha/i, "reCAPTCHA", "Security"],
  [/hcaptcha/i, "hCaptcha", "Security"],
  [/stripe\.com|stripe\.js/i, "Stripe", "Payment"],
  [/paypal/i, "PayPal", "Payment"],
  [/webpack/i, "Webpack", "Build Tool"],
  [/vite/i, "Vite", "Build Tool"],
  [/laravel/i, "Laravel", "PHP Framework"],
  [/symfony/i, "Symfony", "PHP Framework"],
  [/rails/i, "Ruby on Rails", "Web Framework"],
  [/django/i, "Django", "Web Framework"],
  [/flask/i, "Flask", "Web Framework"],
  [/vercel/i, "Vercel", "Hosting"],
  [/netlify/i, "Netlify", "Hosting"],
  [/heroku/i, "Heroku", "Hosting"],
  [/amazonaws\.com/i, "Amazon AWS", "Cloud"],
  [/googleapis\.com/i, "Google Cloud", "Cloud"],
  [/azure/i, "Microsoft Azure", "Cloud"],
];

const META_GENERATOR_MAP: [RegExp, string][] = [
  [/wordpress/i, "WordPress"],
  [/drupal/i, "Drupal"],
  [/joomla/i, "Joomla"],
  [/ghost/i, "Ghost"],
  [/hugo/i, "Hugo"],
  [/jekyll/i, "Jekyll"],
  [/hexo/i, "Hexo"],
  [/gatsby/i, "Gatsby"],
  [/next\.js/i, "Next.js"],
  [/nuxt/i, "Nuxt.js"],
  [/wix\.com/i, "Wix"],
  [/squarespace/i, "Squarespace"],
  [/weebly/i, "Weebly"],
  [/blogger/i, "Blogger"],
  [/medium/i, "Medium"],
  [/typo3/i, "TYPO3"],
  [/contentful/i, "Contentful"],
];

/* ─── SUBDOMAINS (crt.sh) ─── */
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
          const trimmed = sub.trim().toLowerCase();
          if (trimmed && trimmed.includes(domain) && !trimmed.startsWith("*")) {
            subdomains.add(trimmed);
          }
        }
      }
      const sorted = Array.from(subdomains).sort();
      return { source: "crt.sh", status: "success", data: sorted };
    }
    return { source: "crt.sh", status: "failed", error: `HTTP ${resp.status}` };
  } catch (e: unknown) {
    return { source: "crt.sh", status: "error", error: String(e) };
  }
}

/* ─── WAYBACK MACHINE ─── */
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

/* ─── DNS (A, MX, NS, TXT) ─── */
async function queryDns(domain: string) {
  const result: Record<string, unknown> = { source: "dns", status: "success" };
  try {
    const [a, mx, ns, txt] = await Promise.allSettled([
      dns.resolve4(domain),
      dns.resolveMx(domain),
      dns.resolveNs(domain),
      dns.resolveTxt(domain),
    ]);
    if (a.status === "fulfilled") result.ip = a.value[0];
    if (a.status === "fulfilled" && a.value.length > 1) result.all_ips = a.value;
    if (mx.status === "fulfilled")
      result.mx = mx.value
        .sort((x, y) => x.priority - y.priority)
        .map((r) => `${r.priority} ${r.exchange}`);
    if (ns.status === "fulfilled") result.ns = ns.value;
    if (txt.status === "fulfilled")
      result.txt = txt.value.map((t) => t.join("")).slice(0, 10);

    if (!result.ip) {
      result.status = "partial";
      result.error = "Could not resolve A record";
    }
  } catch (e: unknown) {
    result.status = "error";
    result.error = String(e);
  }
  return result;
}

/* ─── TECHNOLOGIES (HTTP fingerprinting + HTML analysis) ─── */
async function queryTechnologies(domain: string) {
  const techs: { name: string; category: string; confidence: string }[] = [];
  const seen = new Set<string>();

  function addTech(name: string, category: string, confidence: string) {
    if (!seen.has(name.toLowerCase())) {
      seen.add(name.toLowerCase());
      techs.push({ name, category, confidence });
    }
  }

  try {
    const resp = await fetch(`https://${domain}`, {
      signal: AbortSignal.timeout(12000),
      redirect: "follow",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    // ── Analyze HTTP headers ──
    for (const [headerKey, signatures] of Object.entries(HEADER_SIGNATURES)) {
      const val = resp.headers.get(headerKey);
      if (val) {
        for (const [pattern, techName] of Object.entries(signatures)) {
          if (val.toLowerCase().includes(pattern)) {
            addTech(techName, headerKey === "server" ? "Web Server" : "Framework", "high");
          }
        }
      }
    }

    // Server header raw
    const server = resp.headers.get("server");
    if (server && techs.filter((t) => t.category === "Web Server").length === 0) {
      addTech(server, "Web Server", "high");
    }

    // X-Powered-By raw
    const xpb = resp.headers.get("x-powered-by");
    if (xpb) addTech(xpb, "Framework", "high");

    // Detect via specific headers
    if (resp.headers.get("x-drupal-cache")) addTech("Drupal", "CMS", "high");
    if (resp.headers.get("x-generator")?.toLowerCase().includes("drupal"))
      addTech("Drupal", "CMS", "high");
    if (resp.headers.get("x-generator")?.toLowerCase().includes("wordpress"))
      addTech("WordPress", "CMS", "high");
    if (resp.headers.get("x-shopify-stage")) addTech("Shopify", "E-Commerce", "high");
    if (resp.headers.get("x-wix-request-id")) addTech("Wix", "CMS", "high");
    if (resp.headers.get("x-vercel-id")) addTech("Vercel", "Hosting", "high");
    if (resp.headers.get("x-netlify-request-id")) addTech("Netlify", "Hosting", "high");
    if (resp.headers.get("cf-ray")) addTech("Cloudflare", "CDN / Security", "high");
    if (resp.headers.get("x-amz-cf-id")) addTech("Amazon CloudFront", "CDN", "high");
    if (resp.headers.get("x-cache")?.includes("cloudfront"))
      addTech("Amazon CloudFront", "CDN", "high");
    if (resp.headers.get("x-fastly-request-id")) addTech("Fastly", "CDN", "high");
    if (resp.headers.get("fly-request-id")) addTech("Fly.io", "Hosting", "high");
    if (resp.headers.get("x-github-request-id")) addTech("GitHub Pages", "Hosting", "high");

    // TLS / Protocol
    addTech("HTTPS", "Protocol", "high");

    // ── Analyze HTML body ──
    const html = await resp.text();

    // Meta generator tag
    const generatorMatch = html.match(
      /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i
    );
    if (generatorMatch) {
      const gen = generatorMatch[1];
      let matched = false;
      for (const [pattern, name] of META_GENERATOR_MAP) {
        if (pattern.test(gen)) {
          addTech(name, "CMS / Generator", "high");
          matched = true;
          break;
        }
      }
      if (!matched) addTech(gen, "CMS / Generator", "high");
    }

    // HTML pattern matching
    for (const [pattern, name, category] of HTML_PATTERNS) {
      if (pattern.test(html)) {
        addTech(name, category, "medium");
      }
    }

    // Detect programming language hints
    if (resp.headers.get("x-aspnet-version")) addTech("ASP.NET", "Framework", "high");
    const setCookie = resp.headers.get("set-cookie") || "";
    if (setCookie.includes("PHPSESSID")) addTech("PHP", "Language", "high");
    if (setCookie.includes("JSESSIONID")) addTech("Java", "Language", "high");
    if (setCookie.includes("ASP.NET")) addTech("ASP.NET", "Framework", "high");
    if (setCookie.includes("laravel_session")) addTech("Laravel", "PHP Framework", "high");
    if (setCookie.includes("_rails")) addTech("Ruby on Rails", "Web Framework", "high");

    // Sort by confidence
    techs.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 };
      return (order[a.confidence as keyof typeof order] || 2) - (order[b.confidence as keyof typeof order] || 2);
    });

    return {
      source: "http-fingerprint",
      status: techs.length > 0 ? "success" : "no_data",
      data: techs,
      count: techs.length,
    };
  } catch (e: unknown) {
    return { source: "http-fingerprint", status: "error", error: String(e), data: [] };
  }
}

/* ─── SECURITY HEADERS ─── */
async function querySecurityHeaders(domain: string) {
  const checks: { header: string; status: string; value: string; severity: string }[] = [];

  const SECURITY_HEADERS = [
    { name: "Strict-Transport-Security", severity: "high", description: "HSTS" },
    { name: "Content-Security-Policy", severity: "high", description: "CSP" },
    { name: "X-Frame-Options", severity: "medium", description: "Clickjacking Protection" },
    { name: "X-Content-Type-Options", severity: "medium", description: "MIME Sniffing Protection" },
    { name: "X-XSS-Protection", severity: "low", description: "XSS Filter" },
    { name: "Referrer-Policy", severity: "medium", description: "Referrer Policy" },
    { name: "Permissions-Policy", severity: "medium", description: "Permissions Policy" },
    { name: "Cross-Origin-Opener-Policy", severity: "low", description: "COOP" },
    { name: "Cross-Origin-Resource-Policy", severity: "low", description: "CORP" },
    { name: "Cross-Origin-Embedder-Policy", severity: "low", description: "COEP" },
  ];

  try {
    const resp = await fetch(`https://${domain}`, {
      signal: AbortSignal.timeout(10000),
      redirect: "follow",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      },
    });

    let score = 0;
    const total = SECURITY_HEADERS.length;

    for (const hdr of SECURITY_HEADERS) {
      const val = resp.headers.get(hdr.name);
      if (val) {
        score++;
        checks.push({
          header: `${hdr.description} (${hdr.name})`,
          status: "present",
          value: val.length > 120 ? val.substring(0, 120) + "..." : val,
          severity: hdr.severity,
        });
      } else {
        checks.push({
          header: `${hdr.description} (${hdr.name})`,
          status: "missing",
          value: "Not set",
          severity: hdr.severity,
        });
      }
    }

    const grade =
      score >= 8 ? "A" : score >= 6 ? "B" : score >= 4 ? "C" : score >= 2 ? "D" : "F";

    return {
      source: "security-headers",
      status: "success",
      grade,
      score: `${score}/${total}`,
      data: checks,
    };
  } catch (e: unknown) {
    return { source: "security-headers", status: "error", error: String(e), data: [] };
  }
}

/* ─── WHOIS via RDAP (free, no API key) ─── */
async function queryWhois(domain: string) {
  try {
    const tld = domain.split(".").pop() || "";
    const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
    const resp = await fetch(rdapUrl, { signal: AbortSignal.timeout(10000) });
    if (!resp.ok) {
      return { source: "rdap", status: "failed", error: `HTTP ${resp.status}`, data: {} };
    }
    const data = await resp.json();

    const info: Record<string, string> = {};
    info["Domain"] = data.ldhName || domain;
    info["TLD"] = tld.toUpperCase();

    // Status
    if (data.status && Array.isArray(data.status)) {
      info["Status"] = data.status.join(", ");
    }

    // Events (registration, expiration, last update)
    if (data.events && Array.isArray(data.events)) {
      for (const ev of data.events) {
        if (ev.eventAction === "registration")
          info["Registered"] = new Date(ev.eventDate).toLocaleDateString("en-GB");
        if (ev.eventAction === "expiration")
          info["Expires"] = new Date(ev.eventDate).toLocaleDateString("en-GB");
        if (ev.eventAction === "last changed")
          info["Last Updated"] = new Date(ev.eventDate).toLocaleDateString("en-GB");
      }
    }

    // Registrar
    if (data.entities && Array.isArray(data.entities)) {
      for (const entity of data.entities) {
        if (entity.roles && entity.roles.includes("registrar")) {
          const vcard = entity.vcardArray;
          if (vcard && vcard[1]) {
            for (const field of vcard[1]) {
              if (field[0] === "fn") info["Registrar"] = field[3];
            }
          }
        }
      }
    }

    // Nameservers
    if (data.nameservers && Array.isArray(data.nameservers)) {
      info["Nameservers"] = data.nameservers
        .map((ns: { ldhName?: string }) => ns.ldhName || "")
        .filter(Boolean)
        .join(", ");
    }

    return {
      source: "rdap",
      status: Object.keys(info).length > 2 ? "success" : "partial",
      data: info,
    };
  } catch (e: unknown) {
    return { source: "rdap", status: "error", error: String(e), data: {} };
  }
}

/* ─── DOMAIN VALIDATION ─── */
function isValidDomain(domain: string): boolean {
  const pattern = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$/;
  return pattern.test(domain);
}

/* ─── MAIN HANDLER ─── */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const domain = (body.domain || "").trim().toLowerCase();
    const modules: string[] = body.modules || [
      "subdomains",
      "technologies",
      "security_headers",
      "whois",
    ];

    if (!domain) {
      return NextResponse.json({ error: "Domain is required" }, { status: 400 });
    }
    if (!isValidDomain(domain)) {
      return NextResponse.json({ error: "Invalid domain format" }, { status: 400 });
    }

    // Run all queries in parallel for speed
    const promises: Promise<[string, unknown]>[] = [];

    // DNS always runs
    promises.push(queryDns(domain).then((r) => ["dns", r]));

    // Subdomains
    if (modules.includes("subdomains")) {
      promises.push(queryCrtsh(domain).then((r) => ["subdomains", r]));
    }

    // Wayback always runs
    promises.push(queryWayback(domain).then((r) => ["wayback", r]));

    // Technologies
    if (modules.includes("technologies")) {
      promises.push(queryTechnologies(domain).then((r) => ["technologies", r]));
    }

    // Security Headers
    if (modules.includes("security_headers")) {
      promises.push(querySecurityHeaders(domain).then((r) => ["security_headers", r]));
    }

    // WHOIS
    if (modules.includes("whois")) {
      promises.push(queryWhois(domain).then((r) => ["whois", r]));
    }

    const settled = await Promise.allSettled(promises);
    const results: Record<string, unknown> = {};
    for (const item of settled) {
      if (item.status === "fulfilled") {
        const [key, value] = item.value;
        results[key] = value;
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
