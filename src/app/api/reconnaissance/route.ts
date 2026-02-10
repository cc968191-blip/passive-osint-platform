import { NextRequest, NextResponse } from "next/server";
import dns from "dns/promises";

export const runtime = "nodejs";
export const maxDuration = 60;

/* ═══════════════════════════════════════════════════════════════════════
   TECHNOLOGY DETECTION — Wappalyzer-level depth
   ═══════════════════════════════════════════════════════════════════════ */

// Patterns matched against individual <script src="..."> URLs
const SCRIPT_SRC_SIGS: [RegExp, string, string][] = [
  [/jquery[.\-/]|jquery\.min\.js|jquery\.slim/i, "jQuery", "JavaScript Library"],
  [/react(?:\.production|\.development|\.min|[\-.]dom)/i, "React", "JavaScript Framework"],
  [/vue(?:\.runtime|\.global|\.esm|\.min)?\.(?:js|mjs)/i, "Vue.js", "JavaScript Framework"],
  [/angular(?:\.min)?\.js|@angular\/core/i, "Angular", "JavaScript Framework"],
  [/svelte(?:\.min)?\.(?:js|mjs)|@sveltejs\//i, "Svelte", "JavaScript Framework"],
  [/ember(?:\.min|\.debug|\.prod)?\.js|emberjs/i, "Ember.js", "JavaScript Framework"],
  [/backbone(?:\.min)?\.js|backbone-/i, "Backbone.js", "JavaScript Framework"],
  [/alpine(?:\.min)?\.js|alpinejs/i, "Alpine.js", "JavaScript Framework"],
  [/htmx(?:\.min)?\.js/i, "htmx", "JavaScript Library"],
  [/lodash|underscore/i, "Lodash/Underscore", "JavaScript Library"],
  [/moment(?:\.min)?\.js|moment-with-locales/i, "Moment.js", "JavaScript Library"],
  [/axios(?:\.min)?\.js/i, "Axios", "JavaScript Library"],
  [/gsap|TweenMax|TweenLite/i, "GSAP", "Animation"],
  [/three(?:\.min)?\.js/i, "Three.js", "3D Library"],
  [/chart\.js|chartjs/i, "Chart.js", "Charting"],
  [/d3(?:\.min)?\.js|d3js/i, "D3.js", "Data Visualization"],
  [/highcharts/i, "Highcharts", "Charting"],
  [/bootstrap(?:\.bundle)?(?:\.min)?\.js/i, "Bootstrap", "CSS Framework"],
  [/popper(?:\.min)?\.js|@popperjs/i, "Popper.js", "UI Library"],
  [/material[\-.]ui|@mui/i, "Material UI", "UI Framework"],
  [/ant[\-.]design|antd/i, "Ant Design", "UI Framework"],
  [/chakra[\-.]ui/i, "Chakra UI", "UI Framework"],
  [/tailwindcss|tailwind/i, "Tailwind CSS", "CSS Framework"],
  [/font[\-.]?awesome|fontawesome/i, "Font Awesome", "Icon Library"],
  [/lucide/i, "Lucide Icons", "Icon Library"],
  [/heroicons/i, "Heroicons", "Icon Library"],
  [/google[\-.]?analytics|gtag\.js|ga\.js|analytics\.js/i, "Google Analytics", "Analytics"],
  [/googletagmanager\.com\/gtm/i, "Google Tag Manager", "Tag Manager"],
  [/gtag.*\/js\?id=G-/i, "Google Analytics 4", "Analytics"],
  [/gtag.*\/js\?id=UA-/i, "Google Analytics (Universal)", "Analytics"],
  [/hotjar/i, "Hotjar", "Analytics"],
  [/clarity\.ms/i, "Microsoft Clarity", "Analytics"],
  [/plausible/i, "Plausible Analytics", "Analytics"],
  [/matomo|piwik/i, "Matomo", "Analytics"],
  [/segment\.com|segment\.io|analytics\.min\.js/i, "Segment", "Analytics"],
  [/mixpanel/i, "Mixpanel", "Analytics"],
  [/amplitude(?:\.min)?\.js|cdn\.amplitude\.com|amplitude-js/i, "Amplitude", "Analytics"],
  [/sentry(?:\.min)?\.js|@sentry\//i, "Sentry", "Error Tracking"],
  [/bugsnag(?:\.min)?\.js|@bugsnag\//i, "Bugsnag", "Error Tracking"],
  [/datadog(?:-rum|-logs)?/i, "Datadog", "Monitoring"],
  [/newrelic|nr-/i, "New Relic", "Monitoring"],
  [/recaptcha/i, "reCAPTCHA", "Security"],
  [/hcaptcha/i, "hCaptcha", "Security"],
  [/turnstile/i, "Cloudflare Turnstile", "Security"],
  [/stripe\.com|stripe\.js|js\.stripe/i, "Stripe", "Payment"],
  [/paypal/i, "PayPal", "Payment"],
  [/adsbygoogle|pagead/i, "Google AdSense", "Advertising"],
  [/fbevents|facebook.*pixel|connect\.facebook/i, "Facebook Pixel", "Marketing"],
  [/snap\.licdn|linkedin.*insight/i, "LinkedIn Insight", "Marketing"],
  [/twitter.*uwt|platform\.twitter/i, "Twitter Pixel", "Marketing"],
  [/analytics\.tiktok\.com|tiktok.*pixel/i, "TikTok Pixel", "Marketing"],
  [/crisp\.chat/i, "Crisp", "Live Chat"],
  [/intercom/i, "Intercom", "Live Chat"],
  [/tawk\.to/i, "Tawk.to", "Live Chat"],
  [/drift\.com|driftt\.com|js\.driftt/i, "Drift", "Live Chat"],
  [/zendesk/i, "Zendesk", "Customer Support"],
  [/hubspot/i, "HubSpot", "Marketing"],
  [/mailchimp/i, "Mailchimp", "Email Marketing"],
  [/wp-content|wp-includes/i, "WordPress", "CMS"],
  [/shopify/i, "Shopify", "E-Commerce"],
  [/wix\.com|parastorage/i, "Wix", "CMS"],
  [/squarespace/i, "Squarespace", "CMS"],
  [/webflow/i, "Webflow", "CMS"],
  [/ghost\.io|ghost\.org/i, "Ghost", "CMS"],
  [/contentful/i, "Contentful", "Headless CMS"],
  [/sanity\.io/i, "Sanity", "Headless CMS"],
  [/prismic/i, "Prismic", "Headless CMS"],
  [/strapi/i, "Strapi", "Headless CMS"],
  [/webpack(?:\.min)?\.js|webpackJsonp|__webpack_/i, "Webpack", "Build Tool"],
  [/parcel(?:\.min)?\.js|parceljs/i, "Parcel", "Build Tool"],
  [/unpkg\.com/i, "unpkg", "CDN"],
  [/cdnjs\.cloudflare\.com/i, "cdnjs", "CDN"],
  [/jsdelivr\.net/i, "jsDelivr", "CDN"],
  [/cloudflare\.com\/ajax|cloudflare-static/i, "Cloudflare", "CDN"],
  [/akamai/i, "Akamai", "CDN"],
  [/fastly/i, "Fastly", "CDN"],
  [/googleapis\.com/i, "Google APIs", "Cloud"],
  [/gstatic\.com/i, "Google Static", "CDN"],
  [/amazonaws\.com/i, "Amazon AWS", "Cloud"],
  [/firebase/i, "Firebase", "Backend"],
  [/supabase/i, "Supabase", "Backend"],
  [/socket\.io/i, "Socket.IO", "Real-time"],
  [/pusher/i, "Pusher", "Real-time"],
  [/lazysizes/i, "lazysizes", "Performance"],
  [/swiper/i, "Swiper", "UI Library"],
  [/slick(?:\.min)?\.js|slick-carousel/i, "Slick Carousel", "UI Library"],
  [/lottie/i, "Lottie", "Animation"],
  [/framer[\-.]motion/i, "Framer Motion", "Animation"],
  [/aos\.js|aos\.css/i, "AOS", "Animation"],
  [/wow\.js|wowjs/i, "WOW.js", "Animation"],
  [/prism(?:\.min)?\.js|prismjs/i, "Prism.js", "Syntax Highlighting"],
  [/highlight\.js|hljs/i, "Highlight.js", "Syntax Highlighting"],
];

// Patterns matched against individual <link href="..."> URLs
const LINK_HREF_SIGS: [RegExp, string, string][] = [
  [/bootstrap(?:\.min)?\.css/i, "Bootstrap", "CSS Framework"],
  [/tailwind/i, "Tailwind CSS", "CSS Framework"],
  [/bulma/i, "Bulma", "CSS Framework"],
  [/foundation(?:\.min)?\.css|foundation-sites/i, "Foundation", "CSS Framework"],
  [/materialize/i, "Materialize CSS", "CSS Framework"],
  [/semantic(?:\.min)?\.css|semantic-ui/i, "Semantic UI", "CSS Framework"],
  [/font[\-.]?awesome|fontawesome/i, "Font Awesome", "Icon Library"],
  [/material[\-.]?icons/i, "Material Icons", "Icon Library"],
  [/animate(?:\.min)?\.css/i, "Animate.css", "Animation"],
  [/normalize(?:\.min)?\.css/i, "Normalize.css", "CSS Reset"],
  [/fonts\.googleapis\.com/i, "Google Fonts", "Font Service"],
  [/fonts\.gstatic\.com/i, "Google Fonts", "Font Service"],
  [/use\.typekit\.net/i, "Adobe Fonts", "Font Service"],
  [/wp-content|wp-includes/i, "WordPress", "CMS"],
];

// Patterns matched against full HTML body
const HTML_BODY_SIGS: [RegExp, string, string][] = [
  // CMS
  [/wp-content\/|wp-includes\/|wp-json\//i, "WordPress", "CMS"],
  [/sites\/default\/files|Drupal\.settings/i, "Drupal", "CMS"],
  [/\/media\/jui\/|com_content/i, "Joomla", "CMS"],
  [/cdn\.shopify\.com|Shopify\.theme/i, "Shopify", "E-Commerce"],
  [/woocommerce/i, "WooCommerce", "E-Commerce"],
  [/static\d*\.squarespace\.com/i, "Squarespace", "CMS"],
  [/parastorage\.com|wix-code/i, "Wix", "CMS"],
  [/webflow\.com|w-webflow/i, "Webflow", "CMS"],
  // Frameworks — structural patterns
  [/_next\/static|__next|__NEXT_DATA__/i, "Next.js", "JavaScript Framework"],
  [/_nuxt\/|__NUXT__|nuxt-link/i, "Nuxt.js", "JavaScript Framework"],
  [/ng-version=|ng-app=|angular\.(?:min\.)?js/i, "Angular", "JavaScript Framework"],
  [/data-reactroot|__REACT|react-root|reactjs/i, "React", "JavaScript Framework"],
  [/data-v-[a-f0-9]|Vue\.config|v-cloak/i, "Vue.js", "JavaScript Framework"],
  [/svelte-[a-z]|__svelte/i, "Svelte", "JavaScript Framework"],
  [/gatsby-/i, "Gatsby", "Static Site Generator"],
  [/data-astro|astro-island/i, "Astro", "Static Site Generator"],
  [/remix-run|__remix/i, "Remix", "JavaScript Framework"],
  // Hosting
  [/vercel\.app|vercel-insights|__vercel/i, "Vercel", "Hosting"],
  [/netlify\.app|netlify-identity|netlify\.com/i, "Netlify", "Hosting"],
  [/herokuapp\.com/i, "Heroku", "Hosting"],
  [/github\.io/i, "GitHub Pages", "Hosting"],
  [/render\.com/i, "Render", "Hosting"],
  [/railway\.app/i, "Railway", "Hosting"],
  // Misc
  [/data-turbo|turbolinks\.js|@hotwired\/turbo/i, "Turbo/Turbolinks", "JavaScript Library"],
  [/stimulus(?:\.min)?\.js|@hotwired\/stimulus/i, "Stimulus", "JavaScript Framework"],
  [/livewire/i, "Laravel Livewire", "PHP Framework"],
  [/blazor/i, "Blazor", "Web Framework"],
];

// Header-based detection
const HEADER_FINGERPRINTS: [string, string | null, string, string][] = [
  // [header_name, value_pattern_or_null, tech_name, category]
  ["server", "nginx", "Nginx", "Web Server"],
  ["server", "apache", "Apache", "Web Server"],
  ["server", "cloudflare", "Cloudflare", "Web Server / CDN"],
  ["server", "microsoft-iis", "Microsoft IIS", "Web Server"],
  ["server", "litespeed", "LiteSpeed", "Web Server"],
  ["server", "openresty", "OpenResty", "Web Server"],
  ["server", "gunicorn", "Gunicorn", "Web Server"],
  ["server", "caddy", "Caddy", "Web Server"],
  ["server", "envoy", "Envoy", "Web Server / Proxy"],
  ["server", "cowboy", "Cowboy (Erlang)", "Web Server"],
  ["server", "deno", "Deno", "Runtime"],
  ["server", "vercel", "Vercel", "Hosting"],
  ["server", "netlify", "Netlify", "Hosting"],
  ["x-powered-by", "express", "Express.js", "Web Framework"],
  ["x-powered-by", "asp.net", "ASP.NET", "Web Framework"],
  ["x-powered-by", "php", "PHP", "Language"],
  ["x-powered-by", "next.js", "Next.js", "JavaScript Framework"],
  ["x-powered-by", "nuxt", "Nuxt.js", "JavaScript Framework"],
  ["x-powered-by", "django", "Django", "Web Framework"],
  ["x-powered-by", "flask", "Flask", "Web Framework"],
  ["x-powered-by", "rails", "Ruby on Rails", "Web Framework"],
  ["x-powered-by", "wp engine", "WP Engine", "Managed Hosting"],
  ["x-powered-by", "plesk", "Plesk", "Hosting Panel"],
  ["x-powered-by", "craft cms", "Craft CMS", "CMS"],
  // Presence-only headers (value_pattern = null)
  ["x-vercel-id", null, "Vercel", "Hosting"],
  ["x-vercel-cache", null, "Vercel", "Hosting"],
  ["x-netlify-request-id", null, "Netlify", "Hosting"],
  ["cf-ray", null, "Cloudflare", "CDN / Security"],
  ["cf-cache-status", null, "Cloudflare", "CDN / Security"],
  ["x-amz-cf-id", null, "Amazon CloudFront", "CDN"],
  ["x-amz-cf-pop", null, "Amazon CloudFront", "CDN"],
  ["x-fastly-request-id", null, "Fastly", "CDN"],
  ["fly-request-id", null, "Fly.io", "Hosting"],
  ["x-github-request-id", null, "GitHub Pages", "Hosting"],
  ["x-shopify-stage", null, "Shopify", "E-Commerce"],
  ["x-wix-request-id", null, "Wix", "CMS"],
  ["x-drupal-cache", null, "Drupal", "CMS"],
  ["x-aspnet-version", null, "ASP.NET", "Web Framework"],
  ["x-page-speed", null, "Google PageSpeed", "Performance"],
  ["x-turbo-charged-by", null, "LiteSpeed", "Web Server"],
  ["x-sucuri-id", null, "Sucuri", "Security / WAF"],
  ["x-kinsta-cache", null, "Kinsta", "Managed Hosting"],
  ["x-cache-hits", null, "Varnish", "Caching"],
  ["x-varnish", null, "Varnish", "Caching"],
  ["x-fw-hash", null, "Flywheel", "Managed Hosting"],
  ["x-pantheon-styx-hostname", null, "Pantheon", "Managed Hosting"],
  ["x-nf-request-id", null, "Netlify", "Hosting"],
];

// Cookie-based detection
const COOKIE_SIGS: [RegExp, string, string][] = [
  [/PHPSESSID/i, "PHP", "Language"],
  [/JSESSIONID/i, "Java", "Language"],
  [/ASP\.NET/i, "ASP.NET", "Web Framework"],
  [/laravel_session/i, "Laravel", "PHP Framework"],
  [/_rails|_session_id.*rack/i, "Ruby on Rails", "Web Framework"],
  [/connect\.sid/i, "Express.js", "Web Framework"],
  [/django_?session|csrftoken.*django|sessionid.*django/i, "Django", "Web Framework"],
  [/flask_?session|session=\.[a-zA-Z0-9]/i, "Flask", "Web Framework"],
  [/ci_session/i, "CodeIgniter", "PHP Framework"],
  [/CAKEPHP/i, "CakePHP", "PHP Framework"],
  [/wordpress_logged_in|wp-settings/i, "WordPress", "CMS"],
  [/PrestaShop/i, "PrestaShop", "E-Commerce"],
  [/Magento|PHPSESSID.*frontend/i, "Magento", "E-Commerce"],
  [/shopify/i, "Shopify", "E-Commerce"],
  [/_gh_sess/i, "GitHub", "Platform"],
  [/cf_clearance|__cf_bm/i, "Cloudflare", "CDN / Security"],
  [/incap_ses|visid_incap/i, "Imperva/Incapsula", "Security / WAF"],
];

/* ═══════════════════════════════════════════════════════════════════════
   FETCH HELPER — single fetch reused by technologies + security headers
   ═══════════════════════════════════════════════════════════════════════ */
async function fetchSite(domain: string) {
  const resp = await fetch(`https://${domain}`, {
    signal: AbortSignal.timeout(15000),
    redirect: "follow",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
      Accept:
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "identity",
    },
  });
  const html = await resp.text();
  return { resp, html };
}

/* ═══════════════════════════════════════════════════════════════════════
   SUBDOMAINS — crt.sh with retry + HackerTarget fallback
   ═══════════════════════════════════════════════════════════════════════ */
async function queryCrtsh(domain: string): Promise<string[]> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const resp = await fetch(
        `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
        { signal: AbortSignal.timeout(12000) }
      );
      if (resp.ok) {
        const data = await resp.json();
        const subs = new Set<string>();
        for (const entry of data) {
          for (const name of (entry.name_value || "").split("\n")) {
            const t = name.trim().toLowerCase();
            if (t && t.includes(domain) && !t.startsWith("*")) subs.add(t);
          }
        }
        return Array.from(subs);
      }
    } catch { /* retry */ }
  }
  return [];
}

async function queryHackerTarget(domain: string): Promise<string[]> {
  try {
    const resp = await fetch(
      `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
      { signal: AbortSignal.timeout(10000) }
    );
    if (resp.ok) {
      const text = await resp.text();
      if (text.startsWith("error") || text.includes("API count exceeded")) return [];
      const subs = new Set<string>();
      for (const line of text.split("\n")) {
        const host = line.split(",")[0]?.trim().toLowerCase();
        if (host && host.includes(domain)) subs.add(host);
      }
      return Array.from(subs);
    }
  } catch { /* ignore */ }
  return [];
}

async function querySubdomains(domain: string) {
  try {
    const [crt, ht] = await Promise.allSettled([
      queryCrtsh(domain),
      queryHackerTarget(domain),
    ]);
    const all = new Set<string>();
    if (crt.status === "fulfilled") crt.value.forEach((s) => all.add(s));
    if (ht.status === "fulfilled") ht.value.forEach((s) => all.add(s));
    const sorted = Array.from(all).sort();
    const sources: string[] = [];
    if (crt.status === "fulfilled" && crt.value.length > 0) sources.push("crt.sh");
    if (ht.status === "fulfilled" && ht.value.length > 0) sources.push("hackertarget");
    return {
      source: sources.join(" + ") || "crt.sh + hackertarget",
      status: sorted.length > 0 ? "success" : "no_data",
      data: sorted,
    };
  } catch (e: unknown) {
    return { source: "crt.sh + hackertarget", status: "error", error: String(e), data: [] };
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   WAYBACK MACHINE
   ═══════════════════════════════════════════════════════════════════════ */
async function queryWayback(domain: string) {
  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}&output=text&fl=original&collapse=urlkey&limit=50`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(20000) });
    if (resp.ok) {
      const text = await resp.text();
      const lines = text.trim().split("\n").filter(Boolean);
      const unique = Array.from(new Set(lines)).slice(0, 30);
      if (unique.length > 0) return { source: "wayback", status: "success", data: unique };
      return { source: "wayback", status: "no_data", data: [] };
    }
    return { source: "wayback", status: "failed", error: `HTTP ${resp.status}` };
  } catch (e: unknown) {
    return { source: "wayback", status: "error", error: String(e) };
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   DNS — A, AAAA, MX, NS, TXT, CNAME, SOA
   ═══════════════════════════════════════════════════════════════════════ */
async function queryDns(domain: string) {
  const result: Record<string, unknown> = { source: "dns", status: "success" };
  try {
    const [a, aaaa, mx, ns, txt, cname, soa] = await Promise.allSettled([
      dns.resolve4(domain),
      dns.resolve6(domain),
      dns.resolveMx(domain),
      dns.resolveNs(domain),
      dns.resolveTxt(domain),
      dns.resolveCname(domain),
      dns.resolveSoa(domain),
    ]);
    if (a.status === "fulfilled" && a.value.length) {
      result.ip = a.value[0];
      if (a.value.length > 1) result.all_ips = a.value;
    }
    if (aaaa.status === "fulfilled" && aaaa.value.length) result.ipv6 = aaaa.value;
    if (mx.status === "fulfilled" && mx.value.length)
      result.mx = mx.value.sort((x, y) => x.priority - y.priority).map((r) => `${r.priority} ${r.exchange}`);
    if (ns.status === "fulfilled" && ns.value.length) result.ns = ns.value;
    if (txt.status === "fulfilled" && txt.value.length)
      result.txt = txt.value.map((t) => t.join("")).slice(0, 15);
    if (cname.status === "fulfilled" && cname.value.length) result.cname = cname.value;
    if (soa.status === "fulfilled") {
      const s = soa.value;
      result.soa = `${s.nsname} ${s.hostmaster} (serial: ${s.serial})`;
    }
    if (!result.ip) { result.status = "partial"; result.error = "Could not resolve A record"; }
  } catch (e: unknown) {
    result.status = "error";
    result.error = String(e);
  }
  return result;
}

/* ═══════════════════════════════════════════════════════════════════════
   TECHNOLOGIES — deep HTTP + HTML fingerprinting
   ═══════════════════════════════════════════════════════════════════════ */
async function queryTechnologies(domain: string, siteData?: { resp: Response; html: string }) {
  const techs: { name: string; category: string; confidence: string }[] = [];
  const seen = new Set<string>();
  const add = (name: string, category: string, confidence: string) => {
    const key = name.toLowerCase();
    if (!seen.has(key)) { seen.add(key); techs.push({ name, category, confidence }); }
  };

  try {
    const { resp, html } = siteData || (await fetchSite(domain));

    // ── 1. Header fingerprinting ──
    for (const [hdr, pattern, techName, category] of HEADER_FINGERPRINTS) {
      const val = resp.headers.get(hdr);
      if (val) {
        if (pattern === null) {
          add(techName, category, "high");
        } else if (val.toLowerCase().includes(pattern)) {
          add(techName, category, "high");
        }
      }
    }

    // Raw server header if no match
    const serverHdr = resp.headers.get("server");
    if (serverHdr && !techs.some((t) => t.category.includes("Web Server"))) {
      add(serverHdr, "Web Server", "high");
    }

    // Raw x-powered-by if no match
    const xpb = resp.headers.get("x-powered-by");
    if (xpb && !seen.has(xpb.toLowerCase())) add(xpb, "Framework", "high");

    // X-Generator header
    const xgen = resp.headers.get("x-generator");
    if (xgen) add(xgen, "CMS / Generator", "high");

    // ── 2. Cookie fingerprinting ──
    const cookies = resp.headers.get("set-cookie") || "";
    for (const [pattern, techName, category] of COOKIE_SIGS) {
      if (pattern.test(cookies)) add(techName, category, "high");
    }

    // ── 3. Extract & analyze all <script src="..."> ──
    const scriptSrcs: string[] = [];
    const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    let m;
    while ((m = scriptRegex.exec(html)) !== null) scriptSrcs.push(m[1]);
    for (const src of scriptSrcs) {
      for (const [pattern, techName, category] of SCRIPT_SRC_SIGS) {
        if (pattern.test(src)) { add(techName, category, "high"); break; }
      }
    }

    // ── 4. Extract & analyze all <link href="..."> ──
    const linkHrefs: string[] = [];
    const linkRegex = /<link[^>]+href=["']([^"']+)["']/gi;
    while ((m = linkRegex.exec(html)) !== null) linkHrefs.push(m[1]);
    for (const href of linkHrefs) {
      for (const [pattern, techName, category] of LINK_HREF_SIGS) {
        if (pattern.test(href)) { add(techName, category, "high"); break; }
      }
    }

    // ── 5. Meta generator ──
    const genMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i);
    if (genMatch) add(genMatch[1], "CMS / Generator", "high");

    // ── 6. HTML body structural patterns ──
    for (const [pattern, techName, category] of HTML_BODY_SIGS) {
      if (pattern.test(html)) add(techName, category, "medium");
    }

    // ── 7. Inline script analysis ──
    const inlineScripts: string[] = [];
    const inlineRegex = /<script(?:\s[^>]*)?>([^<]{10,})<\/script>/gi;
    while ((m = inlineRegex.exec(html)) !== null) inlineScripts.push(m[1]);
    const inlineAll = inlineScripts.join(" ");
    if (/React(?:DOM)?\.(?:render|createRoot|hydrate)/i.test(inlineAll)) add("React", "JavaScript Framework", "high");
    if (/Vue\s*\(\s*\{|createApp|new Vue/i.test(inlineAll)) add("Vue.js", "JavaScript Framework", "high");
    if (/angular\.module|ng\.core/i.test(inlineAll)) add("Angular", "JavaScript Framework", "high");
    if (/gatsby-browser|gatsby-ssr|__gatsby/i.test(inlineAll)) add("Gatsby", "Static Site Generator", "medium");
    if (/window\.__NEXT_DATA__|__next/i.test(inlineAll)) add("Next.js", "JavaScript Framework", "high");
    if (/window\.__NUXT__|__nuxt/i.test(inlineAll)) add("Nuxt.js", "JavaScript Framework", "high");
    if (/gtag\s*\(\s*['"]config['"]/i.test(inlineAll)) add("Google Analytics", "Analytics", "high");
    if (/fbq\s*\(/i.test(inlineAll)) add("Facebook Pixel", "Marketing", "high");
    if (/twq\s*\(/i.test(inlineAll)) add("Twitter Pixel", "Marketing", "medium");
    if (/ttq\s*\(/i.test(inlineAll)) add("TikTok Pixel", "Marketing", "medium");
    if (/Shopify\./i.test(inlineAll)) add("Shopify", "E-Commerce", "high");
    if (/woocommerce/i.test(inlineAll)) add("WooCommerce", "E-Commerce", "high");

    // ── 8. Protocol ──
    add("HTTPS / TLS", "Security", "high");

    // ── 9. Detect HTTP/2 or HTTP/3 via alt-svc ──
    const altSvc = resp.headers.get("alt-svc");
    if (altSvc) {
      if (altSvc.includes("h3")) add("HTTP/3", "Protocol", "high");
      else if (altSvc.includes("h2")) add("HTTP/2", "Protocol", "high");
    }

    // Sort: high confidence first
    techs.sort((a, b) => {
      const o: Record<string, number> = { high: 0, medium: 1, low: 2 };
      return (o[a.confidence] ?? 2) - (o[b.confidence] ?? 2);
    });

    return {
      source: "http-fingerprint + html-analysis",
      status: techs.length > 0 ? "success" : "no_data",
      data: techs,
      count: techs.length,
    };
  } catch (e: unknown) {
    return { source: "http-fingerprint", status: "error", error: String(e), data: [] };
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   SECURITY HEADERS
   ═══════════════════════════════════════════════════════════════════════ */
async function querySecurityHeaders(domain: string, siteData?: { resp: Response; html: string }) {
  const checks: { header: string; status: string; value: string; severity: string }[] = [];
  const SECURITY_HEADERS = [
    { name: "Strict-Transport-Security", severity: "high", description: "HSTS" },
    { name: "Content-Security-Policy", severity: "high", description: "CSP" },
    { name: "X-Frame-Options", severity: "medium", description: "Clickjacking Protection" },
    { name: "X-Content-Type-Options", severity: "medium", description: "MIME Sniffing Protection" },
    { name: "X-XSS-Protection", severity: "low", description: "XSS Filter (Legacy)" },
    { name: "Referrer-Policy", severity: "medium", description: "Referrer Policy" },
    { name: "Permissions-Policy", severity: "medium", description: "Permissions Policy" },
    { name: "Cross-Origin-Opener-Policy", severity: "low", description: "COOP" },
    { name: "Cross-Origin-Resource-Policy", severity: "low", description: "CORP" },
    { name: "Cross-Origin-Embedder-Policy", severity: "low", description: "COEP" },
  ];
  try {
    const { resp } = siteData ? { resp: siteData.resp } : await fetchSite(domain);
    let score = 0;
    const total = SECURITY_HEADERS.length;
    for (const hdr of SECURITY_HEADERS) {
      const val = resp.headers.get(hdr.name);
      if (val) {
        score++;
        checks.push({
          header: `${hdr.description} (${hdr.name})`,
          status: "present",
          value: val.length > 150 ? val.substring(0, 150) + "…" : val,
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
    const grade = score >= 8 ? "A" : score >= 6 ? "B" : score >= 4 ? "C" : score >= 2 ? "D" : "F";
    return { source: "security-headers", status: "success", grade, score: `${score}/${total}`, data: checks };
  } catch (e: unknown) {
    return { source: "security-headers", status: "error", error: String(e), data: [] };
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   WHOIS — IANA RDAP bootstrap (finds correct server per TLD)
   ═══════════════════════════════════════════════════════════════════════ */
async function findRdapServer(domain: string): Promise<string | null> {
  const tld = domain.split(".").pop()?.toLowerCase() || "";
  // Try IANA bootstrap
  try {
    const resp = await fetch("https://data.iana.org/rdap/dns.json", {
      signal: AbortSignal.timeout(5000),
    });
    if (resp.ok) {
      const data = await resp.json();
      for (const service of data.services || []) {
        const tlds: string[] = service[0] || [];
        const urls: string[] = service[1] || [];
        if (tlds.some((t: string) => t.toLowerCase() === tld) && urls.length > 0) {
          let base = urls[0];
          if (!base.endsWith("/")) base += "/";
          return `${base}domain/${domain}`;
        }
      }
    }
  } catch { /* fallback below */ }
  // Known RDAP servers for common TLDs
  const known: Record<string, string> = {
    com: "https://rdap.verisign.com/com/v1/domain/",
    net: "https://rdap.verisign.com/net/v1/domain/",
    org: "https://rdap.org/domain/",
    io: "https://rdap.nic.io/domain/",
    dev: "https://rdap.nic.google/domain/",
    app: "https://rdap.nic.google/domain/",
    me: "https://rdap.nic.me/domain/",
    co: "https://rdap.nic.co/domain/",
    info: "https://rdap.afilias.net/rdap/info/domain/",
    xyz: "https://rdap.nic.xyz/domain/",
    ai: "https://rdap.nic.ai/domain/",
    fr: "https://rdap.nic.fr/domain/",
    de: "https://rdap.denic.de/domain/",
    uk: "https://rdap.nominet.uk/uk/domain/",
    eu: "https://rdap.eu/domain/",
    nl: "https://rdap.sidn.nl/domain/",
    ca: "https://rdap.ca.fury.ca/rdap/domain/",
    au: "https://rdap.auda.org.au/domain/",
    ru: "https://rdap.ripn.net/domain/",
    br: "https://rdap.registro.br/domain/",
    in: "https://rdap.registry.in/domain/",
    jp: "https://rdap.jprs.jp/domain/",
  };
  if (known[tld]) return `${known[tld]}${domain}`;
  return null;
}

async function queryWhois(domain: string) {
  try {
    const rdapUrl = await findRdapServer(domain);
    if (!rdapUrl) {
      return { source: "rdap", status: "failed", error: `No RDAP server found for TLD .${domain.split(".").pop()}`, data: {} };
    }
    const resp = await fetch(rdapUrl, {
      signal: AbortSignal.timeout(10000),
      headers: { Accept: "application/rdap+json, application/json" },
    });
    if (!resp.ok) {
      // Fallback: try rdap.org
      const fallback = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        signal: AbortSignal.timeout(8000),
        headers: { Accept: "application/rdap+json, application/json" },
      });
      if (!fallback.ok) return { source: "rdap", status: "failed", error: `HTTP ${resp.status} (primary) + HTTP ${fallback.status} (fallback)`, data: {} };
      return parseRdap(await fallback.json(), domain);
    }
    return parseRdap(await resp.json(), domain);
  } catch (e: unknown) {
    return { source: "rdap", status: "error", error: String(e), data: {} };
  }
}

function parseRdap(data: Record<string, unknown>, domain: string) {
  const info: Record<string, string> = {};
  info["Domain"] = (data.ldhName as string) || domain;
  const tld = domain.split(".").pop() || "";
  info["TLD"] = tld.toUpperCase();

  const status = data.status as string[] | undefined;
  if (status?.length) info["Status"] = status.join(", ");

  const events = data.events as { eventAction: string; eventDate: string }[] | undefined;
  if (events?.length) {
    for (const ev of events) {
      const d = new Date(ev.eventDate);
      const fmt = d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
      if (ev.eventAction === "registration") info["Registered"] = fmt;
      if (ev.eventAction === "expiration") info["Expires"] = fmt;
      if (ev.eventAction === "last changed") info["Last Updated"] = fmt;
      if (ev.eventAction === "last update of RDAP database") info["RDAP Updated"] = fmt;
    }
  }

  const entities = data.entities as { roles?: string[]; vcardArray?: unknown[]; handle?: string }[] | undefined;
  if (entities?.length) {
    for (const entity of entities) {
      if (entity.roles?.includes("registrar")) {
        const vcard = entity.vcardArray as unknown[][] | undefined;
        if (vcard?.[1]) {
          for (const field of vcard[1] as unknown[][]) {
            if (field[0] === "fn") info["Registrar"] = String(field[3]);
          }
        }
        if (!info["Registrar"] && entity.handle) info["Registrar"] = entity.handle;
      }
      if (entity.roles?.includes("registrant")) {
        const vcard = entity.vcardArray as unknown[][] | undefined;
        if (vcard?.[1]) {
          for (const field of vcard[1] as unknown[][]) {
            if (field[0] === "fn" && field[3]) info["Registrant"] = String(field[3]);
            if (field[0] === "org" && field[3]) info["Organization"] = String(field[3]);
          }
        }
      }
    }
  }

  const nameservers = data.nameservers as { ldhName?: string }[] | undefined;
  if (nameservers?.length) {
    info["Nameservers"] = nameservers.map((ns) => ns.ldhName || "").filter(Boolean).join(", ");
  }

  // DNSSEC
  const secureDNS = data.secureDNS as { delegationSigned?: boolean } | undefined;
  if (secureDNS) {
    info["DNSSEC"] = secureDNS.delegationSigned ? "Signed" : "Unsigned";
  }

  return {
    source: "rdap",
    status: Object.keys(info).length > 2 ? "success" : "partial",
    data: info,
  };
}

/* ═══════════════════════════════════════════════════════════════════════
   DOMAIN VALIDATION
   ═══════════════════════════════════════════════════════════════════════ */
function isValidDomain(domain: string): boolean {
  return /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$/.test(domain);
}

/* ═══════════════════════════════════════════════════════════════════════
   MAIN HANDLER
   ═══════════════════════════════════════════════════════════════════════ */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const domain = (body.domain || "").trim().toLowerCase();
    const modules: string[] = body.modules || ["subdomains", "technologies", "security_headers", "whois"];

    if (!domain) return NextResponse.json({ error: "Domain is required" }, { status: 400 });
    if (!isValidDomain(domain)) return NextResponse.json({ error: "Invalid domain format" }, { status: 400 });

    const promises: Promise<[string, unknown]>[] = [];

    // DNS always
    promises.push(queryDns(domain).then((r) => ["dns", r]));

    // Subdomains
    if (modules.includes("subdomains")) {
      promises.push(querySubdomains(domain).then((r) => ["subdomains", r]));
    }

    // Wayback always
    promises.push(queryWayback(domain).then((r) => ["wayback", r]));

    // Fetch site once, share between technologies + security headers
    const needsTech = modules.includes("technologies");
    const needsSec = modules.includes("security_headers");
    if (needsTech || needsSec) {
      const sitePromise = fetchSite(domain).catch(() => null);
      promises.push(
        sitePromise.then(async (site) => {
          const results: [string, unknown][] = [];
          if (needsTech) {
            const t = site
              ? await queryTechnologies(domain, site)
              : await queryTechnologies(domain);
            results.push(["technologies", t]);
          }
          if (needsSec) {
            const s = site
              ? await querySecurityHeaders(domain, site)
              : await querySecurityHeaders(domain);
            results.push(["security_headers", s]);
          }
          return results;
        }).then((pairs) => ["__multi__", pairs] as [string, unknown])
      );
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
        if (key === "__multi__") {
          for (const [k, v] of value as [string, unknown][]) results[k] = v;
        } else {
          results[key] = value;
        }
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
