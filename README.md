# Passive OSINT Platform

[![Next.js 15](https://img.shields.io/badge/Next.js-15-black)](https://nextjs.org/)
[![React 19](https://img.shields.io/badge/React-19-blue)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Production-grade passive OSINT reconnaissance platform built with Next.js 15. Performs deep fingerprinting and intelligence gathering from public sources — zero API keys required.

---

## Modules

| Module | Sources | API Key |
|--------|---------|---------|
| **Technologies** | HTTP headers, `<script src>`, `<link href>`, cookies, inline JS, meta tags | No |
| **Security Headers** | HSTS, CSP, X-Frame-Options, Referrer-Policy + 6 more — graded A–F | No |
| **WHOIS / RDAP** | IANA RDAP bootstrap + 22 TLD fallbacks | No |
| **DNS** | A, AAAA, MX, NS, TXT, CNAME, SOA records | No |
| **Subdomains** | crt.sh (Certificate Transparency) + HackerTarget | No |
| **Wayback Machine** | Historical URLs via CDX API | No |

## Quick Start

```bash
git clone https://github.com/cc968191-blip/passive-osint-platform.git
cd passive-osint-platform
npm install
npm run dev          # http://localhost:3000
```

## Architecture

```
src/
├── app/
│   ├── api/
│   │   ├── health/route.ts          Health check
│   │   └── reconnaissance/route.ts  OSINT engine (all modules)
│   ├── globals.css                  Tailwind base styles
│   ├── layout.tsx                   Root layout
│   └── page.tsx                     Dashboard (input → scan → results)
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/reconnaissance` | Execute OSINT modules |

**Example:**

```bash
curl -X POST http://localhost:3000/api/reconnaissance \
  -H "Content-Type: application/json" \
  -d '{"domain":"github.com","modules":["subdomains","technologies","security_headers","whois"]}'
```

## Tech Stack

- **Next.js 15** — App Router, Turbopack dev server
- **React 19** — Server and client components
- **TypeScript 5.7** — Strict mode
- **Tailwind CSS 3.4** — Black & white monospace UI
- **Vercel** — Production deployment

## Deployment

Push to `main` — Vercel auto-deploys.

```bash
npm run build        # Verify build locally
git push origin main # Deploy
```

## Legal

This tool performs **passive reconnaissance only**. No active scanning, exploitation, or direct target interaction. Users are responsible for compliance with applicable laws.

## License

[MIT](LICENSE)
