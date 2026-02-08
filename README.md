# Passive OSINT Platform

[![CI](https://github.com/cc968191-blip/passive-osint-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/cc968191-blip/passive-osint-platform/actions)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Production-grade passive OSINT reconnaissance platform. Aggregates publicly available intelligence from multiple data sources for authorized security assessments — without active scanning or target interaction.

---

## Modules

| Module | Sources | API Key Required |
|--------|---------|-----------------|
| **Subdomains** | crt.sh, Wayback Machine, VirusTotal, SecurityTrails | Optional |
| **Ports** | Shodan, Censys | Yes |
| **Technologies** | HTTP headers, Wappalyzer, TLS certificates | No |
| **Vulnerabilities** | CVE databases, ExploitDB | Optional |
| **Credentials** | Breach aggregators, paste sites | Optional |

## Quick Start

```bash
git clone https://github.com/cc968191-blip/passive-osint-platform.git
cd passive-osint-platform
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env       # then edit SECRET_KEY and API_TOKEN
python app.py              # http://localhost:5000
```

Generate cryptographic keys:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Architecture

```
passive_osint/
├── core/
│   ├── config.py            Configuration management
│   ├── engine.py            Reconnaissance engine
│   └── exceptions.py        Custom exceptions
├── modules/
│   ├── subdomains.py        Certificate Transparency, DNS, Wayback
│   ├── ports.py             Shodan / Censys passive lookups
│   ├── technologies.py      HTTP fingerprinting, TLS analysis
│   ├── vulnerabilities.py   CVE correlation
│   └── credentials.py       Breach data aggregation
├── reports/
│   └── generator.py         JSON / HTML / CSV output
├── utils.py                 Domain validation, async helpers
└── cli.py                   Click-based CLI
```

## REST API

Authenticated endpoints require the `X-API-Token` header.

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/health` | No | Health check |
| `GET` | `/api/status` | No | Platform status and module availability |
| `POST` | `/api/validate-domain` | Yes | RFC-compliant domain validation |
| `POST` | `/api/reconnaissance` | Yes | Execute OSINT modules against a domain |
| `GET` | `/api/config` | Yes | Current platform configuration |

**Example — start reconnaissance:**

```bash
curl -X POST http://localhost:5000/api/reconnaissance \
  -H "Content-Type: application/json" \
  -H "X-API-Token: <token>" \
  -d '{"domain":"example.com","modules":["subdomains","technologies"]}'
```

## Configuration

All settings are loaded from environment variables (`.env`). See [`.env.example`](.env.example) for the full reference.

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask session signing key |
| `API_TOKEN` | Yes | Bearer token for API authentication |
| `CORS_ORIGINS` | Recommended | Comma-separated allowed origins |
| `VIRUSTOTAL_API_KEY` | Optional | Enables VirusTotal module |
| `SHODAN_API_KEY` | Optional | Enables Shodan module |
| `SECURITYTRAILS_API_KEY` | Optional | Enables SecurityTrails module |

## Security

- Token-based API authentication on all sensitive endpoints
- Rate limiting — 100 requests/hour global, 10/min on reconnaissance
- HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- CORS restricted to configured origins
- Strict RFC 1035 domain validation
- No raw exceptions exposed to clients

## Deployment

**Development:**

```bash
FLASK_ENV=development python app.py
```

**Production (Gunicorn):**

```bash
gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
```

**Render:**

The included [`render.yaml`](render.yaml) provides a one-click deploy configuration.

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

## Legal

This tool is designed exclusively for **authorized passive reconnaissance**. It does not perform active scanning, exploitation, or direct interaction with target infrastructure. Users are solely responsible for ensuring compliance with all applicable laws and regulations.

## License

[MIT](LICENSE)
