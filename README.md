# Passive OSINT Platform

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Plateforme OSINT passive open-source avec **vraies sources de données** pour reconnaissance professionnelle.

> **Legal & Ethics:** This platform collects **public passive data only**. Use only with explicit authorization on assets you own or have permission to test.

---

## Features

### 5 OSINT Modules
- **Subdomains** — Certificate Transparency enumeration (crt.sh, Wayback, VirusTotal, SecurityTrails)
- **Ports** — Passive port detection (Shodan, Censys)
- **Technologies** — Tech stack fingerprinting (HTTP headers, Wappalyzer, TLS)
- **Vulnerabilities** — CVE database matching
- **Credentials** — Breach database aggregation

### Security Hardened
- API token authentication (`X-API-Token`) on all sensitive endpoints
- Rate limiting (flask-limiter) — 100/hour global, 10/min on reconnaissance
- HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- CORS restricted to configured origins (no wildcard in production)
- XSS-safe frontend (textContent, no innerHTML)
- No raw exceptions exposed to clients

### Real Data Sources
| Source | API Key | Reliability | Cost |
|--------|---------|-------------|------|
| crt.sh | No | 100% | Free |
| Wayback Machine | No | 95% | Free |
| DNS Direct | No | 100% | Free |
| VirusTotal | Yes | 98% | Free tier |
| Shodan | Yes | 95% | Free tier |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/passive-osint-platform.git
cd passive-osint-platform

# 2. Virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env: set SECRET_KEY and API_TOKEN
# Generate strong keys: python -c "import secrets; print(secrets.token_hex(32))"

# 5. Run
python app.py
# Open http://localhost:5000
```

---

## Architecture

```
passive-osint-platform/
├── passive_osint/
│   ├── core/
│   │   ├── config.py          Configuration management
│   │   ├── engine.py          Reconnaissance engine
│   │   └── exceptions.py      Error handling
│   ├── modules/
│   │   ├── subdomains.py      Subdomain enumeration
│   │   ├── ports.py           Port detection
│   │   ├── technologies.py    Technology stack
│   │   ├── vulnerabilities.py CVE assessment
│   │   └── credentials.py     Credential monitoring
│   ├── reports/
│   │   └── generator.py       Report generation
│   └── cli.py                 Command-line interface
├── templates/
│   └── dashboard.html         Web dashboard
├── app.py                     Flask application
├── config.py                  Flask configuration
├── wsgi.py                    WSGI entry point
├── requirements.txt           Python dependencies
└── .env.example               Environment template
```

---

## API

All mutating endpoints require `X-API-Token` header.

### Health Check (public)
```bash
GET /api/health
```

### Platform Status (public)
```bash
GET /api/status
```

### Validate Domain (authenticated)
```bash
POST /api/validate-domain
X-API-Token: your-token
Content-Type: application/json

{"domain": "example.com"}
```

### Start Reconnaissance (authenticated, rate-limited)
```bash
POST /api/reconnaissance
X-API-Token: your-token
Content-Type: application/json

{
  "domain": "example.com",
  "modules": ["subdomains", "ports", "technologies"]
}
```

### Get Config (authenticated, admin)
```bash
GET /api/config
X-API-Token: your-token
```

---

## Configuration

Copy `.env.example` to `.env` and configure:

```env
# Required — generate with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your-secret-key
API_TOKEN=your-api-token

# Flask
FLASK_ENV=production
FLASK_HOST=0.0.0.0
PORT=5000

# CORS — comma-separated origins (no wildcard in production)
CORS_ORIGINS=http://localhost:5000

# Optional OSINT API keys
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
SECURITYTRAILS_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=

# Logging
LOG_LEVEL=INFO
```

---

## Deployment

### Development
```bash
FLASK_ENV=development python app.py
```

### Production (Gunicorn)
```bash
gunicorn wsgi:app --workers 4 --bind 0.0.0.0:5000
```

### Docker
```bash
docker build -t osint-platform .
docker run -p 5000:5000 --env-file .env osint-platform
```

---

## CLI Usage

```bash
# Basic reconnaissance
python -m passive_osint.cli main --domain example.com

# Specific modules with JSON output
python -m passive_osint.cli main --domain example.com --modules subdomains ports --output json --file report.json

# Verbose mode
python -m passive_osint.cli main --domain example.com --verbose
```

---

## Legal Notice

**This tool is for authorized security testing only.**

- Use only on domains you own or have explicit written permission to test
- Complies with passive-only data collection principles
- No active scanning, exploitation, or network interaction beyond data retrieval
- Users assume full responsibility for compliance with applicable laws

## License

MIT License — see [LICENSE](LICENSE) file for details.
