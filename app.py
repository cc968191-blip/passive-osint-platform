"""
Flask web application for Passive OSINT Platform.
Provides REST API and interactive web interface with REAL OSINT data.
"""

import os
import sys
import secrets
import logging

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import asyncio
import aiohttp
import socket
from datetime import datetime
from config import get_config
from passive_osint.core.config import Config
from passive_osint.core.engine import ReconEngine
from passive_osint.reports.generator import ReportGenerator

app = Flask(__name__)
app.config.from_object(get_config())
CORS(app, origins=app.config.get('CORS_ORIGINS', ['http://localhost:5000']))
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=['100 per hour'])

# --- Authentication Middleware ---
API_TOKEN = os.getenv('API_TOKEN') or secrets.token_hex(32)
if not os.getenv('API_TOKEN'):
    print(f"[!] AVERTISSEMENT: API_TOKEN non défini. Token généré automatiquement: {API_TOKEN}")
    print(f"[!] Ajoutez API_TOKEN dans votre fichier .env pour un token persistant.")

def require_api_token(f):
    """Decorator to require API token authentication."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-API-Token') or request.args.get('api_token')
        if not token or not secrets.compare_digest(token, API_TOKEN):
            return jsonify({'error': 'Authentification requise. Fournir X-API-Token header.'}), 401
        return f(*args, **kwargs)
    return decorated

# --- Security Headers ---
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# --- Request Logging ---
@app.before_request
def log_request():
    app.logger.info(f"Requête: {request.method} {request.path} "
                    f"IP={request.remote_addr} UA={request.user_agent}")

# --- Initialize components ---
try:
    config = Config()
    engine = ReconEngine()
    report_gen = ReportGenerator()
except Exception as e:
    print(f"FATAL: Impossible d'initialiser les composants : {e}", file=sys.stderr)
    sys.exit(1)

# --- Helper: thread-safe async execution ---
def run_async(coro):
    """Exécute une coroutine de manière thread-safe."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

# Real OSINT Functions
async def query_crtsh(domain):
    """Query crt.sh for real subdomains"""
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=True) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subdomains = set()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip()
                            if subdomain and domain in subdomain:
                                subdomains.add(subdomain)
                    return {'source': 'crt.sh', 'status': 'success', 'data': list(subdomains)}
                else:
                    return {'source': 'crt.sh', 'status': 'failed', 'error': f'HTTP {resp.status}'}
    except Exception as e:
        return {'source': 'crt.sh', 'status': 'error', 'error': str(e)}

async def query_wayback(domain):
    """Query Wayback Machine for historical data"""
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=timestamp,original&filter=statuscode:200&collapse=original"
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=True) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if len(data) > 1:
                        results = data[1:]
                        unique_urls = set()
                        for entry in results:
                            if len(entry) >= 2:
                                unique_urls.add(entry[1])
                        return {'source': 'wayback', 'status': 'success', 'data': list(unique_urls)[:20]}
                    else:
                        return {'source': 'wayback', 'status': 'no_data', 'data': []}
                else:
                    return {'source': 'wayback', 'status': 'failed', 'error': f'HTTP {resp.status}'}
    except Exception as e:
        return {'source': 'wayback', 'status': 'error', 'error': str(e)}

def query_dns(domain):
    """Query DNS for IP resolution"""
    try:
        ip = socket.gethostbyname(domain)
        return {'source': 'dns', 'status': 'success', 'ip': ip}
    except Exception as e:
        return {'source': 'dns', 'status': 'error', 'error': str(e)}

@app.route('/')
def index():
    """Serve the main web interface."""
    return render_template('dashboard.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get platform status."""
    return jsonify({
        'status': 'ACTIVE',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat(),
        'modules': {
            'subdomains': config.is_module_enabled('subdomains'),
            'ports': config.is_module_enabled('ports'),
            'technologies': config.is_module_enabled('technologies'),
            'vulnerabilities': config.is_module_enabled('vulnerabilities'),
            'credentials': config.is_module_enabled('credentials')
        }
    })

@app.route('/api/validate-domain', methods=['POST'])
@require_api_token
def validate_domain():
    """Validate domain input."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Corps JSON requis'}), 400
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'valid': False, 'message': 'Domain is required'}), 400
    
    try:
        validated = engine.validate_domain(domain)
        return jsonify({
            'valid': True,
            'domain': validated,
            'message': f'Domain {validated} is valid'
        })
    except Exception as e:
        return jsonify({
            'valid': False,
            'message': str(e)
        }), 400

@app.route('/api/reconnaissance', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_token
def start_reconnaissance():
    """Start reconnaissance on a domain with REAL data."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Corps JSON requis'}), 400
    domain = data.get('domain', '').strip()
    modules = data.get('modules', ['subdomains', 'ports', 'technologies', 'vulnerabilities', 'credentials'])
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        # Validate domain
        validated_domain = engine.validate_domain(domain)
        
        # Execute OSINT queries
        results = {
            'domain': validated_domain,
            'timestamp': datetime.now().isoformat(),
            'modules_run': modules,
            'status': 'COMPLETE',
            'results': {}
        }
        
        # DNS Resolution (always run)
        dns_result = query_dns(validated_domain)
        results['results']['dns'] = dns_result
        
        # Subdomain enumeration
        if 'subdomains' in modules:
            ct_result = run_async(query_crtsh(validated_domain))
            results['results']['subdomains'] = ct_result
        
        # Wayback Machine
        if 'technologies' in modules:
            wb_result = run_async(query_wayback(validated_domain))
            results['results']['wayback'] = wb_result
        
        # Module stubs — clearly flagged as NOT real data
        for module_name in modules:
            if module_name not in results['results']:
                results['results'][module_name] = {
                    'source': module_name,
                    'status': 'skipped',
                    'simulated': True,
                    'message': f'[NO DATA] {module_name} requires a valid API key. No real data collected.'
                }
        
        return jsonify(results), 200
        
    except Exception as e:
        app.logger.error(f"Erreur de reconnaissance : {e}", exc_info=True)
        return jsonify({'error': 'Erreur interne du serveur'}), 500

@app.route('/api/config', methods=['GET'])
@require_api_token
def get_app_config():
    """Get current configuration (protected, admin only)."""
    config_data = {
        'modules': {}
    }
    
    for module_name in ['subdomains', 'ports', 'technologies', 'vulnerabilities', 'credentials']:
        config_data['modules'][module_name] = {
            'enabled': config.is_module_enabled(module_name)
        }
    
    return jsonify(config_data)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'HEALTHY',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    # Production vs Development
    debug_mode = os.getenv('FLASK_ENV', 'production') == 'development'
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    
    print(f"[*] Starting Passive OSINT Platform")
    print(f"[*] Environment: {'DEVELOPMENT' if debug_mode else 'PRODUCTION'}")
    print(f"[*] Host: {host}:{port}")
    
    app.run(
        debug=debug_mode,
        host=host,
        port=port,
        threaded=True
    )
