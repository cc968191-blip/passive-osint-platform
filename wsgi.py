"""
WSGI entry point for Passive OSINT Platform
Use with Gunicorn for production deployment
"""

import os
from app import app

if __name__ == "__main__":
    # Production WSGI server should call app directly
    port = int(os.getenv('PORT', 5000))
    app.run(port=port)
