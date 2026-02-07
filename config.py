"""
Production configuration for Passive OSINT Platform
"""

import os
import secrets
import warnings
from datetime import timedelta

class ProductionConfig:
    """Production environment configuration"""
    
    # Flask
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv('SECRET_KEY') or secrets.token_hex(32)
    if not os.getenv('SECRET_KEY'):
        warnings.warn(
            "SECRET_KEY non définie ! Utilisation d'une clé aléatoire temporaire. "
            "Les sessions ne survivront pas au redémarrage.",
            RuntimeWarning
        )
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CORS
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5000').split(',')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'osint_platform.log')
    
    # Rate limiting
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = 'memory://'
    
    # Cache
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 300
    
    # API Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max request size
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = False
    
    # Timeout
    SEND_FILE_MAX_AGE_DEFAULT = 3600

class DevelopmentConfig(ProductionConfig):
    """Development environment configuration"""
    
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    CORS_ORIGINS = ['*']
    
class TestingConfig(ProductionConfig):
    """Testing environment configuration"""
    
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False

# Configuration dictionary
config = {
    'production': ProductionConfig,
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'default': ProductionConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.getenv('FLASK_ENV', 'production')
    return config.get(env, config['default'])
