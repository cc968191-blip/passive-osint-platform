"""Utility functions for the Passive OSINT Platform."""

import functools
import logging
import logging.handlers
import re
import socket
import urllib.parse
import time
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone
import hashlib
import json


def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """
    Setup comprehensive logging configuration.
    
    Args:
        config: Logging configuration
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger('osint_recon')
    logger.setLevel(getattr(logging, config.get('level', 'INFO')))
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    log_file = config.get('file', 'osint_recon.log')
    max_size = config.get('max_size', '10MB')
    backup_count = config.get('backup_count', 5)
    
    # Parse max_size
    if max_size.endswith('MB'):
        max_bytes = int(max_size[:-2]) * 1024 * 1024
    elif max_size.endswith('KB'):
        max_bytes = int(max_size[:-2]) * 1024
    else:
        max_bytes = int(max_size)
    
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger


def validate_domain(domain: str) -> str:
    """
    Validate and normalize a domain name.
    
    Args:
        domain: Domain to validate
        
    Returns:
        Normalized domain
        
    Raises:
        ValueError: If domain is invalid
    """
    if not domain:
        raise ValueError("Domain cannot be empty")
    
    # Remove protocol and path
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Remove port
    domain = domain.split(':')[0]
    
    # Remove whitespace
    domain = domain.strip()
    
    # Basic validation
    if len(domain) > 253:
        raise ValueError("Domain too long (max 253 characters)")
    
    if len(domain) < 3:
        raise ValueError("Domain too short (min 3 characters)")
    
    # Convert to lowercase early
    domain = domain.lower()
    
    # Strict RFC 1035 / 1123 validation
    # Each label: 1-63 chars, alphanumeric + hyphens, no leading/trailing hyphen
    label_re = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
    
    if '.' not in domain:
        raise ValueError("Domain must have at least one dot (e.g., example.com)")
    
    labels = domain.split('.')
    
    for label in labels:
        if not label:
            raise ValueError("Domain contains empty label (consecutive or trailing dots)")
        if len(label) > 63:
            raise ValueError(f"Label '{label}' exceeds 63 characters")
        if not label_re.match(label):
            raise ValueError(f"Label '{label}' contains invalid characters or format")
    
    # TLD must be alphabetic (no pure-numeric TLD)
    tld = labels[-1]
    if not re.match(r'^[a-z]{2,}$', tld):
        raise ValueError(f"Invalid TLD: '{tld}'")
    
    return domain


def normalize_url(url: str) -> str:
    """
    Normalize a URL.
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL
    """
    if not url:
        return url
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Parse and reconstruct
    parsed = urllib.parse.urlparse(url)
    
    # Normalize scheme and netloc
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    # Remove default port
    if (scheme == 'http' and netloc.endswith(':80')) or \
       (scheme == 'https' and netloc.endswith(':443')):
        netloc = netloc.rsplit(':', 1)[0]
    
    # Reconstruct
    normalized = urllib.parse.urlunparse((
        scheme,
        netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        ''  # Remove fragment
    ))
    
    return normalized


def generate_hash(data: Union[str, Dict[str, Any]]) -> str:
    """
    Generate SHA256 hash of data.
    
    Args:
        data: Data to hash
        
    Returns:
        Hexadecimal hash
    """
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL.
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain or None if invalid
    """
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return None


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if private IP
    """
    try:
        # Private IP ranges
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),  # Loopback
            ('169.254.0.0', '169.254.255.255'),  # Link-local
        ]
        
        ip_obj = socket.inet_aton(ip)
        
        for start, end in private_ranges:
            start_obj = socket.inet_aton(start)
            end_obj = socket.inet_aton(end)
            
            if start_obj <= ip_obj <= end_obj:
                return True
        
        return False
    except socket.error:
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file system usage.
    
    Args:
        filename: Filename to sanitize
        
    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove control characters
    filename = ''.join(char for char in filename if ord(char) >= 32)
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_len = 255 - len(ext) - 1
        filename = name[:max_name_len] + ('.' + ext if ext else '')
    
    return filename


def format_timestamp(timestamp: Union[str, datetime], format_str: str = '%Y-%m-%d %H:%M:%S UTC') -> str:
    """
    Format timestamp to string.
    
    Args:
        timestamp: Timestamp to format
        format_str: Format string
        
    Returns:
        Formatted timestamp string
    """
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except ValueError:
            return timestamp
    
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    
    return timestamp.strftime(format_str)


def calculate_confidence_score(sources: List[str], evidence_count: int) -> str:
    """
    Calculate confidence score based on sources and evidence.
    
    Args:
        sources: List of data sources
        evidence_count: Number of evidence pieces
        
    Returns:
        Confidence level (low, medium, high, very_high)
    """
    score = 0
    
    # Source weighting
    high_confidence_sources = ['virustotal', 'shodan', 'censys', 'securitytrails']
    medium_confidence_sources = ['wayback', 'crtsh']
    
    for source in sources:
        if source in high_confidence_sources:
            score += 3
        elif source in medium_confidence_sources:
            score += 2
        else:
            score += 1
    
    # Evidence weighting
    score += min(evidence_count, 5)
    
    # Determine confidence level
    if score >= 10:
        return 'very_high'
    elif score >= 7:
        return 'high'
    elif score >= 4:
        return 'medium'
    else:
        return 'low'


def merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two dictionaries recursively.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split list into chunks of specified size.
    
    Args:
        lst: List to chunk
        chunk_size: Size of each chunk
        
    Returns:
        List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def retry_async(max_retries: int = 3, delay: float = 1.0):
    """
    Decorator for retrying async functions.
    
    Args:
        max_retries: Maximum number of retries
        delay: Delay between retries in seconds
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        import asyncio
                        await asyncio.sleep(delay * (2 ** attempt))  # Exponential backoff
                    else:
                        raise last_exception
            
            return None
        return wrapper
    return decorator


def mask_sensitive_data(data: str, mask_char: str = '*', visible_chars: int = 4) -> str:
    """
    Mask sensitive data for logging.
    
    Args:
        data: Data to mask
        mask_char: Character to use for masking
        visible_chars: Number of characters to keep visible
        
    Returns:
        Masked data
    """
    if len(data) <= visible_chars:
        return mask_char * len(data)
    
    return data[:visible_chars] + mask_char * (len(data) - visible_chars)


def parse_user_agent(user_agent: str) -> Dict[str, Any]:
    """
    Parse user agent string.
    
    Args:
        user_agent: User agent string
        
    Returns:
        Parsed user agent information
    """
    # Simple user agent parsing
    # In production, consider using a dedicated library like ua-parser
    
    info = {
        'raw': user_agent,
        'browser': None,
        'os': None,
        'device': None
    }
    
    # Browser detection
    browsers = [
        ('Chrome', 'Chrome'),
        ('Firefox', 'Firefox'),
        ('Safari', 'Safari'),
        ('Edge', 'Edge'),
        ('Opera', 'Opera'),
        ('IE', 'MSIE')
    ]
    
    for name, pattern in browsers:
        if pattern in user_agent:
            info['browser'] = name
            break
    
    # OS detection
    os_patterns = [
        ('Windows', 'Windows'),
        ('Mac OS X', 'macOS'),
        ('Linux', 'Linux'),
        ('Android', 'Android'),
        ('iOS', 'iOS')
    ]
    
    for name, pattern in os_patterns:
        if pattern in user_agent:
            info['os'] = name
            break
    
    return info


def create_progress_callback(total: int, description: str = "Processing"):
    """
    Create a progress callback function.
    
    Args:
        total: Total number of items
        description: Description of the operation
        
    Returns:
        Progress callback function
    """
    def callback(current: int):
        percentage = (current / total) * 100
        print(f"\r{description}: {current}/{total} ({percentage:.1f}%)", end='', flush=True)
        
        if current == total:
            print()  # New line when complete
    
    return callback


class RateLimiter:
    """Simple rate limiter for API calls."""
    
    def __init__(self, max_calls: int, time_window: float):
        """
        Initialize rate limiter.
        
        Args:
            max_calls: Maximum number of calls allowed
            time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
    
    async def acquire(self):
        """Acquire permission to make a call."""
        import asyncio
        import time
        
        now = time.time()
        
        # Remove old calls outside the time window
        self.calls = [call_time for call_time in self.calls if now - call_time < self.time_window]
        
        # Check if we can make a call
        if len(self.calls) >= self.max_calls:
            # Calculate wait time
            oldest_call = min(self.calls)
            wait_time = self.time_window - (now - oldest_call)
            
            if wait_time > 0:
                await asyncio.sleep(wait_time)
        
        # Record this call
        self.calls.append(now)


class Cache:
    """Simple in-memory cache with TTL."""
    
    def __init__(self, ttl: float = 3600):
        """
        Initialize cache.
        
        Args:
            ttl: Time to live in seconds
        """
        self.ttl = ttl
        self.cache = {}
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None
        """
        if key in self.cache:
            value, timestamp = self.cache[key]
            
            if time.time() - timestamp < self.ttl:
                return value
            else:
                del self.cache[key]
        
        return None
    
    def set(self, key: str, value: Any) -> None:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        self.cache[key] = (value, time.time())
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()
    
    def size(self) -> int:
        """Get cache size."""
        return len(self.cache)
