"""Custom exceptions for the Passive OSINT Platform."""


class OSINTError(Exception):
    """Base exception for all OSINT platform errors."""
    pass


class ConfigurationError(OSINTError):
    """Raised when configuration is invalid or missing."""
    pass


class APIError(OSINTError):
    """Raised when API requests fail."""
    def __init__(self, message, status_code=None, response=None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class RateLimitError(APIError):
    """Raised when rate limits are exceeded."""
    pass


class AuthenticationError(APIError):
    """Raised when API authentication fails."""
    pass


class NetworkError(OSINTError):
    """Raised when network connectivity issues occur."""
    pass


class DataParsingError(OSINTError):
    """Raised when data parsing fails."""
    pass


class ValidationError(OSINTError):
    """Raised when input validation fails."""
    pass
