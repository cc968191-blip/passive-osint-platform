"""Tests for utility functions."""

import pytest
from passive_osint.utils import validate_domain


class TestValidateDomain:
    """Validate domain validation logic."""

    def test_simple_domain(self):
        assert validate_domain("example.com") == "example.com"

    def test_subdomain(self):
        assert validate_domain("mail.example.com") == "mail.example.com"

    def test_uppercase_normalized(self):
        assert validate_domain("EXAMPLE.COM") == "example.com"

    def test_strips_whitespace(self):
        assert validate_domain("  example.com  ") == "example.com"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_domain("")

    def test_rejects_no_dot(self):
        with pytest.raises(ValueError):
            validate_domain("localhost")

    def test_rejects_special_chars(self):
        with pytest.raises(ValueError):
            validate_domain("ex@mple.com")

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ValueError):
            validate_domain("-example.com")

    def test_rejects_numeric_tld(self):
        with pytest.raises(ValueError):
            validate_domain("example.123")
