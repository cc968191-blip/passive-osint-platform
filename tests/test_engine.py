"""Tests for the reconnaissance engine."""

import pytest
from passive_osint.core.engine import ReconEngine
from passive_osint.core.exceptions import ValidationError


class TestReconEngine:
    """Validate engine initialization and domain validation."""

    def test_engine_initializes(self):
        engine = ReconEngine()
        assert engine is not None

    def test_valid_domain(self):
        engine = ReconEngine()
        assert engine.validate_domain("example.com") == "example.com"

    def test_valid_subdomain(self):
        engine = ReconEngine()
        assert engine.validate_domain("sub.example.com") == "sub.example.com"

    def test_invalid_domain_raises(self):
        engine = ReconEngine()
        with pytest.raises(ValidationError):
            engine.validate_domain("not a domain")

    def test_empty_domain_raises(self):
        engine = ReconEngine()
        with pytest.raises((ValidationError, ValueError)):
            engine.validate_domain("")
