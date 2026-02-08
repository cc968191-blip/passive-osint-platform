"""Tests for configuration loading."""

import pytest
from passive_osint.core.config import Config


class TestConfig:
    """Validate configuration manager behavior."""

    def test_config_loads(self):
        config = Config()
        assert config is not None

    def test_default_modules_enabled(self):
        config = Config()
        for module in ("subdomains", "ports", "technologies", "vulnerabilities", "credentials"):
            assert config.is_module_enabled(module) is True

    def test_get_missing_api_key_returns_none(self):
        config = Config()
        assert config.get_api_key("nonexistent_service") is None
