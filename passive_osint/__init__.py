"""
Passive OSINT Reconnaissance Platform

A production-grade passive OSINT automation tool for authorized security research.
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__email__ = "security@example.com"

from .core.engine import ReconEngine
from .core.config import Config
from .modules.subdomains import SubdomainEnumerator
from .modules.ports import PortDetector
from .modules.technologies import TechnologyIdentifier
from .modules.vulnerabilities import VulnerabilityScanner
from .modules.credentials import CredentialLeakDetector
from .reports.generator import ReportGenerator

__all__ = [
    "ReconEngine",
    "Config", 
    "SubdomainEnumerator",
    "PortDetector",
    "TechnologyIdentifier",
    "VulnerabilityScanner",
    "CredentialLeakDetector",
    "ReportGenerator"
]
