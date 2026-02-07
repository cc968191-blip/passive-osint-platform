"""Core reconnaissance engine for the Passive OSINT Platform."""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from .config import Config
from .exceptions import OSINTError, ValidationError
from ..utils import validate_domain as _validate_domain
from ..modules.subdomains import SubdomainEnumerator
from ..modules.ports import PortDetector
from ..modules.technologies import TechnologyIdentifier
from ..modules.vulnerabilities import VulnerabilityScanner
from ..modules.credentials import CredentialLeakDetector


@dataclass
class ReconResult:
    """Data class for reconnaissance results."""
    domain: str
    timestamp: str
    subdomains: List[Dict[str, Any]]
    ports: List[Dict[str, Any]]
    technologies: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class ReconEngine:
    """Main reconnaissance engine that orchestrates all modules."""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the reconnaissance engine.
        
        Args:
            config: Configuration object
        """
        self.config = config or Config()
        self.logger = self._setup_logging()
        
        # Initialize modules
        self.subdomain_enumerator = SubdomainEnumerator(self.config)
        self.port_detector = PortDetector(self.config)
        self.technology_identifier = TechnologyIdentifier(self.config)
        self.vulnerability_scanner = VulnerabilityScanner(self.config)
        self.credential_detector = CredentialLeakDetector(self.config)
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('osint_recon')
        logger.setLevel(getattr(logging, self.config.get('logging.level', 'INFO')))
        
        if not logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
            
            # File handler
            log_file = self.config.get('logging.file', 'osint_recon.log')
            file_handler = logging.FileHandler(log_file)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def validate_domain(self, domain: str) -> str:
        """
        Validate and normalize domain input.
        
        Args:
            domain: Domain to validate
            
        Returns:
            Normalized domain
            
        Raises:
            ValidationError: If domain is invalid
        """
        try:
            return _validate_domain(domain)
        except ValueError as e:
            raise ValidationError(str(e))
    
    async def enumerate_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """
        Enumerate subdomains for the given domain.
        
        Args:
            domain: Target domain
            
        Returns:
            List of subdomain results
        """
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        
        if not self.config.is_module_enabled('subdomains'):
            self.logger.info("Subdomain enumeration module disabled")
            return []
        
        try:
            results = await self.subdomain_enumerator.enumerate(domain)
            self.logger.info(f"Found {len(results)} subdomains")
            return results
        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {e}")
            return []
    
    async def detect_ports(self, domain: str) -> List[Dict[str, Any]]:
        """
        Detect open ports and services from passive data.
        
        Args:
            domain: Target domain
            
        Returns:
            List of port detection results
        """
        self.logger.info(f"Starting port detection for {domain}")
        
        if not self.config.is_module_enabled('ports'):
            self.logger.info("Port detection module disabled")
            return []
        
        try:
            results = await self.port_detector.detect(domain)
            self.logger.info(f"Found {len(results)} port/service entries")
            return results
        except Exception as e:
            self.logger.error(f"Port detection failed: {e}")
            return []
    
    async def identify_technologies(self, domain: str) -> List[Dict[str, Any]]:
        """
        Identify technologies used by the domain.
        
        Args:
            domain: Target domain
            
        Returns:
            List of technology identification results
        """
        self.logger.info(f"Starting technology identification for {domain}")
        
        if not self.config.is_module_enabled('technologies'):
            self.logger.info("Technology identification module disabled")
            return []
        
        try:
            results = await self.technology_identifier.identify(domain)
            self.logger.info(f"Found {len(results)} technologies")
            return results
        except Exception as e:
            self.logger.error(f"Technology identification failed: {e}")
            return []
    
    async def scan_vulnerabilities(self, domain: str) -> List[Dict[str, Any]]:
        """
        Scan for vulnerabilities using passive data.
        
        Args:
            domain: Target domain
            
        Returns:
            List of vulnerability scan results
        """
        self.logger.info(f"Starting vulnerability scanning for {domain}")
        
        if not self.config.is_module_enabled('vulnerabilities'):
            self.logger.info("Vulnerability scanning module disabled")
            return []
        
        try:
            results = await self.vulnerability_scanner.scan(domain)
            self.logger.info(f"Found {len(results)} potential vulnerabilities")
            return results
        except Exception as e:
            self.logger.error(f"Vulnerability scanning failed: {e}")
            return []
    
    async def detect_credentials(self, domain: str) -> List[Dict[str, Any]]:
        """
        Detect credential leaks related to the domain.
        
        Args:
            domain: Target domain
            
        Returns:
            List of credential detection results
        """
        self.logger.info(f"Starting credential leak detection for {domain}")
        
        if not self.config.is_module_enabled('credentials'):
            self.logger.info("Credential detection module disabled")
            return []
        
        try:
            results = await self.credential_detector.detect(domain)
            self.logger.info(f"Found {len(results)} credential leak entries")
            return results
        except Exception as e:
            self.logger.error(f"Credential detection failed: {e}")
            return []
    
    async def run_reconnaissance(self, domain: str, modules: Optional[List[str]] = None) -> ReconResult:
        """
        Run complete reconnaissance on the target domain.
        
        Args:
            domain: Target domain
            modules: List of modules to run (None for all enabled)
            
        Returns:
            Complete reconnaissance results
        """
        start_time = time.time()
        
        # Validate domain
        domain = self.validate_domain(domain)
        self.logger.info(f"Starting reconnaissance for {domain}")
        
        # Determine which modules to run
        if modules is None:
            modules = ['subdomains', 'ports', 'technologies', 'vulnerabilities', 'credentials']
        
        # Run modules concurrently
        tasks = []
        
        if 'subdomains' in modules:
            tasks.append(self.enumerate_subdomains(domain))
        else:
            tasks.append(asyncio.create_task(asyncio.sleep(0, result=[])))
        
        if 'ports' in modules:
            tasks.append(self.detect_ports(domain))
        else:
            tasks.append(asyncio.create_task(asyncio.sleep(0, result=[])))
        
        if 'technologies' in modules:
            tasks.append(self.identify_technologies(domain))
        else:
            tasks.append(asyncio.create_task(asyncio.sleep(0, result=[])))
        
        if 'vulnerabilities' in modules:
            tasks.append(self.scan_vulnerabilities(domain))
        else:
            tasks.append(asyncio.create_task(asyncio.sleep(0, result=[])))
        
        if 'credentials' in modules:
            tasks.append(self.detect_credentials(domain))
        else:
            tasks.append(asyncio.create_task(asyncio.sleep(0, result=[])))
        
        # Wait for all tasks to complete
        subdomains, ports, technologies, vulnerabilities, credentials = await asyncio.gather(*tasks)
        
        # Create metadata
        end_time = time.time()
        metadata = {
            'execution_time': round(end_time - start_time, 2),
            'modules_run': modules,
            'total_subdomains': len(subdomains),
            'total_ports': len(ports),
            'total_technologies': len(technologies),
            'total_vulnerabilities': len(vulnerabilities),
            'total_credentials': len(credentials),
            'timestamp_utc': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        }
        
        # Create result object
        result = ReconResult(
            domain=domain,
            timestamp=metadata['timestamp_utc'],
            subdomains=subdomains,
            ports=ports,
            technologies=technologies,
            vulnerabilities=vulnerabilities,
            credentials=credentials,
            metadata=metadata
        )
        
        self.logger.info(f"Reconnaissance completed for {domain} in {metadata['execution_time']}s")
        return result
    
    def run_reconnaissance_sync(self, domain: str, modules: Optional[List[str]] = None) -> ReconResult:
        """
        Synchronous wrapper for reconnaissance.
        
        Args:
            domain: Target domain
            modules: List of modules to run
            
        Returns:
            Complete reconnaissance results
        """
        return asyncio.run(self.run_reconnaissance(domain, modules))
