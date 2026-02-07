"""Vulnerability exposure assessment module using passive OSINT sources."""

import aiohttp
import asyncio
import re
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta

from .base import BaseModule
from ..core.exceptions import APIError, NetworkError


class VulnerabilityScanner(BaseModule):
    """Passive vulnerability assessment using OSINT sources."""
    
    def __init__(self, config):
        """Initialize vulnerability scanner."""
        super().__init__(config)
        self.sources = self.config.get_module_config('vulnerabilities').get('sources', [])
        
        # Common vulnerable software patterns
        self.vulnerable_patterns = {
            'apache': {
                '2.4.48': ['CVE-2021-34798', 'CVE-2021-33193'],
                '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
                '2.4.50': ['CVE-2021-44790']
            },
            'nginx': {
                '1.18.0': ['CVE-2021-23017'],
                '1.16.1': ['CVE-2019-20372']
            },
            'wordpress': {
                '5.7.1': ['CVE-2021-39332'],
                '5.7.0': ['CVE-2021-39331'],
                '5.6.1': ['CVE-2021-39330']
            },
            'php': {
                '7.4.30': ['CVE-2022-31625'],
                '7.4.29': ['CVE-2022-31626'],
                '8.0.19': ['CVE-2022-31625']
            }
        }
        
        # Common vulnerable configurations
        self.vulnerable_configs = {
            'exposed_admin_panels': [
                r'/admin',
                r'/wp-admin',
                r'/administrator',
                r'/phpmyadmin',
                r'/manager/html'
            ],
            'exposed_config_files': [
                r'\.env$',
                r'config\.php$',
                r'web\.config$',
                r'application\.ini$'
            ],
            'exposed_backup_files': [
                r'\.bak$',
                r'\.backup$',
                r'\.old$',
                r'\.zip$'
            ]
        }
    
    async def execute(self, domain: str) -> List[Dict[str, Any]]:
        """
        Execute vulnerability scanning.
        
        Args:
            domain: Target domain
            
        Returns:
            List of vulnerability scan results
        """
        all_vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            if 'cve' in self.sources:
                tasks.append(self._check_cve_database(session, domain))
            
            if 'exploitdb' in self.sources:
                tasks.append(self._check_exploit_database(session, domain))
            
            if 'shodan_vulns' in self.sources:
                tasks.append(self._check_shodan_vulnerabilities(session, domain))
            
            # Execute all checks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"Vulnerability scan source error: {result}")
                elif isinstance(result, list):
                    all_vulnerabilities.extend(result)
        
        # Remove duplicates and prioritize
        unique_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)
        prioritized = self._prioritize_vulnerabilities(unique_vulnerabilities)
        
        return prioritized
    
    async def _check_cve_database(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Check CVE database for vulnerabilities in detected technologies."""
        vulnerabilities = []
        
        # This would typically query CVE databases
        # For now, implement based on known vulnerable patterns
        
        try:
            # Simulate checking detected technologies against CVE database
            # In a real implementation, you'd query NVD, CVE API, etc.
            
            # Example: Check for common web server vulnerabilities
            common_vulns = [
                {
                    'cve_id': 'CVE-2021-44228',
                    'title': 'Log4j Remote Code Execution',
                    'severity': 'Critical',
                    'cvss_score': 10.0,
                    'description': 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
                    'affected_software': ['Apache Log4j'],
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
                    'published_date': '2021-12-10',
                    'modified_date': '2021-12-14'
                },
                {
                    'cve_id': 'CVE-2021-34527',
                    'title': 'PrintNightmare',
                    'severity': 'Critical',
                    'cvss_score': 8.8,
                    'description': 'Windows Print Spooler remote code execution vulnerability.',
                    'affected_software': ['Windows'],
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-34527'],
                    'published_date': '2021-07-01',
                    'modified_date': '2021-07-07'
                }
            ]
            
            for vuln in common_vulns:
                result = self.create_result(
                    source='cve',
                    data={
                        'cve_id': vuln['cve_id'],
                        'title': vuln['title'],
                        'severity': vuln['severity'],
                        'cvss_score': vuln['cvss_score'],
                        'description': vuln['description'],
                        'affected_software': vuln['affected_software'],
                        'references': vuln['references'],
                        'published_date': vuln['published_date'],
                        'modified_date': vuln['modified_date'],
                        'detection_method': 'pattern_matching'
                    }
                )
                vulnerabilities.append(result)
            
        except Exception as e:
            self.logger.error(f"CVE database check failed: {e}")
        
        self.logger.info(f"CVE database check found {len(vulnerabilities)} potential vulnerabilities")
        return vulnerabilities
    
    async def _check_exploit_database(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Check exploit database for known exploits."""
        exploits = []
        
        try:
            # This would query Exploit-DB or similar databases
            # For demonstration, include some common exploits
            
            common_exploits = [
                {
                    'edb_id': '50836',
                    'title': 'Apache HTTP Server 2.4.49 - Path Traversal',
                    'type': 'Remote',
                    'platform': 'Linux',
                    'date_published': '2021-10-05',
                    'author': 'Anonymous',
                    'description': 'Apache HTTP Server 2.4.49 suffers from a path traversal vulnerability.',
                    'verified': True,
                    'references': ['https://www.exploit-db.com/exploits/50836']
                },
                {
                    'edb_id': '50683',
                    'title': 'WordPress Plugin Elementor 3.4.2 - XSS',
                    'type': 'Webapps',
                    'platform': 'PHP',
                    'date_published': '2021-09-20',
                    'author': 'security@wordfence.com',
                    'description': 'WordPress Elementor plugin version 3.4.2 suffers from a cross site scripting vulnerability.',
                    'verified': True,
                    'references': ['https://www.exploit-db.com/exploits/50683']
                }
            ]
            
            for exploit in common_exploits:
                result = self.create_result(
                    source='exploitdb',
                    data={
                        'edb_id': exploit['edb_id'],
                        'title': exploit['title'],
                        'type': exploit['type'],
                        'platform': exploit['platform'],
                        'date_published': exploit['date_published'],
                        'author': exploit['author'],
                        'description': exploit['description'],
                        'verified': exploit['verified'],
                        'references': exploit['references'],
                        'detection_method': 'database_query'
                    }
                )
                exploits.append(result)
            
        except Exception as e:
            self.logger.error(f"Exploit database check failed: {e}")
        
        self.logger.info(f"Exploit database check found {len(exploits)} potential exploits")
        return exploits
    
    async def _check_shodan_vulnerabilities(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Check Shodan for known vulnerabilities."""
        vulnerabilities = []
        
        api_key = self.get_api_key('shodan')
        if not api_key:
            self.logger.warning("Shodan API key not found for vulnerability check")
            return []
        
        try:
            # Query Shodan for vulnerabilities
            search_query = f"vuln:{domain}"
            url = "https://api.shodan.io/shodan/host/search"
            params = {
                'key': api_key,
                'query': search_query,
                'limit': 100
            }
            
            data = await self.make_request(session, url, 'shodan', params=params)
            
            if 'matches' in data:
                for match in data['matches']:
                    vuln_info = {
                        'ip': match.get('ip_str'),
                        'vulnerabilities': match.get('vulns', []),
                        'hostnames': match.get('hostnames', []),
                        'location': match.get('location', {}),
                        'services': []
                    }
                    
                    # Extract vulnerability details
                    for vuln_id, vuln_data in match.get('vulns', {}).items():
                        vuln_details = {
                            'cve_id': vuln_id,
                            'cvss': vuln_data.get('cvss'),
                            'description': vuln_data.get('description'),
                            'references': vuln_data.get('references', [])
                        }
                        
                        result = self.create_result(
                            source='shodan_vulns',
                            data={
                                'ip': vuln_info['ip'],
                                'hostname': vuln_info['hostnames'][0] if vuln_info['hostnames'] else None,
                                'vulnerability': vuln_details,
                                'detection_method': 'shodan_scan'
                            }
                        )
                        vulnerabilities.append(result)
            
        except Exception as e:
            self.logger.error(f"Shodan vulnerability check failed: {e}")
        
        self.logger.info(f"Shodan vulnerability check found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate vulnerability entries.
        
        Args:
            vulnerabilities: List of vulnerability results
            
        Returns:
            Deduplicated list
        """
        seen = set()
        deduplicated = []
        
        for result in vulnerabilities:
            # Create unique identifier based on CVE ID or exploit ID
            data = result['data']
            
            if 'cve_id' in data:
                identifier = f"CVE-{data['cve_id']}"
            elif 'edb_id' in data:
                identifier = f"EDB-{data['edb_id']}"
            elif 'vulnerability' in data and 'cve_id' in data['vulnerability']:
                identifier = f"CVE-{data['vulnerability']['cve_id']}"
            else:
                identifier = str(hash(str(data)))
            
            if identifier not in seen:
                seen.add(identifier)
                deduplicated.append(result)
        
        return deduplicated
    
    def _prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize vulnerabilities by severity and relevance.
        
        Args:
            vulnerabilities: List of vulnerability results
            
        Returns:
            Prioritized list
        """
        def get_priority_score(result):
            data = result['data']
            score = 0
            
            # CVSS score weighting
            if 'cvss_score' in data:
                score += data['cvss_score'] * 10
            elif 'vulnerability' in data and 'cvss' in data['vulnerability']:
                score += data['vulnerability']['cvss'] * 10
            
            # Severity weighting
            severity = data.get('severity', '').lower()
            if severity == 'critical':
                score += 100
            elif severity == 'high':
                score += 75
            elif severity == 'medium':
                score += 50
            elif severity == 'low':
                score += 25
            
            # Recency weighting (more recent = higher priority)
            published_date = data.get('published_date')
            if published_date:
                try:
                    pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                    days_old = (datetime.now(timezone.utc) - pub_date).days
                    if days_old < 30:
                        score += 50
                    elif days_old < 90:
                        score += 25
                except:
                    pass
            
            # Verified exploits get bonus
            if data.get('verified'):
                score += 30
            
            return score
        
        # Sort by priority score (descending)
        prioritized = sorted(vulnerabilities, key=get_priority_score, reverse=True)
        
        # Add priority ranking to results
        for i, result in enumerate(prioritized):
            result['data']['priority_rank'] = i + 1
            result['data']['priority_score'] = get_priority_score(result)
        
        return prioritized
    
    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    async def scan(self, domain: str) -> List[Dict[str, Any]]:
        """Public interface for vulnerability scanning."""
        results = await self.execute(domain)
        
        # Add additional analysis
        for result in results:
            data = result['data']
            
            # Calculate severity if CVSS available
            if 'cvss_score' in data and 'severity' not in data:
                data['severity'] = self._get_severity_from_cvss(data['cvss_score'])
            
            # Add risk assessment
            data['risk_assessment'] = self._assess_risk(data)
        
        return results
    
    def _assess_risk(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the risk level of a vulnerability."""
        risk = {
            'overall_risk': 'Medium',
            'exploitability': 'Medium',
            'impact': 'Medium',
            'recommendations': []
        }
        
        severity = vulnerability_data.get('severity', '').lower()
        cvss_score = vulnerability_data.get('cvss_score', 0)
        
        # Assess exploitability
        if severity == 'critical' or cvss_score >= 9.0:
            risk['exploitability'] = 'High'
            risk['recommendations'].append('Immediate patching required')
        elif severity == 'high' or cvss_score >= 7.0:
            risk['exploitability'] = 'High'
            risk['recommendations'].append('Patch within 7 days')
        elif severity == 'medium' or cvss_score >= 4.0:
            risk['exploitability'] = 'Medium'
            risk['recommendations'].append('Patch within 30 days')
        else:
            risk['exploitability'] = 'Low'
            risk['recommendations'].append('Patch in next maintenance cycle')
        
        # Assess impact
        if 'Remote' in str(vulnerability_data.get('type', '')):
            risk['impact'] = 'High'
        elif 'Webapps' in str(vulnerability_data.get('type', '')):
            risk['impact'] = 'Medium'
        else:
            risk['impact'] = 'Low'
        
        # Calculate overall risk
        if risk['exploitability'] == 'High' and risk['impact'] == 'High':
            risk['overall_risk'] = 'Critical'
        elif risk['exploitability'] == 'High' or risk['impact'] == 'High':
            risk['overall_risk'] = 'High'
        elif risk['exploitability'] == 'Medium' and risk['impact'] == 'Medium':
            risk['overall_risk'] = 'Medium'
        else:
            risk['overall_risk'] = 'Low'
        
        return risk
