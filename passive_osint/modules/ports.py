"""Port and service detection module using passive OSINT sources."""

import aiohttp
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

from .base import BaseModule
from ..core.exceptions import APIError, NetworkError


class PortDetector(BaseModule):
    """Passive port and service detection using OSINT sources."""
    
    def __init__(self, config):
        """Initialize port detector."""
        super().__init__(config)
        self.sources = self.config.get_module_config('ports').get('sources', [])
        self.common_ports = self.config.get_module_config('ports').get('common_ports', [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443
        ])
    
    async def execute(self, domain: str) -> List[Dict[str, Any]]:
        """
        Execute port detection.
        
        Args:
            domain: Target domain
            
        Returns:
            List of port detection results
        """
        all_ports = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            if 'shodan' in self.sources:
                tasks.append(self._query_shodan(session, domain))
            
            if 'censys' in self.sources:
                tasks.append(self._query_censys(session, domain))
            
            # Execute all queries concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"Port detection source error: {result}")
                elif isinstance(result, list):
                    all_ports.extend(result)
        
        # Remove duplicates and organize results
        unique_ports = self._deduplicate_ports(all_ports)
        
        return unique_ports
    
    async def _query_shodan(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Query Shodan for exposed ports and services."""
        api_key = self.get_api_key('shodan')
        if not api_key:
            self.logger.warning("Shodan API key not found")
            return []
        
        # Search for the domain and its subdomains
        search_query = f"ssl:{domain} OR hostname:{domain}"
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            'key': api_key,
            'query': search_query,
            'limit': 100
        }
        
        try:
            data = await self.make_request(session, url, 'shodan', params=params)
            
            ports = []
            if 'matches' in data:
                for match in data['matches']:
                    host_info = {
                        'ip': match.get('ip_str'),
                        'ports': match.get('ports', []),
                        'hostnames': match.get('hostnames', []),
                        'location': match.get('location', {}),
                        'domains': match.get('domains', []),
                        'vulns': match.get('vulns', []),
                        'services': []
                    }
                    
                    # Extract service information for each port
                    for port in match.get('ports', []):
                        if str(port) in match.get('data', {}):
                            service_data = match['data'][str(port)]
                            service_info = {
                                'port': port,
                                'transport': service_data.get('transport', 'tcp'),
                                'product': service_data.get('product'),
                                'version': service_data.get('version'),
                                'banner': service_data.get('banner', ''),
                                'cpe': service_data.get('cpe'),
                                'timestamp': service_data.get('timestamp')
                            }
                            host_info['services'].append(service_info)
                    
                    result = self.create_result(
                        source='shodan',
                        data=host_info,
                        confidence='high'
                    )
                    ports.append(result)
            
            self.logger.info(f"Shodan found {len(ports)} hosts with services")
            return ports
            
        except Exception as e:
            self.logger.error(f"Shodan query failed: {e}")
            return []
    
    async def _query_censys(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Query Censys for exposed ports and services."""
        api_id = self.get_api_key('censys_id')
        api_secret = self.get_api_key('censys')
        
        if not api_id or not api_secret:
            self.logger.warning("Censys API credentials not found")
            return []
        
        # Censys search query
        search_query = f"parsed.names: {domain}"
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {
            'q': search_query,
            'per_page': 100,
            'virtual_hosts': 'EXCLUDE'
        }
        
        # Basic auth for Censys
        auth = aiohttp.BasicAuth(api_id, api_secret)
        
        try:
            async with session.get(url, params=params, auth=auth) as response:
                if response.status == 401:
                    raise APIError("Censys authentication failed", response.status)
                elif response.status >= 400:
                    raise APIError(f"Censys HTTP {response.status}", response.status)
                
                data = await response.json()
                
                ports = []
                if 'result' in data and 'hits' in data['result']:
                    for hit in data['result']['hits']:
                        host_info = {
                            'ip': hit.get('ip'),
                            'services': [],
                            'location': hit.get('location', {}),
                            'autonomous_system': hit.get('autonomous_system', {}),
                            'metadata': hit.get('metadata', {})
                        }
                        
                        # Extract service information
                        for service in hit.get('services', []):
                            service_info = {
                                'port': service.get('port'),
                                'transport': service.get('transport_protocol', 'tcp'),
                                'service_name': service.get('service_name'),
                                'banner': service.get('banner', ''),
                                'software': service.get('software', []),
                                'extended_service_name': service.get('extended_service_name'),
                                'observed_at': service.get('observed_at'),
                                'tls': service.get('tls', {})
                            }
                            host_info['services'].append(service_info)
                        
                        result = self.create_result(
                            source='censys',
                            data=host_info,
                            confidence='high'
                        )
                        ports.append(result)
                
                self.logger.info(f"Censys found {len(ports)} hosts with services")
                return ports
                
        except Exception as e:
            self.logger.error(f"Censys query failed: {e}")
            return []
    
    def _deduplicate_ports(self, ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate port entries and merge information.
        
        Args:
            ports: List of port detection results
            
        Returns:
            Deduplicated list
        """
        seen = {}
        deduplicated = []
        
        for result in ports:
            ip = result['data'].get('ip')
            
            if ip and ip not in seen:
                seen[ip] = result
                deduplicated.append(result)
            elif ip:
                # Merge services from different sources
                existing = seen[ip]
                if 'sources' not in existing:
                    existing['sources'] = [existing['source']]
                    del existing['source']
                
                if result['source'] not in existing['sources']:
                    existing['sources'].append(result['source'])
                
                # Merge services
                existing_services = {s['port']: s for s in existing['data']['services']}
                new_services = {s['port']: s for s in result['data']['services']}
                
                for port, service in new_services.items():
                    if port not in existing_services:
                        existing['data']['services'].append(service)
                    else:
                        # Merge additional information
                        existing_service = existing_services[port]
                        for key, value in service.items():
                            if value and not existing_service.get(key):
                                existing_service[key] = value
        
        return deduplicated
    
    def _analyze_service_risks(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze services for potential security risks.
        
        Args:
            services: List of service information
            
        Returns:
            List of risk assessments
        """
        risks = []
        
        for service in services:
            port = service.get('port')
            service_name = service.get('service_name', '').lower()
            banner = service.get('banner', '').lower()
            
            risk_assessment = {
                'port': port,
                'risk_level': 'low',
                'risk_reasons': [],
                'recommendations': []
            }
            
            # Check for common risky services
            if port in [21, 23, 25, 53, 110, 143]:
                risk_assessment['risk_level'] = 'medium'
                risk_assessment['risk_reasons'].append(f"Potentially insecure service on port {port}")
                risk_assessment['recommendations'].append("Consider using encrypted alternatives")
            
            # Check for default credentials in banners
            if any(keyword in banner for keyword in ['default', 'password', 'admin', 'root']):
                risk_assessment['risk_level'] = 'high'
                risk_assessment['risk_reasons'].append("Banner suggests default credentials")
                risk_assessment['recommendations'].append("Change default credentials immediately")
            
            # Check for outdated software
            if service.get('software'):
                for software in service['software']:
                    if 'version' in software:
                        version = software['version']
                        # Simple version check (could be enhanced with CVE database)
                        if any(v in version.lower() for v in ['1.0', '2.0', '3.0', 'alpha', 'beta']):
                            risk_assessment['risk_level'] = 'high'
                            risk_assessment['risk_reasons'].append(f"Potentially outdated software: {software}")
                            risk_assessment['recommendations'].append("Update to latest stable version")
            
            if risk_assessment['risk_reasons']:
                risks.append(risk_assessment)
        
        return risks
    
    async def detect(self, domain: str) -> List[Dict[str, Any]]:
        """Public interface for port detection."""
        results = await self.execute(domain)
        
        # Add risk analysis to results
        for result in results:
            services = result['data'].get('services', [])
            if services:
                risks = self._analyze_service_risks(services)
                result['data']['risk_assessment'] = risks
        
        return results
