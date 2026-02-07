"""Subdomain enumeration module using passive OSINT sources."""

import aiohttp
import asyncio
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

from .base import BaseModule
from ..core.exceptions import APIError, NetworkError


class SubdomainEnumerator(BaseModule):
    """Passive subdomain enumeration using multiple OSINT sources."""
    
    def __init__(self, config):
        """Initialize subdomain enumerator."""
        super().__init__(config)
        self.sources = self.config.get_module_config('subdomains').get('sources', [])
        self.max_results = self.config.get_module_config('subdomains').get('max_results', 1000)
    
    async def execute(self, domain: str) -> List[Dict[str, Any]]:
        """
        Execute subdomain enumeration.
        
        Args:
            domain: Target domain
            
        Returns:
            List of subdomain results
        """
        all_subdomains = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            if 'virustotal' in self.sources:
                tasks.append(self._query_virustotal(session, domain))
            
            if 'securitytrails' in self.sources:
                tasks.append(self._query_securitytrails(session, domain))
            
            if 'wayback' in self.sources:
                tasks.append(self._query_wayback(session, domain))
            
            if 'crtsh' in self.sources:
                tasks.append(self._query_crtsh(session, domain))
            
            # Execute all queries concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"Subdomain source error: {result}")
                elif isinstance(result, list):
                    all_subdomains.extend(result)
        
        # Remove duplicates and limit results
        unique_subdomains = self._deduplicate_subdomains(all_subdomains)
        
        if len(unique_subdomains) > self.max_results:
            unique_subdomains = unique_subdomains[:self.max_results]
        
        return unique_subdomains
    
    async def _query_virustotal(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Query VirusTotal for subdomains."""
        api_key = self.get_api_key('virustotal')
        if not api_key:
            self.logger.warning("VirusTotal API key not found")
            return []
        
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {
            'apikey': api_key,
            'domain': domain
        }
        
        try:
            data = await self.make_request(session, url, 'virustotal', params=params)
            
            subdomains = []
            if 'subdomains' in data:
                for subdomain in data['subdomains']:
                    result = self.create_result(
                        source='virustotal',
                        data={
                            'subdomain': subdomain,
                            'domain': domain,
                            'full_host': f"{subdomain}.{domain}"
                        },
                        confidence='high'
                    )
                    subdomains.append(result)
            
            self.logger.info(f"VirusTotal found {len(subdomains)} subdomains")
            return subdomains
            
        except Exception as e:
            self.logger.error(f"VirusTotal query failed: {e}")
            return []
    
    async def _query_securitytrails(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Query SecurityTrails for subdomains."""
        api_key = self.get_api_key('securitytrails')
        if not api_key:
            self.logger.warning("SecurityTrails API key not found")
            return []
        
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {'apikey': api_key}
        
        try:
            data = await self.make_request(session, url, 'securitytrails', headers=headers)
            
            subdomains = []
            if 'subdomains' in data:
                for subdomain in data['subdomains']:
                    result = self.create_result(
                        source='securitytrails',
                        data={
                            'subdomain': subdomain,
                            'domain': domain,
                            'full_host': f"{subdomain}.{domain}"
                        },
                        confidence='high'
                    )
                    subdomains.append(result)
            
            self.logger.info(f"SecurityTrails found {len(subdomains)} subdomains")
            return subdomains
            
        except Exception as e:
            self.logger.error(f"SecurityTrails query failed: {e}")
            return []
    
    async def _query_wayback(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Query Wayback Machine for subdomains."""
        url = "https://web.archive.org/cdx/search/cdx"
        params = {
            'url': f"*.{domain}",
            'output': 'json',
            'fl': 'original',
            'collapse': 'original',
            'limit': 1000
        }
        
        try:
            # Wayback Machine doesn't require API key but has rate limits
            await self.rate_limit('wayback')
            
            async with session.get(url, params=params) as response:
                if response.status != 200:
                    raise APIError(f"Wayback Machine HTTP {response.status}")
                
                data = await response.json()
                
                subdomains = set()
                if len(data) > 1:  # First row is headers
                    for row in data[1:]:
                        if len(row) > 0:
                            original_url = row[0]
                            # Extract hostname from URL
                            hostname = original_url.split('://')[1].split('/')[0]
                            if hostname.endswith(f".{domain}"):
                                subdomain = hostname.replace(f".{domain}", "")
                                if subdomain and subdomain != domain:
                                    subdomains.add(subdomain)
                
                results = []
                for subdomain in subdomains:
                    result = self.create_result(
                        source='wayback',
                        data={
                            'subdomain': subdomain,
                            'domain': domain,
                            'full_host': f"{subdomain}.{domain}"
                        },
                        confidence='medium'
                    )
                    results.append(result)
                
                self.logger.info(f"Wayback Machine found {len(results)} subdomains")
                return results
                
        except Exception as e:
            self.logger.error(f"Wayback Machine query failed: {e}")
            return []
    
    async def _query_crtsh(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Query crt.sh for certificate transparency subdomains."""
        url = "https://crt.sh/"
        params = {
            'q': f"%.{domain}",
            'output': 'json'
        }
        
        try:
            # crt.sh doesn't require API key but has rate limits
            await self.rate_limit('crtsh')
            
            async with session.get(url, params=params) as response:
                if response.status != 200:
                    raise APIError(f"crt.sh HTTP {response.status}")
                
                data = await response.json()
                
                subdomains = set()
                for cert in data:
                    if 'name_value' in cert and cert['name_value']:
                        # Split multiple names in certificate
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip()
                            # Remove wildcards and extract subdomain
                            if name.startswith('*.'):
                                name = name[2:]
                            
                            if name.endswith(f".{domain}") and name != domain:
                                subdomain = name.replace(f".{domain}", "")
                                if subdomain:
                                    subdomains.add(subdomain)
                
                results = []
                for subdomain in subdomains:
                    result = self.create_result(
                        source='crtsh',
                        data={
                            'subdomain': subdomain,
                            'domain': domain,
                            'full_host': f"{subdomain}.{domain}"
                        },
                        confidence='high'
                    )
                    results.append(result)
                
                self.logger.info(f"crt.sh found {len(results)} subdomains")
                return results
                
        except Exception as e:
            self.logger.error(f"crt.sh query failed: {e}")
            return []
    
    def _deduplicate_subdomains(self, subdomains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate subdomains and merge confidence levels.
        
        Args:
            subdomains: List of subdomain results
            
        Returns:
            Deduplicated list
        """
        seen = {}
        deduplicated = []
        
        for result in subdomains:
            subdomain = result['data']['subdomain']
            
            if subdomain not in seen:
                seen[subdomain] = result
                deduplicated.append(result)
            else:
                # Merge sources if multiple sources found same subdomain
                existing = seen[subdomain]
                if 'sources' not in existing:
                    existing['sources'] = [existing['source']]
                    del existing['source']
                
                if result['source'] not in existing['sources']:
                    existing['sources'].append(result['source'])
                
                # Update confidence based on multiple sources
                if len(existing['sources']) > 1:
                    existing['confidence'] = 'very_high'
        
        return deduplicated
    
    async def enumerate(self, domain: str) -> List[Dict[str, Any]]:
        """Public interface for subdomain enumeration."""
        return await self.execute(domain)
