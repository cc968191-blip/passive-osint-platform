"""Technology stack identification module using passive OSINT sources."""

import aiohttp
import asyncio
import re
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse

from .base import BaseModule
from ..core.exceptions import APIError, NetworkError


class TechnologyIdentifier(BaseModule):
    """Passive technology stack identification using multiple sources."""
    
    def __init__(self, config):
        """Initialize technology identifier."""
        super().__init__(config)
        self.sources = self.config.get_module_config('technologies').get('sources', [])
        
        # Technology detection patterns
        self.technology_patterns = {
            'web_servers': {
                'apache': [r'Apache[/\s](\d+\.\d+\.\d+)', r'Server: Apache'],
                'nginx': [r'nginx[/\s](\d+\.\d+\.\d+)', r'Server: nginx'],
                'iis': [r'IIS[/\s](\d+\.\d+)', r'Server: Microsoft-IIS'],
                'cloudflare': [r'cloudflare', r'server: cloudflare'],
                'litespeed': [r'LiteSpeed', r'Server: LiteSpeed']
            },
            'frameworks': {
                'wordpress': [r'wp-content', r'WordPress', r'wp-json'],
                'drupal': [r'Drupal', r'Drupal.settings'],
                'joomla': [r'Joomla', r'joomla'],
                'magento': [r'Magento', r'Mage.Cookies'],
                'shopify': [r'Shopify', r'shopify'],
                'django': [r'Django', r'csrftoken'],
                'flask': [r'Flask', r'Werkzeug'],
                'rails': [r'Rails', r'Ruby on Rails'],
                'express': [r'Express', r'X-Powered-By: Express'],
                'spring': [r'Spring', r'X-Application-Context'],
                'laravel': [r'Laravel', r'X-Powered-By: Laravel']
            },
            'analytics': {
                'google_analytics': [r'google-analytics.com', r'ga.js', r'analytics.js'],
                'google_tag_manager': [r'googletagmanager.com', r'GTM-'],
                'hotjar': [r'hotjar.com', r'hj-'],
                'mixpanel': [r'mixpanel.com', r'mixpanel'],
                'segment': [r'segment.io', r'analytics.js']
            },
            'cdn': {
                'cloudflare': [r'cloudflare', r'cf-ray'],
                'cloudfront': [r'cloudfront', r'aws'],
                'fastly': [r'fastly', r'fastly'],
                'akamai': [r'akamai', r'AkamaiGHost'],
                'maxcdn': [r'maxcdn', r'maxcdn']
            },
            'databases': {
                'mysql': [r'mysql', r'MySQL'],
                'postgresql': [r'postgresql', r'PostgreSQL'],
                'mongodb': [r'mongodb', r'MongoDB'],
                'redis': [r'redis', r'Redis'],
                'elasticsearch': [r'elasticsearch', r'Elasticsearch']
            }
        }
    
    async def execute(self, domain: str) -> List[Dict[str, Any]]:
        """
        Execute technology identification.
        
        Args:
            domain: Target domain
            
        Returns:
            List of technology identification results
        """
        all_technologies = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            if 'headers' in self.sources:
                tasks.append(self._analyze_headers(session, domain))
            
            if 'wappalyzer' in self.sources:
                tasks.append(self._query_wappalyzer(session, domain))
            
            if 'certificates' in self.sources:
                tasks.append(self._analyze_certificates(session, domain))
            
            # Execute all analyses concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"Technology identification source error: {result}")
                elif isinstance(result, list):
                    all_technologies.extend(result)
        
        # Consolidate and organize results
        consolidated = self._consolidate_technologies(all_technologies)
        
        return consolidated
    
    async def _analyze_headers(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Analyze HTTP headers to identify technologies."""
        technologies = []
        
        # Try common HTTPS and HTTP ports
        urls = [f"https://{domain}", f"http://{domain}"]
        
        for url in urls:
            try:
                await self.rate_limit('http_headers')
                
                async with session.head(url, timeout=10, allow_redirects=True) as response:
                    headers = dict(response.headers)
                    
                    # Analyze headers for technology indicators
                    detected = self._analyze_response_headers(headers, url)
                    
                    for tech in detected:
                        result = self.create_result(
                            source='headers',
                            data={
                                'technology': tech['name'],
                                'category': tech['category'],
                                'version': tech.get('version'),
                                'confidence': tech['confidence'],
                                'evidence': tech['evidence'],
                                'url': url
                            }
                        )
                        technologies.append(result)
                    
                    break  # Success, no need to try other URLs
                    
            except Exception as e:
                self.logger.debug(f"Header analysis failed for {url}: {e}")
                continue
        
        self.logger.info(f"Header analysis found {len(technologies)} technologies")
        return technologies
    
    def _analyze_response_headers(self, headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
        """Analyze HTTP response headers for technology indicators."""
        detected = []
        
        # Check server header
        server = headers.get('Server', '').lower()
        if server:
            for tech_name, patterns in self.technology_patterns['web_servers'].items():
                for pattern in patterns:
                    if re.search(pattern, server, re.IGNORECASE):
                        version_match = re.search(r'(\d+\.\d+\.\d+)', server)
                        detected.append({
                            'name': tech_name,
                            'category': 'web_server',
                            'version': version_match.group(1) if version_match else None,
                            'confidence': 'high',
                            'evidence': f"Server header: {headers.get('Server')}"
                        })
                        break
        
        # Check X-Powered-By header
        powered_by = headers.get('X-Powered-By', '').lower()
        if powered_by:
            frameworks = {
                'php': 'PHP',
                'asp.net': 'ASP.NET',
                'express': 'Express',
                'laravel': 'Laravel',
                'django': 'Django'
            }
            
            for framework, name in frameworks.items():
                if framework in powered_by:
                    detected.append({
                        'name': name,
                        'category': 'framework',
                        'version': None,
                        'confidence': 'medium',
                        'evidence': f"X-Powered-By header: {headers.get('X-Powered-By')}"
                    })
        
        # Check other technology-specific headers
        tech_headers = {
            'X-Drupal-Cache': ('Drupal', 'framework'),
            'X-Generator': ('Joomla', 'framework'),
            'X-Pingback': ('WordPress', 'framework'),
            'X-Varnish': ('Varnish', 'cache'),
            'CF-RAY': ('Cloudflare', 'cdn'),
            'X-CDN': ('CDN', 'cdn')
        }
        
        for header, (tech, category) in tech_headers.items():
            if header in headers:
                detected.append({
                    'name': tech,
                    'category': category,
                    'version': None,
                    'confidence': 'medium',
                    'evidence': f"{header} header present"
                })
        
        return detected
    
    async def _query_wappalyzer(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Query Wappalyzer API for technology detection."""
        # Note: This would require Wappalyzer API integration
        # For now, implement a basic version using public patterns
        
        technologies = []
        
        try:
            # Fetch homepage content
            url = f"https://{domain}"
            await self.rate_limit('wappalyzer')
            
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    detected = self._analyze_html_content(content, url)
                    
                    for tech in detected:
                        result = self.create_result(
                            source='wappalyzer',
                            data={
                                'technology': tech['name'],
                                'category': tech['category'],
                                'version': tech.get('version'),
                                'confidence': tech['confidence'],
                                'evidence': tech['evidence'],
                                'url': url
                            }
                        )
                        technologies.append(result)
        
        except Exception as e:
            self.logger.error(f"Wappalyzer analysis failed: {e}")
        
        self.logger.info(f"Wappalyzer analysis found {len(technologies)} technologies")
        return technologies
    
    def _analyze_html_content(self, content: str, url: str) -> List[Dict[str, Any]]:
        """Analyze HTML content for technology indicators."""
        detected = []
        content_lower = content.lower()
        
        # Check for meta generators
        meta_generator_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', content_lower)
        if meta_generator_match:
            generator = meta_generator_match.group(1)
            
            if 'wordpress' in generator:
                version_match = re.search(r'(\d+\.\d+\.\d+)', generator)
                detected.append({
                    'name': 'WordPress',
                    'category': 'cms',
                    'version': version_match.group(1) if version_match else None,
                    'confidence': 'high',
                    'evidence': f"Meta generator: {generator}"
                })
        
        # Check for common technology patterns
        for category, techs in self.technology_patterns.items():
            for tech_name, patterns in techs.items():
                for pattern in patterns:
                    if re.search(pattern, content_lower, re.IGNORECASE):
                        detected.append({
                            'name': tech_name,
                            'category': category,
                            'version': None,
                            'confidence': 'medium',
                            'evidence': f"HTML pattern match: {pattern}"
                        })
                        break
        
        return detected
    
    async def _analyze_certificates(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Analyze SSL certificates for technology indicators."""
        technologies = []
        
        try:
            # Get SSL certificate information
            url = f"https://{domain}"
            await self.rate_limit('certificates')
            
            async with session.get(url, timeout=10) as response:
                # Extract certificate info from response (simplified)
                # In a real implementation, you'd use ssl module or similar
                
                # Check for common hosting providers based on certificate issuer
                # This is a simplified version
                pass
        
        except Exception as e:
            self.logger.debug(f"Certificate analysis failed: {e}")
        
        self.logger.info(f"Certificate analysis found {len(technologies)} technologies")
        return technologies
    
    def _consolidate_technologies(self, technologies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Consolidate technology detection results from multiple sources.
        
        Args:
            technologies: List of technology detection results
            
        Returns:
            Consolidated list
        """
        consolidated = {}
        
        for result in technologies:
            tech_name = result['data']['technology']
            
            if tech_name not in consolidated:
                consolidated[tech_name] = {
                    'technology': tech_name,
                    'category': result['data']['category'],
                    'version': result['data'].get('version'),
                    'confidence': result['data']['confidence'],
                    'sources': [result['source']],
                    'evidence': [result['data']['evidence']],
                    'urls': [result['data'].get('url')]
                }
            else:
                # Merge information from multiple sources
                existing = consolidated[tech_name]
                
                if result['source'] not in existing['sources']:
                    existing['sources'].append(result['source'])
                
                if result['data']['evidence'] not in existing['evidence']:
                    existing['evidence'].append(result['data']['evidence'])
                
                if result['data'].get('url') and result['data']['url'] not in existing['urls']:
                    existing['urls'].append(result['data']['url'])
                
                # Update confidence based on multiple sources
                if len(existing['sources']) > 1:
                    existing['confidence'] = 'very_high'
                elif existing['confidence'] == 'low' and result['data']['confidence'] == 'medium':
                    existing['confidence'] = 'medium'
                
                # Prefer version from higher confidence source
                if (result['data'].get('version') and 
                    (not existing['version'] or result['data']['confidence'] == 'high')):
                    existing['version'] = result['data']['version']
        
        # Convert to list and sort by confidence
        result_list = list(consolidated.values())
        
        # Sort by confidence level
        confidence_order = {'very_high': 4, 'high': 3, 'medium': 2, 'low': 1}
        result_list.sort(key=lambda x: confidence_order.get(x['confidence'], 0), reverse=True)
        
        return result_list
    
    async def identify(self, domain: str) -> List[Dict[str, Any]]:
        """Public interface for technology identification."""
        return await self.execute(domain)
