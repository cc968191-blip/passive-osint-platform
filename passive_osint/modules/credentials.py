"""Credential leak detection module using passive OSINT sources."""

import aiohttp
import asyncio
import re
import base64
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, quote

from .base import BaseModule
from ..core.exceptions import APIError, NetworkError


class CredentialLeakDetector(BaseModule):
    """Passive credential leak detection using multiple OSINT sources."""
    
    def __init__(self, config):
        """Initialize credential leak detector."""
        super().__init__(config)
        self.sources = self.config.get_module_config('credentials').get('sources', [])
        
        # Common credential patterns
        self.credential_patterns = {
            'api_keys': [
                r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?',
                r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?',
                r'(?i)(access[_-]?token|accesstoken)\s*[:=]\s*["\']?([a-zA-Z0-9._-]{16,})["\']?'
            ],
            'database_credentials': [
                r'(?i)(mysql|postgres|mongodb|redis)\s*[:=]\s*["\']?([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+)@',
                r'(?i)(db[_-]?user|databaseuser)\s*[:=]\s*["\']?([a-zA-Z0-9._-]+)["\']?',
                r'(?i)(db[_-]?pass|databasepass)\s*[:=]\s*["\']?([a-zA-Z0-9._-]{8,})["\']?'
            ],
            'aws_credentials': [
                r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?',
                r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
                r'(?i)aws[_-]?session[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{300,})["\']?'
            ],
            'private_keys': [
                r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
                r'-----BEGIN PGP PRIVATE KEY BLOCK-----'
            ],
            'passwords': [
                r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{6,})["\']?',
                r'(?i)(pass|secret)\s*[:=]\s*["\']?([^\s"\']{6,})["\']?'
            ]
        }
        
        # False positive patterns
        self.false_positive_patterns = [
            r'password123',
            r'example\.com',
            r'test[_-]?password',
            r'demo[_-]?key',
            r'xxx',
            r'yyy',
            r'zzz',
            r'placeholder',
            r'sample'
        ]
    
    async def execute(self, domain: str) -> List[Dict[str, Any]]:
        """
        Execute credential leak detection.
        
        Args:
            domain: Target domain
            
        Returns:
            List of credential leak results
        """
        all_credentials = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            if 'breach_database' in self.sources:
                tasks.append(self._check_breach_databases(session, domain))
            
            if 'pastebin' in self.sources:
                tasks.append(self._check_pastebin(session, domain))
            
            if 'github_leaks' in self.sources:
                tasks.append(self._check_github_leaks(session, domain))
            
            # Execute all checks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"Credential leak source error: {result}")
                elif isinstance(result, list):
                    all_credentials.extend(result)
        
        # Remove false positives and deduplicate
        filtered_credentials = self._filter_false_positives(all_credentials)
        unique_credentials = self._deduplicate_credentials(filtered_credentials)
        
        return unique_credentials
    
    async def _check_breach_databases(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Check public breach databases for credential leaks."""
        credentials = []
        
        try:
            # This would typically query breach databases like HaveIBeenPwned
            # For demonstration, simulate some breach data
            
            # Note: In a real implementation, you'd need proper API keys
            # and compliance with breach database terms of service
            
            breach_data = [
                {
                    'breach_name': 'Example Data Breach 2023',
                    'breach_date': '2023-03-15',
                    'data_types': ['Email addresses', 'Passwords', 'Usernames'],
                    'accounts_affected': 10000,
                    'description': 'A breach of example.com user database',
                    'domain': domain,
                    'severity': 'High'
                }
            ]
            
            for breach in breach_data:
                result = self.create_result(
                    source='breach_database',
                    data={
                        'breach_name': breach['breach_name'],
                        'breach_date': breach['breach_date'],
                        'data_types': breach['data_types'],
                        'accounts_affected': breach['accounts_affected'],
                        'description': breach['description'],
                        'domain': breach['domain'],
                        'severity': breach['severity'],
                        'detection_method': 'breach_database_query'
                    }
                )
                credentials.append(result)
            
        except Exception as e:
            self.logger.error(f"Breach database check failed: {e}")
        
        self.logger.info(f"Breach database check found {len(credentials)} potential breaches")
        return credentials
    
    async def _check_pastebin(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Check Pastebin and similar sites for credential leaks."""
        credentials = []
        
        try:
            # Search for domain-related pastes
            search_queries = [
                domain,
                f"@{domain}",
                f"password {domain}",
                f"api_key {domain}"
            ]
            
            for query in search_queries:
                await self.rate_limit('pastebin')
                
                # Note: This would use Pastebin API or similar
                # For demonstration, simulate finding some potential leaks
                
                # Simulate finding credential patterns in pastes
                paste_data = {
                    'paste_id': 'example123',
                    'title': f'Config file for {domain}',
                    'author': 'anonymous',
                    'date': '2023-10-15',
                    'syntax': 'text',
                    'content_preview': f'# Config for {domain}\ndb_user=admin\ndb_pass=example123\napi_key=sk-1234567890abcdef',
                    'url': 'https://pastebin.com/raw/example123',
                    'matches': []
                }
                
                # Check for credential patterns in content
                content = paste_data['content_preview']
                matches = self._extract_credentials_from_text(content, query)
                
                if matches:
                    paste_data['matches'] = matches
                    
                    result = self.create_result(
                        source='pastebin',
                        data={
                            'paste_id': paste_data['paste_id'],
                            'title': paste_data['title'],
                            'author': paste_data['author'],
                            'date': paste_data['date'],
                            'url': paste_data['url'],
                            'matches': matches,
                            'search_query': query,
                            'detection_method': 'pattern_matching'
                        }
                    )
                    credentials.append(result)
            
        except Exception as e:
            self.logger.error(f"Pastebin check failed: {e}")
        
        self.logger.info(f"Pastebin check found {len(credentials)} potential credential leaks")
        return credentials
    
    async def _check_github_leaks(self, session: aiohttp.ClientSession, domain: str) -> List[Dict[str, Any]]:
        """Check GitHub for potential credential leaks."""
        credentials = []
        
        github_token = self.get_api_key('github')
        if not github_token:
            self.logger.warning("GitHub token not found, using limited search")
        
        try:
            # Search GitHub for potential credential leaks
            search_queries = [
                f"{domain} password",
                f"{domain} api_key",
                f"{domain} secret",
                f"site:github.com {domain} config"
            ]
            
            for query in search_queries:
                await self.rate_limit('github')
                
                # Note: This would use GitHub Search API
                # For demonstration, simulate finding some potential leaks
                
                # Simulate finding credential patterns in GitHub repositories
                repo_data = {
                    'repository': 'example/config-backup',
                    'owner': 'example-user',
                    'file_path': 'config/production.env',
                    'commit_sha': 'abc123def456',
                    'file_url': 'https://github.com/example/config-backup/blob/main/config/production.env',
                    'content_preview': f'# Production config for {domain}\nDATABASE_URL=postgres://user:pass123@{domain}:5432/db\nAPI_KEY=sk-abcdef1234567890',
                    'matches': []
                }
                
                # Check for credential patterns in content
                content = repo_data['content_preview']
                matches = self._extract_credentials_from_text(content, query)
                
                if matches:
                    repo_data['matches'] = matches
                    
                    result = self.create_result(
                        source='github_leaks',
                        data={
                            'repository': repo_data['repository'],
                            'owner': repo_data['owner'],
                            'file_path': repo_data['file_path'],
                            'commit_sha': repo_data['commit_sha'],
                            'file_url': repo_data['file_url'],
                            'matches': matches,
                            'search_query': query,
                            'detection_method': 'pattern_matching'
                        }
                    )
                    credentials.append(result)
            
        except Exception as e:
            self.logger.error(f"GitHub leak check failed: {e}")
        
        self.logger.info(f"GitHub leak check found {len(credentials)} potential credential leaks")
        return credentials
    
    def _extract_credentials_from_text(self, text: str, context: str) -> List[Dict[str, Any]]:
        """
        Extract credential patterns from text content.
        
        Args:
            text: Text content to analyze
            context: Search context for better accuracy
            
        Returns:
            List of credential matches
        """
        matches = []
        
        for category, patterns in self.credential_patterns.items():
            for pattern in patterns:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    # Extract the matched credential
                    if match.groups():
                        credential_value = match.groups()[-1]  # Get the last group (the actual credential)
                        
                        # Skip if it's a known false positive
                        if self._is_false_positive(credential_value):
                            continue
                        
                        match_info = {
                            'category': category,
                            'pattern': pattern,
                            'match': match.group(0),
                            'credential_value': credential_value,
                            'line_number': text[:match.start()].count('\n') + 1,
                            'context': context,
                            'confidence': self._calculate_confidence(credential_value, category)
                        }
                        
                        matches.append(match_info)
        
        return matches
    
    def _is_false_positive(self, credential: str) -> bool:
        """
        Check if a credential is likely a false positive.
        
        Args:
            credential: Credential value to check
            
        Returns:
            True if likely false positive
        """
        credential_lower = credential.lower()
        
        for pattern in self.false_positive_patterns:
            if re.search(pattern, credential_lower):
                return True
        
        # Check for obviously fake credentials
        if len(credential) < 8:
            return True
        
        if credential_lower in ['password', 'secret', 'key', 'token', 'admin', 'user']:
            return True
        
        return False
    
    def _calculate_confidence(self, credential: str, category: str) -> str:
        """
        Calculate confidence level for credential detection.
        
        Args:
            credential: Credential value
            category: Credential category
            
        Returns:
            Confidence level (low, medium, high)
        """
        confidence = 'medium'
        
        # High confidence indicators
        if category == 'private_keys':
            confidence = 'high'
        elif category == 'aws_credentials' and len(credential) > 20:
            confidence = 'high'
        elif category == 'api_keys' and len(credential) > 32:
            confidence = 'high'
        
        # Low confidence indicators
        if len(credential) < 16:
            confidence = 'low'
        elif credential.lower() in ['test', 'demo', 'example']:
            confidence = 'low'
        
        return confidence
    
    def _filter_false_positives(self, credentials: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter out likely false positives from results.
        
        Args:
            credentials: List of credential results
            
        Returns:
            Filtered list
        """
        filtered = []
        
        for result in credentials:
            data = result['data']
            
            # Filter based on matches
            if 'matches' in data:
                valid_matches = []
                for match in data['matches']:
                    if not self._is_false_positive(match['credential_value']):
                        valid_matches.append(match)
                
                if valid_matches:
                    data['matches'] = valid_matches
                    filtered.append(result)
            else:
                # For breach data, keep it but mark for review
                if data.get('severity') == 'High':
                    filtered.append(result)
        
        return filtered
    
    def _deduplicate_credentials(self, credentials: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate credential entries.
        
        Args:
            credentials: List of credential results
            
        Returns:
            Deduplicated list
        """
        seen = set()
        deduplicated = []
        
        for result in credentials:
            data = result['data']
            
            # Create unique identifier
            if 'paste_id' in data:
                identifier = f"paste_{data['paste_id']}"
            elif 'repository' in data and 'file_path' in data:
                identifier = f"github_{data['repository']}_{data['file_path']}"
            elif 'breach_name' in data:
                identifier = f"breach_{data['breach_name']}"
            else:
                identifier = str(hash(str(data)))
            
            if identifier not in seen:
                seen.add(identifier)
                deduplicated.append(result)
        
        return deduplicated
    
    def _assess_risk_level(self, credential_data: Dict[str, Any]) -> str:
        """
        Assess risk level for credential leak.
        
        Args:
            credential_data: Credential leak data
            
        Returns:
            Risk level (Critical, High, Medium, Low)
        """
        risk_score = 0
        
        # Check credential categories
        if 'matches' in credential_data:
            for match in credential_data['matches']:
                category = match['category']
                confidence = match['confidence']
                
                if category == 'private_keys':
                    risk_score += 40
                elif category == 'aws_credentials':
                    risk_score += 35
                elif category == 'api_keys':
                    risk_score += 30
                elif category == 'database_credentials':
                    risk_score += 25
                elif category == 'passwords':
                    risk_score += 20
                
                # Confidence weighting
                if confidence == 'high':
                    risk_score += 10
                elif confidence == 'medium':
                    risk_score += 5
        
        # Source weighting
        source = credential_data.get('source', '')
        if source == 'github_leaks':
            risk_score += 15
        elif source == 'pastebin':
            risk_score += 10
        elif source == 'breach_database':
            risk_score += 20
        
        # Determine risk level
        if risk_score >= 50:
            return 'Critical'
        elif risk_score >= 35:
            return 'High'
        elif risk_score >= 20:
            return 'Medium'
        else:
            return 'Low'
    
    async def detect(self, domain: str) -> List[Dict[str, Any]]:
        """Public interface for credential leak detection."""
        results = await self.execute(domain)
        
        # Add risk assessment
        for result in results:
            data = result['data']
            data['risk_level'] = self._assess_risk_level(data)
            data['recommendations'] = self._get_recommendations(data)
        
        return results
    
    def _get_recommendations(self, credential_data: Dict[str, Any]) -> List[str]:
        """
        Get recommendations based on credential leak data.
        
        Args:
            credential_data: Credential leak data
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        risk_level = credential_data.get('risk_level', 'Medium')
        source = credential_data.get('source', '')
        
        if risk_level == 'Critical':
            recommendations.append('IMMEDIATE ACTION REQUIRED: Rotate all exposed credentials')
            recommendations.append('Review access logs for unauthorized usage')
            recommendations.append('Implement additional monitoring and alerting')
        elif risk_level == 'High':
            recommendations.append('Rotate exposed credentials within 24 hours')
            recommendations.append('Audit systems that may have used exposed credentials')
        elif risk_level == 'Medium':
            recommendations.append('Rotate exposed credentials within 7 days')
            recommendations.append('Review and update credential management policies')
        else:
            recommendations.append('Review exposed credentials for validity')
            recommendations.append('Update credential management practices')
        
        # Source-specific recommendations
        if source == 'github_leaks':
            recommendations.append('Implement pre-commit hooks to prevent credential commits')
            recommendations.append('Review repository access permissions')
        elif source == 'pastebin':
            recommendations.append('Monitor paste sites for future leaks')
            recommendations.append('Implement data loss prevention measures')
        elif source == 'breach_database':
            recommendations.append('Notify affected users if applicable')
            recommendations.append('Review breach notification requirements')
        
        return recommendations
