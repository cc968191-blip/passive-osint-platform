"""Base class for all OSINT modules."""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from ..core.config import Config
from ..core.exceptions import APIError, RateLimitError, NetworkError


class BaseModule(ABC):
    """Base class for all OSINT reconnaissance modules."""
    
    def __init__(self, config: Config):
        """
        Initialize the base module.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(f'osint_recon.{self.__class__.__name__.lower()}')
        self.rate_limits = {}
        self.last_request_times = {}
    
    @abstractmethod
    async def execute(self, target: str) -> List[Dict[str, Any]]:
        """
        Execute the module's main functionality.
        
        Args:
            target: Target domain or identifier
            
        Returns:
            List of results
        """
        pass
    
    async def rate_limit(self, service: str) -> None:
        """
        Apply rate limiting for API requests.
        
        Args:
            service: Service name for rate limiting
        """
        rate_limit = self.config.get(f'rate_limits.{service}', 1)
        current_time = datetime.now(timezone.utc).timestamp()
        
        if service in self.last_request_times:
            time_since_last = current_time - self.last_request_times[service]
            min_interval = 60 / rate_limit if rate_limit > 60 else 1 / rate_limit
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                self.logger.debug(f"Rate limiting {service}: sleeping {sleep_time:.2f}s")
                await asyncio.sleep(sleep_time)
        
        self.last_request_times[service] = datetime.now(timezone.utc).timestamp()
    
    async def make_request(self, session, url: str, service: str, **kwargs) -> Any:
        """
        Make an HTTP request with error handling and rate limiting.
        
        Args:
            session: aiohttp session
            url: Request URL
            service: Service name for rate limiting
            **kwargs: Additional request parameters
            
        Returns:
            Response data
            
        Raises:
            APIError: If request fails
        """
        await self.rate_limit(service)
        
        try:
            async with session.get(url, **kwargs) as response:
                if response.status == 429:
                    raise RateLimitError(f"Rate limit exceeded for {service}")
                elif response.status == 401:
                    raise APIError(f"Authentication failed for {service}", response.status)
                elif response.status == 403:
                    raise APIError(f"Access forbidden for {service}", response.status)
                elif response.status >= 400:
                    raise APIError(f"HTTP {response.status} for {service}", response.status)
                
                return await response.json()
        
        except asyncio.TimeoutError:
            raise NetworkError(f"Request timeout for {service}")
        except Exception as e:
            if isinstance(e, (APIError, RateLimitError, NetworkError)):
                raise
            raise NetworkError(f"Network error for {service}: {e}")
    
    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get API key for a service.
        
        Args:
            service: Service name
            
        Returns:
            API key or None
        """
        return self.config.get_api_key(service)
    
    def validate_result(self, result: Dict[str, Any]) -> bool:
        """
        Validate a result entry.
        
        Args:
            result: Result dictionary
            
        Returns:
            True if valid
        """
        required_fields = self.get_required_fields()
        return all(field in result for field in required_fields)
    
    def get_required_fields(self) -> List[str]:
        """
        Get required fields for results.
        
        Returns:
            List of required field names
        """
        return ['source', 'timestamp', 'data']
    
    def create_result(self, source: str, data: Any, **metadata) -> Dict[str, Any]:
        """
        Create a standardized result entry.
        
        Args:
            source: Data source name
            data: Result data
            **metadata: Additional metadata
            
        Returns:
            Standardized result dictionary
        """
        result = {
            'source': source,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': data
        }
        result.update(metadata)
        return result
    
    def filter_duplicates(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate results based on data content.
        
        Args:
            results: List of results
            
        Returns:
            Filtered list without duplicates
        """
        seen = set()
        filtered = []
        
        for result in results:
            # Create a hashable representation of the data
            data_str = str(result.get('data', ''))
            if data_str not in seen:
                seen.add(data_str)
                filtered.append(result)
        
        return filtered
    
    def sort_results(self, results: List[Dict[str, Any]], sort_key: str = 'timestamp') -> List[Dict[str, Any]]:
        """
        Sort results by a specific key.
        
        Args:
            results: List of results
            sort_key: Key to sort by
            
        Returns:
            Sorted list
        """
        return sorted(results, key=lambda x: x.get(sort_key, ''), reverse=True)
