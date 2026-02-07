"""Configuration management for the Passive OSINT Platform."""

import os
import yaml
from typing import Dict, Any, Optional
from .exceptions import ConfigurationError


class Config:
    """Configuration manager for the OSINT platform."""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Path to configuration file
        """
        self.config_file = config_file or self._find_config_file()
        self._config = {}
        self.load()
    
    def _find_config_file(self) -> str:
        """Find configuration file in standard locations."""
        possible_paths = [
            "config.yaml",
            os.path.expanduser("~/.osint-recon/config.yaml"),
            "/etc/osint-recon/config.yaml"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Return default path if none found
        return "config.yaml"
    
    def load(self) -> None:
        """Load configuration from file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self._config = yaml.safe_load(f) or {}
            else:
                self._config = self._default_config()
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load config: {e}")
    
    def save(self) -> None:
        """Save configuration to file."""
        try:
            directory = os.path.dirname(self.config_file)
            if directory:
                os.makedirs(directory, exist_ok=True)

            with open(self.config_file, "w", encoding="utf-8") as f:
                yaml.safe_dump(self._config, f, default_flow_style=False)

        except Exception as e:
            raise ConfigurationError(f"Failed to save config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'api_keys.virustotal')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'api_keys.virustotal')
            value: Value to set
        """
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get API key for a specific service.
        
        Args:
            service: Service name (e.g., 'virustotal')
            
        Returns:
            API key or None if not found
        """
        # Check config file first
        api_key = self.get(f'api_keys.{service}')
        if api_key:
            return api_key
        
        # Check environment variables
        env_var = f'OSINT_{service.upper()}_API_KEY'
        return os.getenv(env_var)
    
    def is_module_enabled(self, module: str) -> bool:
        """
        Check if a module is enabled.
        
        Args:
            module: Module name
            
        Returns:
            True if module is enabled
        """
        return self.get(f'modules.{module}.enabled', True)
    
    def get_module_config(self, module: str) -> Dict[str, Any]:
        """
        Get configuration for a specific module.
        
        Args:
            module: Module name
            
        Returns:
            Module configuration
        """
        return self.get(f'modules.{module}', {})
    
    def _default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'api_keys': {},
            'modules': {
                'subdomains': {
                    'enabled': True,
                    'sources': ['virustotal', 'securitytrails', 'wayback', 'crtsh'],
                    'max_results': 1000
                },
                'ports': {
                    'enabled': True,
                    'sources': ['shodan', 'censys'],
                    'common_ports': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443]
                },
                'technologies': {
                    'enabled': True,
                    'sources': ['wappalyzer', 'headers', 'certificates']
                },
                'vulnerabilities': {
                    'enabled': True,
                    'sources': ['cve', 'exploitdb', 'shodan_vulns']
                },
                'credentials': {
                    'enabled': True,
                    'sources': ['breach_database', 'pastebin', 'github_leaks']
                }
            },
            'rate_limits': {
                'virustotal': 4,
                'shodan': 1,
                'censys': 1,
                'securitytrails': 1
            },
            'output': {
                'default_format': 'json',
                'include_raw_data': False,
                'timestamp_format': '%Y-%m-%d %H:%M:%S UTC'
            },
            'logging': {
                'level': 'INFO',
                'file': 'osint_recon.log',
                'max_size': '10MB',
                'backup_count': 5
            }
        }
