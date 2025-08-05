#!/usr/bin/env python3
"""
MCP Server Configuration

Simple configuration management for the enhanced MCP server
"""

import os
from pathlib import Path
from typing import Dict, Any

class MCPConfig:
    """Simple MCP server configuration"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self._load_env()
    
    def _load_env(self):
        """Load environment variables from .env file"""
        env_file = self.base_dir / '.env'
        if env_file.exists():
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        if key not in os.environ:
                            os.environ[key] = value
    
    @property
    def server_host(self) -> str:
        """MCP server host"""
        return os.getenv('MCP_HOST', 'localhost')
    
    @property
    def server_port(self) -> int:
        """MCP server port"""
        try:
            return int(os.getenv('MCP_PORT', '8000'))
        except ValueError:
            return 8000
    
    @property
    def log_level(self) -> str:
        """Logging level"""
        return os.getenv('MCP_LOG_LEVEL', 'INFO')
    
    @property
    def enable_audit_logging(self) -> bool:
        """Enable comprehensive audit logging"""
        return os.getenv('MCP_AUDIT_LOGGING', 'true').lower() in ('true', '1', 'yes')
    
    @property
    def api_key_expiry_days(self) -> int:
        """API key expiry in days"""
        try:
            return int(os.getenv('MCP_API_KEY_EXPIRY_DAYS', '90'))
        except ValueError:
            return 90
    
    def get_server_config(self) -> Dict[str, Any]:
        """Get complete server configuration"""
        return {
            'host': self.server_host,
            'port': self.server_port,
            'log_level': self.log_level,
            'audit_logging': self.enable_audit_logging,
            'api_key_expiry_days': self.api_key_expiry_days
        }

# Global config instance
mcp_config = MCPConfig()