#!/usr/bin/env python3
"""
Enhanced MCP Server Setup

Simple setup script for the enhanced MCP server with secure API key management
"""

import os
import sys
from pathlib import Path

# Add current directory to path
sys.path.append(str(Path(__file__).parent))

from mcp.enhanced_mcp_server import EnhancedMCPServer
from config.mcp_config import mcp_config

def setup_enhanced_mcp():
    """Setup enhanced MCP server with initial configuration"""
    
    print("🚀 Enhanced MCP Server Setup")
    print("=" * 50)
    
    # Create server instance
    server = EnhancedMCPServer("network-automation-enhanced")
    
    print("✅ Enhanced MCP server initialized")
    print(f"   - Secure API key management: Enabled")
    print(f"   - Audit logging: Enabled")
    print(f"   - Network context awareness: Enabled")
    print()
    
    # Generate API keys for different clients
    print("🔑 Generating API keys for external Claude access:")
    
    # Claude.ai web interface
    web_key = server.generate_client_api_key(
        "claude_web", 
        ["read", "execute", "network", "config"]
    )
    print(f"   Claude.ai Web: {web_key}")
    
    # Mobile/API clients
    mobile_key = server.generate_client_api_key(
        "claude_mobile",
        ["read", "execute", "network"]
    )
    print(f"   Mobile/API:    {mobile_key}")
    
    # Admin access
    admin_key = server.generate_client_api_key(
        "admin_access",
        ["read", "execute", "network", "config", "admin"]
    )
    print(f"   Admin Access:  {admin_key}")
    
    print()
    print("💾 Configuration saved to:")
    print(f"   - API Keys: {server.base_dir}/config/mcp/api_keys.json")
    print(f"   - Logs: {server.base_dir}/logs/")
    print()
    
    # Display server configuration
    config = mcp_config.get_server_config()
    print("⚙️  Server Configuration:")
    for key, value in config.items():
        print(f"   {key}: {value}")
    
    print()
    print("🎯 Next Steps:")
    print("   1. Save the API keys above for Claude integration")
    print("   2. Run: python mcp/network_mcp_server.py")
    print("   3. Configure Claude.ai to connect to your MCP server")
    print()
    print("✅ Enhanced MCP server setup complete!")

if __name__ == "__main__":
    try:
        setup_enhanced_mcp()
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        sys.exit(1)