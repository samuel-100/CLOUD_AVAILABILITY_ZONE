#!/usr/bin/env python3
"""
Network Automation MCP Server

Complete Model Context Protocol server for network automation with AI integration.
Provides tools for datacenter operations, troubleshooting, and configuration management.
"""

import os
import sys
import json
import asyncio
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from services.fastmcp import NetworkMCPServer
from mcp.enhanced_mcp_server import EnhancedMCPServer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/mcp_server.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

async def run_mcp_server():
    """Run the Network Automation MCP Server"""
    
    print("🤖 Enhanced Network Automation MCP Server")
    print("=" * 60)
    print("Initializing AI-powered network automation tools with enhanced security...")
    
    # Initialize enhanced server
    server = EnhancedMCPServer(name="network-automation-datacenter")
    
    # Generate API key for external Claude access
    demo_key = server.generate_client_api_key("external_claude", ["read", "execute", "network"])
    print(f"🔑 External Claude API Key: {demo_key}")
    print("   (Save this key for Claude.ai web interface integration)")
    print()
    
    # Display available tools
    tools = server.get_available_tools()
    print(f"\n📋 Available MCP Tools ({len(tools)}):")
    print("-" * 40)
    
    tool_descriptions = {
        "test_network_connectivity": "Test ping/SSH to all devices",
        "network_precheck": "Capture baseline network state",
        "network_postcheck": "Validate post-change state", 
        "push_network_config": "Deploy configurations",
        "analyze_network_issue": "AI-powered issue analysis",
        "generate_network_config": "AI configuration generation",
        "get_automation_recommendation": "AI workflow recommendations",
        "get_network_topology": "Retrieve topology information",
        "get_device_status": "Get device status and info",
        "network_chat": "Natural language network interface"
    }
    
    for tool in tools:
        description = tool_descriptions.get(tool, "Network automation tool")
        print(f"  🔧 {tool:<30} - {description}")
    
    print("-" * 60)
    print("🌐 Server Configuration:")
    print(f"  Host: localhost")
    print(f"  Port: 8000") 
    print(f"  Protocol: HTTP/WebSocket")
    print(f"  AI Integration: Anthropic Claude")
    print("-" * 60)
    
    # Start server
    try:
        print("🚀 Starting MCP server...")
        print("   Use Ctrl+C to stop the server")
        print("=" * 60)
        
        await server.start_server(host="localhost", port=8000)
        
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        print(f"❌ Server error: {e}")

def create_mcp_config():
    """Create MCP configuration file for Kiro IDE integration"""
    
    config = {
        "mcpServers": {
            "network-automation": {
                "command": "python",
                "args": [
                    str(Path(__file__).absolute())
                ],
                "cwd": str(Path(__file__).parent.parent),
                "env": {
                    "PYTHONPATH": str(Path(__file__).parent.parent),
                    "FASTMCP_LOG_LEVEL": "INFO"
                },
                "disabled": False,
                "autoApprove": [
                    "test_network_connectivity",
                    "get_network_topology", 
                    "get_device_status",
                    "network_chat"
                ]
            }
        }
    }
    
    # Save to .kiro/settings/mcp.json
    kiro_dir = Path(__file__).parent.parent.parent / ".kiro" / "settings"
    kiro_dir.mkdir(parents=True, exist_ok=True)
    
    mcp_config_file = kiro_dir / "mcp.json"
    
    try:
        # Load existing config if it exists
        existing_config = {}
        if mcp_config_file.exists():
            with open(mcp_config_file) as f:
                existing_config = json.load(f)
        
        # Merge configurations
        if "mcpServers" not in existing_config:
            existing_config["mcpServers"] = {}
        
        existing_config["mcpServers"].update(config["mcpServers"])
        
        # Save updated config
        with open(mcp_config_file, 'w') as f:
            json.dump(existing_config, f, indent=2)
        
        print(f"✅ MCP configuration saved to: {mcp_config_file}")
        
    except Exception as e:
        print(f"❌ Failed to save MCP config: {e}")

def main():
    """Main entry point"""
    
    # Create MCP configuration
    create_mcp_config()
    
    # Run server
    try:
        asyncio.run(run_mcp_server())
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()