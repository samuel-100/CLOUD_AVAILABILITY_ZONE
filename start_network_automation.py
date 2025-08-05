#!/usr/bin/env python3
"""
Network Automation Startup Script

Quick launcher for all network automation capabilities including:
- AI Agent with Claude integration
- FastMCP server with network tools
- Complete automation workflows
- Chat interface for natural language operations
"""

import os
import sys
import asyncio
import argparse
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from services.automation import NetworkAutomationOrchestrator

def print_banner():
    """Print startup banner"""
    print("""
🤖 NETWORK AUTOMATION SYSTEM
═══════════════════════════════════════════════════════════════
🏢 Datacenter: CLOUD_AVAILABILITY_ZONE (Spine-Leaf CLOS)
🔧 Protocols: OSPF, BGP, VXLAN, EVPN, BFD
🤖 AI Engine: Anthropic Claude
🌐 MCP Server: FastMCP with network tools
📱 Interface: CLI, Chat, and API
═══════════════════════════════════════════════════════════════
""")

def print_menu():
    """Print main menu"""
    print("""
🚀 AVAILABLE OPERATIONS:

📋 WORKFLOWS:
  1. Full Health Check        - Complete network assessment
  2. Pre-Change Validation    - Baseline capture before changes  
  3. Post-Change Validation   - Verify changes and state
  4. Configuration Deployment - Deploy configs with validation
  5. AI Troubleshooting       - Intelligent issue analysis
  6. Config Generation        - AI-powered configuration creation

🛠️ SERVICES:
  7. Test Connectivity        - Ping/SSH test all devices
  8. Run Precheck            - Capture current state
  9. Run Postcheck           - Validate current state
  10. Push Configuration      - Deploy configurations

🤖 AI INTERFACES:
  11. Chat Interface          - Natural language operations
  12. Start MCP Server        - Enable external tool access

0. Exit
""")

async def interactive_mode():
    """Interactive menu mode"""
    orchestrator = NetworkAutomationOrchestrator()
    
    while True:
        print_menu()
        
        try:
            choice = input("🎯 Select operation (0-12): ").strip()
            
            if choice == "0":
                print("👋 Goodbye!")
                break
            
            elif choice == "1":
                print("\n" + "="*60)
                result = orchestrator.execute_workflow("full_health_check")
                print(f"\n📊 Result: {result.message}")
            
            elif choice == "2":
                print("\n" + "="*60)
                result = orchestrator.execute_workflow("pre_change_validation")
                print(f"\n📊 Result: {result.message}")
            
            elif choice == "3":
                print("\n" + "="*60)
                result = orchestrator.execute_workflow("post_change_validation")
                print(f"\n📊 Result: {result.message}")
            
            elif choice == "4":
                print("\n" + "="*60)
                result = orchestrator.execute_workflow("configuration_deployment")
                print(f"\n📊 Result: {result.message}")
            
            elif choice == "5":
                issue = input("🔍 Describe the network issue: ").strip()
                if issue:
                    print("\n" + "="*60)
                    result = orchestrator.execute_workflow("ai_troubleshooting", issue=issue)
                    print(f"\n📊 Result: {result.message}")
            
            elif choice == "6":
                request = input("⚙️ Describe configuration needed: ").strip()
                if request:
                    print("\n" + "="*60)
                    result = orchestrator.execute_workflow("intelligent_config_generation", request=request)
                    print(f"\n📊 Result: {result.message}")
            
            elif choice == "7":
                print("\n🔗 Testing connectivity...")
                from services.test_connectivity import main as test_conn
                result = test_conn()
                print(f"✅ Connectivity test: {'PASSED' if result else 'FAILED'}")
            
            elif choice == "8":
                print("\n📋 Running precheck...")
                from services.precheck import main as precheck
                result = precheck()
                print(f"✅ Precheck: {'COMPLETED' if result else 'FAILED'}")
            
            elif choice == "9":
                print("\n✅ Running postcheck...")
                from services.postcheck import main as postcheck
                result = postcheck()
                print(f"✅ Postcheck: {'COMPLETED' if result else 'FAILED'}")
            
            elif choice == "10":
                print("\n🚀 Pushing configuration...")
                from services.push_config import main as push_cfg
                result = push_cfg()
                print(f"✅ Config push: {'COMPLETED' if result else 'FAILED'}")
            
            elif choice == "11":
                print("\n🤖 Starting chat interface...")
                print("Type 'back' to return to main menu")
                print("-" * 40)
                
                while True:
                    user_input = input("\n💬 You: ").strip()
                    if user_input.lower() == 'back':
                        break
                    
                    response = orchestrator.chat_interface(user_input)
                    print(f"🤖 AI: {response}")
            
            elif choice == "12":
                print("\n🌐 Starting MCP server...")
                print("Server will run on localhost:8000")
                print("Press Ctrl+C to stop")
                try:
                    await orchestrator.start_mcp_server()
                except KeyboardInterrupt:
                    print("\n🛑 MCP server stopped")
            
            else:
                print("❌ Invalid choice. Please select 0-12.")
            
            if choice not in ["0", "11", "12"]:
                input("\n⏸️  Press Enter to continue...")
        
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            input("\n⏸️  Press Enter to continue...")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Network Automation System")
    parser.add_argument("--interactive", "-i", action="store_true", 
                       help="Start interactive mode")
    parser.add_argument("--mcp-server", action="store_true",
                       help="Start MCP server directly")
    parser.add_argument("--chat", action="store_true",
                       help="Start chat interface directly")
    parser.add_argument("--workflow", choices=[
        "health_check", "pre_validation", "post_validation", 
        "deploy", "troubleshoot", "generate_config"
    ], help="Run specific workflow")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.mcp_server:
        print("🌐 Starting MCP Server...")
        orchestrator = NetworkAutomationOrchestrator()
        asyncio.run(orchestrator.start_mcp_server())
    
    elif args.chat:
        print("🤖 Starting Chat Interface...")
        orchestrator = NetworkAutomationOrchestrator()
        
        while True:
            try:
                user_input = input("\n💬 You: ").strip()
                if user_input.lower() in ['exit', 'quit']:
                    break
                
                response = orchestrator.chat_interface(user_input)
                print(f"🤖 AI: {response}")
            except KeyboardInterrupt:
                break
    
    elif args.workflow:
        orchestrator = NetworkAutomationOrchestrator()
        
        workflow_map = {
            "health_check": "full_health_check",
            "pre_validation": "pre_change_validation", 
            "post_validation": "post_change_validation",
            "deploy": "configuration_deployment",
            "troubleshoot": "ai_troubleshooting",
            "generate_config": "intelligent_config_generation"
        }
        
        workflow = workflow_map[args.workflow]
        result = orchestrator.execute_workflow(workflow)
        print(f"\n📊 Result: {result.message}")
    
    elif args.interactive or len(sys.argv) == 1:
        asyncio.run(interactive_mode())
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()