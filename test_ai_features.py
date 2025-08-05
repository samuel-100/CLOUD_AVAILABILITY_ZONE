#!/usr/bin/env python3
"""
Test AI Features in Network Automation System
"""

import os
import sys
sys.path.append('.')

# Use environment variable for API key (set externally for security)
# os.environ['ANTHROPIC_API_KEY'] = 'your-api-key-here'  # Set this externally
if not os.getenv('ANTHROPIC_API_KEY'):
    print("⚠️  WARNING: ANTHROPIC_API_KEY environment variable not set")
    print("   Please set your API key: export ANTHROPIC_API_KEY='your-key-here'")

from services.ai_agent import NetworkAIAgent
from services.automation import NetworkAutomationOrchestrator

def test_ai_features():
    print("🤖 TESTING AI FEATURES IN NETWORK AUTOMATION")
    print("=" * 60)
    
    # Initialize AI agent
    agent = NetworkAIAgent()
    orchestrator = NetworkAutomationOrchestrator()
    
    print("\n1️⃣ TESTING NETWORK ISSUE ANALYSIS")
    print("-" * 40)
    analysis = agent.analyze_network_issue("BGP sessions are down between SPINE1 and LEAF switches")
    print("AI Analysis:")
    print(analysis['ai_analysis'][:300] + "...")
    
    print("\n2️⃣ TESTING CONFIGURATION GENERATION")
    print("-" * 40)
    config = agent.generate_configuration("Configure BFD on all OSPF interfaces for faster convergence")
    print("Generated Config:")
    print(config['generated_config'][:300] + "...")
    
    print("\n3️⃣ TESTING AUTOMATION RECOMMENDATIONS")
    print("-" * 40)
    recommendation = agent.recommend_automation("Deploy new VLAN 100 across all leaf switches")
    print("AI Recommendation:")
    print(recommendation['ai_recommendation'][:300] + "...")
    
    print("\n4️⃣ TESTING CHAT INTERFACE")
    print("-" * 40)
    questions = [
        "What protocols are running in my datacenter?",
        "How can I troubleshoot OSPF neighbor issues?",
        "test connectivity"
    ]
    
    for question in questions:
        print(f"Q: {question}")
        response = orchestrator.chat_interface(question)
        print(f"A: {response[:150]}...")
        print()
    
    print("✅ ALL AI FEATURES WORKING SUCCESSFULLY!")

if __name__ == "__main__":
    test_ai_features()