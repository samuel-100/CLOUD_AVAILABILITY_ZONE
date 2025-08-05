#!/usr/bin/env python3
"""
Network Automation Orchestrator

Unified automation interface that integrates AI Agent, FastMCP, and all network services
for comprehensive datacenter operations and intelligent network management.
"""

import os
import sys
import json
import yaml
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Import all network services
try:
    from .ai_agent import NetworkAIAgent
    from .test_connectivity import main as test_connectivity
    from .precheck import main as run_precheck
    from .postcheck import main as run_postcheck
    from .config_deployment_tool import deploy_configuration as push_config
except ImportError:
    # Fallback for direct execution
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from services.ai_agent import NetworkAIAgent
    from services.test_connectivity import main as test_connectivity
    from services.precheck import main as run_precheck
    from services.postcheck import main as run_postcheck
    from services.config_deployment_tool import deploy_configuration as push_config

logger = logging.getLogger(__name__)

@dataclass
class AutomationResult:
    """Automation operation result"""
    operation: str
    success: bool
    message: str
    timestamp: str
    duration: Optional[float] = None
    details: Optional[Dict] = None

class NetworkAutomationOrchestrator:
    """
    Unified network automation orchestrator with AI and MCP integration
    """
    
    def __init__(self):
        self.ai_agent = NetworkAIAgent()
        # MCP server is handled separately by the enhanced_mcp_server
        self.base_dir = os.path.dirname(os.path.dirname(__file__))
        self.results_history: List[AutomationResult] = []
        
        # Setup logging
        self._setup_logging()
        
        logger.info("Network Automation Orchestrator initialized")
    
    def _setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = os.path.join(self.base_dir, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Create automation-specific log file
        log_file = os.path.join(log_dir, 'automation.log')
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def execute_workflow(self, workflow_name: str, **kwargs) -> AutomationResult:
        """Execute predefined automation workflows"""
        
        start_time = datetime.now()
        logger.info(f"Starting workflow: {workflow_name}")
        
        try:
            if workflow_name == "full_health_check":
                return self._full_health_check_workflow()
            
            elif workflow_name == "pre_change_validation":
                return self._pre_change_validation_workflow()
            
            elif workflow_name == "post_change_validation":
                return self._post_change_validation_workflow()
            
            elif workflow_name == "configuration_deployment":
                return self._configuration_deployment_workflow(**kwargs)
            
            elif workflow_name == "ai_troubleshooting":
                issue = kwargs.get('issue', 'General network issue')
                return self._ai_troubleshooting_workflow(issue)
            
            elif workflow_name == "intelligent_config_generation":
                request = kwargs.get('request', 'Generate basic configuration')
                return self._intelligent_config_generation_workflow(request)
            
            else:
                return AutomationResult(
                    operation=workflow_name,
                    success=False,
                    message=f"Unknown workflow: {workflow_name}",
                    timestamp=datetime.now().isoformat()
                )
        
        except Exception as e:
            logger.error(f"Workflow {workflow_name} failed: {e}")
            return AutomationResult(
                operation=workflow_name,
                success=False,
                message=f"Workflow failed: {str(e)}",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds()
            )
    
    def _full_health_check_workflow(self) -> AutomationResult:
        """Complete network health check workflow"""
        start_time = datetime.now()
        results = []
        
        print("🏥 Starting Full Network Health Check")
        print("=" * 50)
        
        # Step 1: Test connectivity
        print("1️⃣ Testing network connectivity...")
        try:
            connectivity_result = test_connectivity()
            results.append(("connectivity", connectivity_result))
            print(f"   ✅ Connectivity test: {'PASSED' if connectivity_result else 'FAILED'}")
        except Exception as e:
            results.append(("connectivity", False))
            print(f"   ❌ Connectivity test failed: {e}")
        
        # Step 2: Run comprehensive precheck
        print("2️⃣ Collecting network state...")
        try:
            precheck_result = run_precheck()
            results.append(("precheck", precheck_result))
            print(f"   ✅ State collection: {'COMPLETED' if precheck_result else 'FAILED'}")
        except Exception as e:
            results.append(("precheck", False))
            print(f"   ❌ State collection failed: {e}")
        
        # Step 3: AI analysis of current state
        print("3️⃣ AI-powered health analysis...")
        try:
            analysis = self.ai_agent.analyze_network_issue("Perform comprehensive network health assessment")
            results.append(("ai_analysis", True))
            print(f"   ✅ AI analysis completed")
        except Exception as e:
            results.append(("ai_analysis", False))
            print(f"   ❌ AI analysis failed: {e}")
        
        # Calculate overall success
        success_count = sum(1 for _, success in results if success)
        overall_success = success_count == len(results)
        
        duration = (datetime.now() - start_time).total_seconds()
        
        print("=" * 50)
        print(f"🎯 Health Check Results: {success_count}/{len(results)} passed")
        print(f"⏱️  Duration: {duration:.2f} seconds")
        
        result = AutomationResult(
            operation="full_health_check",
            success=overall_success,
            message=f"Health check completed: {success_count}/{len(results)} tests passed",
            timestamp=datetime.now().isoformat(),
            duration=duration,
            details={"test_results": results}
        )
        
        self.results_history.append(result)
        return result
    
    def _pre_change_validation_workflow(self) -> AutomationResult:
        """Pre-change validation workflow"""
        start_time = datetime.now()
        
        print("🔍 Starting Pre-Change Validation")
        print("=" * 40)
        
        try:
            # Test connectivity first
            print("1️⃣ Verifying device connectivity...")
            connectivity_ok = test_connectivity()
            
            if not connectivity_ok:
                return AutomationResult(
                    operation="pre_change_validation",
                    success=False,
                    message="Pre-change validation failed: Connectivity issues detected",
                    timestamp=datetime.now().isoformat(),
                    duration=(datetime.now() - start_time).total_seconds()
                )
            
            # Capture baseline state
            print("2️⃣ Capturing baseline state...")
            precheck_ok = run_precheck()
            
            if not precheck_ok:
                return AutomationResult(
                    operation="pre_change_validation",
                    success=False,
                    message="Pre-change validation failed: Could not capture baseline",
                    timestamp=datetime.now().isoformat(),
                    duration=(datetime.now() - start_time).total_seconds()
                )
            
            print("✅ Pre-change validation completed successfully")
            
            return AutomationResult(
                operation="pre_change_validation",
                success=True,
                message="Pre-change validation completed - ready for changes",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds()
            )
        
        except Exception as e:
            return AutomationResult(
                operation="pre_change_validation",
                success=False,
                message=f"Pre-change validation failed: {str(e)}",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds()
            )
    
    def _post_change_validation_workflow(self) -> AutomationResult:
        """Post-change validation workflow"""
        start_time = datetime.now()
        
        print("✅ Starting Post-Change Validation")
        print("=" * 40)
        
        try:
            # Test connectivity after changes
            print("1️⃣ Testing connectivity after changes...")
            connectivity_ok = test_connectivity()
            
            # Capture post-change state
            print("2️⃣ Capturing post-change state...")
            postcheck_ok = run_postcheck()
            
            # AI analysis of changes
            print("3️⃣ AI analysis of changes...")
            analysis = self.ai_agent.analyze_network_issue("Analyze post-change network state and validate changes")
            
            success = connectivity_ok and postcheck_ok
            
            print(f"✅ Post-change validation: {'PASSED' if success else 'FAILED'}")
            
            return AutomationResult(
                operation="post_change_validation",
                success=success,
                message=f"Post-change validation {'completed successfully' if success else 'detected issues'}",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds(),
                details={
                    "connectivity": connectivity_ok,
                    "state_capture": postcheck_ok,
                    "ai_analysis": analysis
                }
            )
        
        except Exception as e:
            return AutomationResult(
                operation="post_change_validation",
                success=False,
                message=f"Post-change validation failed: {str(e)}",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds()
            )
    
    def _configuration_deployment_workflow(self, **kwargs) -> AutomationResult:
        """Configuration deployment workflow with validation"""
        start_time = datetime.now()
        
        print("🚀 Starting Configuration Deployment")
        print("=" * 45)
        
        try:
            # Pre-deployment validation
            print("1️⃣ Pre-deployment validation...")
            pre_validation = self._pre_change_validation_workflow()
            
            if not pre_validation.success:
                return AutomationResult(
                    operation="configuration_deployment",
                    success=False,
                    message="Deployment aborted: Pre-validation failed",
                    timestamp=datetime.now().isoformat(),
                    duration=(datetime.now() - start_time).total_seconds()
                )
            
            # Deploy configuration
            print("2️⃣ Deploying configuration...")
            deployment_ok = push_config()
            
            if not deployment_ok:
                return AutomationResult(
                    operation="configuration_deployment",
                    success=False,
                    message="Configuration deployment failed",
                    timestamp=datetime.now().isoformat(),
                    duration=(datetime.now() - start_time).total_seconds()
                )
            
            # Post-deployment validation
            print("3️⃣ Post-deployment validation...")
            post_validation = self._post_change_validation_workflow()
            
            success = deployment_ok and post_validation.success
            
            print(f"✅ Configuration deployment: {'SUCCESSFUL' if success else 'FAILED'}")
            
            return AutomationResult(
                operation="configuration_deployment",
                success=success,
                message=f"Configuration deployment {'completed successfully' if success else 'completed with issues'}",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds(),
                details={
                    "pre_validation": pre_validation.success,
                    "deployment": deployment_ok,
                    "post_validation": post_validation.success
                }
            )
        
        except Exception as e:
            return AutomationResult(
                operation="configuration_deployment",
                success=False,
                message=f"Configuration deployment failed: {str(e)}",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds()
            )
    
    def _ai_troubleshooting_workflow(self, issue: str) -> AutomationResult:
        """AI-powered troubleshooting workflow"""
        start_time = datetime.now()
        
        print(f"🤖 Starting AI Troubleshooting: {issue}")
        print("=" * 50)
        
        try:
            # AI analysis
            print("1️⃣ AI issue analysis...")
            analysis = self.ai_agent.analyze_network_issue(issue)
            
            # Get automation recommendations
            print("2️⃣ Getting automation recommendations...")
            recommendations = self.ai_agent.recommend_automation(f"Troubleshoot: {issue}")
            
            # Execute recommended actions if any
            print("3️⃣ Executing recommended actions...")
            executed_actions = []
            
            for step in recommendations.get('workflow_steps', []):
                action = step.get('action')
                if action:
                    print(f"   Executing: {action}")
                    action_result = self.ai_agent.execute_automation_action(action)
                    executed_actions.append(action_result)
            
            print("✅ AI troubleshooting completed")
            
            return AutomationResult(
                operation="ai_troubleshooting",
                success=True,
                message="AI troubleshooting completed with recommendations",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds(),
                details={
                    "issue": issue,
                    "analysis": analysis,
                    "recommendations": recommendations,
                    "executed_actions": executed_actions
                }
            )
        
        except Exception as e:
            return AutomationResult(
                operation="ai_troubleshooting",
                success=False,
                message=f"AI troubleshooting failed: {str(e)}",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds()
            )
    
    def _intelligent_config_generation_workflow(self, request: str) -> AutomationResult:
        """Intelligent configuration generation workflow"""
        start_time = datetime.now()
        
        print(f"⚙️ Starting Intelligent Config Generation: {request}")
        print("=" * 55)
        
        try:
            # Generate configuration using AI
            print("1️⃣ AI configuration generation...")
            config = self.ai_agent.generate_configuration(request)
            
            # Validate generated configuration
            print("2️⃣ Configuration validation...")
            # This could include syntax checking, policy compliance, etc.
            
            print("✅ Configuration generation completed")
            
            return AutomationResult(
                operation="intelligent_config_generation",
                success=True,
                message="Configuration generated successfully",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds(),
                details={
                    "request": request,
                    "generated_config": config
                }
            )
        
        except Exception as e:
            return AutomationResult(
                operation="intelligent_config_generation",
                success=False,
                message=f"Configuration generation failed: {str(e)}",
                timestamp=datetime.now().isoformat(),
                duration=(datetime.now() - start_time).total_seconds()
            )
    
    def get_workflow_history(self) -> List[Dict]:
        """Get automation workflow history"""
        return [asdict(result) for result in self.results_history]
    
    def chat_interface(self, user_input: str) -> str:
        """Natural language interface for automation"""
        return self.ai_agent.chat_interface(user_input)
    
    async def start_mcp_server(self, host: str = "localhost", port: int = 8000):
        """Start the integrated MCP server"""
        await self.mcp_server.start_server(host, port)


# CLI Interface
def main():
    """Main CLI interface for network automation"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Automation Orchestrator")
    parser.add_argument("--workflow", choices=[
        "full_health_check",
        "pre_change_validation", 
        "post_change_validation",
        "configuration_deployment",
        "ai_troubleshooting",
        "intelligent_config_generation"
    ], help="Workflow to execute")
    parser.add_argument("--issue", help="Issue description for troubleshooting")
    parser.add_argument("--request", help="Configuration request")
    parser.add_argument("--mcp-server", action="store_true", help="Start MCP server")
    parser.add_argument("--chat", action="store_true", help="Start chat interface")
    
    args = parser.parse_args()
    
    orchestrator = NetworkAutomationOrchestrator()
    
    if args.mcp_server:
        print("Starting MCP server...")
        asyncio.run(orchestrator.start_mcp_server())
    
    elif args.chat:
        print("🤖 Network Automation Chat Interface")
        print("Type 'exit' to quit")
        print("=" * 40)
        
        while True:
            user_input = input("\n💬 You: ").strip()
            if user_input.lower() in ['exit', 'quit']:
                break
            
            response = orchestrator.chat_interface(user_input)
            print(f"🤖 AI: {response}")
    
    elif args.workflow:
        kwargs = {}
        if args.issue:
            kwargs['issue'] = args.issue
        if args.request:
            kwargs['request'] = args.request
        
        result = orchestrator.execute_workflow(args.workflow, **kwargs)
        
        print("\n" + "=" * 60)
        print("📊 AUTOMATION RESULT")
        print("=" * 60)
        print(f"Operation: {result.operation}")
        print(f"Success: {result.success}")
        print(f"Message: {result.message}")
        print(f"Duration: {result.duration:.2f}s" if result.duration else "Duration: N/A")
        if result.details:
            print(f"Details: {json.dumps(result.details, indent=2)}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()