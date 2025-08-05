"""
AI Agent and LLM Integration Module for Network Automation

This module integrates with Anthropic Claude for intelligent network operations,
troubleshooting, and configuration management in the datacenter environment.
"""

import os
import sys
import json
import yaml
import logging
import requests
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# Add config directory to path
sys.path.append(str(Path(__file__).parent.parent / "config"))

# Import network services
try:
    from .test_connectivity import main as test_connectivity
    from .precheck import main as run_precheck
    from .postcheck import main as run_postcheck
    from .config_deployment_tool import deploy_configuration as push_config
except ImportError:
    # Fallback for direct execution
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from services.test_connectivity import main as test_connectivity
    from services.precheck import main as run_precheck
    from services.postcheck import main as run_postcheck
    from services.config_deployment_tool import deploy_configuration as push_config

logger = logging.getLogger(__name__)

class NetworkAIAgent:
    """
    AI-powered network automation agent with Claude integration
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-5-sonnet-20241022"):
        # Load API configuration
        self._load_api_config()
        
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        self.model = model
        self.api_url = "https://api.anthropic.com/v1/messages"
        self.network_context = self._load_network_context()
        
        if not self.api_key:
            logger.warning("No Anthropic API key provided. AI features will be limited.")
            logger.info("Run 'python3 CLOUD_AVAILABILITY_ZONE/config/api_config.py' to configure API key")
        else:
            logger.info("Anthropic API key loaded successfully")
    
    def _load_api_config(self):
        """Load API configuration from .env file"""
        try:
            from api_config import APIConfig
            config = APIConfig()
            config.load_env_file()
        except ImportError:
            # Fallback: try to load .env manually
            env_file = Path(__file__).parent.parent / ".env"
            if env_file.exists():
                with open(env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            os.environ[key] = value
        except Exception as e:
            logger.debug(f"Could not load API config: {e}")
    
    def _load_network_context(self) -> Dict[str, Any]:
        """Load network topology and device information for AI context"""
        try:
            base_dir = os.path.dirname(os.path.dirname(__file__))
            topology_file = os.path.join(base_dir, 'network_topology.yaml')
            devices_file = os.path.join(base_dir, 'devices.yaml')
            
            context = {
                'datacenter_name': 'CLOUD_AVAILABILITY_ZONE',
                'architecture': 'Spine-Leaf CLOS',
                'protocols': ['OSPF', 'BGP', 'VXLAN', 'EVPN', 'BFD'],
                'devices': {},
                'topology': {}
            }
            
            # Load topology
            if os.path.exists(topology_file):
                with open(topology_file) as f:
                    context['topology'] = yaml.safe_load(f)
            
            # Load device details
            if os.path.exists(devices_file):
                with open(devices_file) as f:
                    devices_data = yaml.safe_load(f)
                    for device in devices_data.get('devices', []):
                        context['devices'][device['name']] = {
                            'ip': device['mgmt_ip'],
                            'role': 'spine' if 'SPINE' in device['name'] else 'leaf',
                            'username': device['username']
                        }
            
            return context
            
        except Exception as e:
            logger.error(f"Failed to load network context: {e}")
            return {'error': str(e)}
    
    def _create_system_prompt(self) -> str:
        """Create system prompt with network context"""
        return f"""You are an expert network engineer and AI assistant specializing in Cisco datacenter technologies. 

NETWORK CONTEXT:
- Datacenter: {self.network_context.get('datacenter_name', 'Unknown')}
- Architecture: {self.network_context.get('architecture', 'Unknown')}
- Protocols: {', '.join(self.network_context.get('protocols', []))}
- Devices: {len(self.network_context.get('devices', {}))} total
  - Spines: {len([d for d in self.network_context.get('devices', {}).values() if d.get('role') == 'spine'])}
  - Leafs: {len([d for d in self.network_context.get('devices', {}).values() if d.get('role') == 'leaf'])}

CAPABILITIES:
- Network troubleshooting and analysis
- Configuration generation and validation
- Protocol-specific guidance (OSPF, BGP, VXLAN, EVPN)
- Automation workflow recommendations
- Performance optimization suggestions

AVAILABLE ACTIONS:
- test_connectivity: Test ping/SSH to all devices
- run_precheck: Collect baseline network state
- run_postcheck: Validate network state after changes
- push_config: Deploy configurations to devices

Provide expert network engineering advice, actionable recommendations, and when appropriate, suggest specific automation actions from the available capabilities."""

    def query_llm(self, prompt: str, include_context: bool = True) -> str:
        """Query Claude LLM with network context"""
        if not self.api_key:
            return "AI features unavailable - no API key configured"
        
        try:
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            
            messages = []
            if include_context:
                messages.append({
                    "role": "user", 
                    "content": f"Network Context: {json.dumps(self.network_context, indent=2)}\n\nQuery: {prompt}"
                })
            else:
                messages.append({"role": "user", "content": prompt})
            
            data = {
                "model": self.model,
                "max_tokens": 2000,
                "temperature": 0.1,
                "system": self._create_system_prompt(),
                "messages": messages
            }
            
            response = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                content = result.get("content", [])
                if content and isinstance(content, list):
                    return content[0].get("text", "No response content")
                return str(content)
            else:
                logger.error(f"LLM API error: {response.status_code} - {response.text}")
                return f"AI service error: {response.status_code}"
                
        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            return f"AI query failed: {str(e)}"
    
    def analyze_network_issue(self, issue_description: str) -> Dict[str, Any]:
        """Analyze network issue using AI"""
        prompt = f"""
        NETWORK ISSUE ANALYSIS REQUEST:
        
        Issue Description: {issue_description}
        
        Please provide:
        1. Likely root causes
        2. Troubleshooting steps
        3. Recommended automation actions
        4. Prevention strategies
        
        Format your response as structured analysis with clear action items.
        """
        
        analysis = self.query_llm(prompt)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'issue': issue_description,
            'ai_analysis': analysis,
            'recommended_actions': self._extract_actions(analysis)
        }
    
    def generate_configuration(self, config_request: str) -> Dict[str, Any]:
        """Generate network configuration using AI"""
        prompt = f"""
        CONFIGURATION GENERATION REQUEST:
        
        Request: {config_request}
        
        Please generate appropriate Cisco IOS configuration for our spine-leaf datacenter.
        Consider:
        - Current network topology and protocols
        - Best practices for datacenter design
        - Integration with existing OSPF, BGP, VXLAN, EVPN setup
        
        Provide configuration snippets with explanations.
        """
        
        config = self.query_llm(prompt)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'request': config_request,
            'generated_config': config,
            'validation_needed': True
        }
    
    def recommend_automation(self, scenario: str) -> Dict[str, Any]:
        """Recommend automation workflow for given scenario"""
        prompt = f"""
        AUTOMATION RECOMMENDATION REQUEST:
        
        Scenario: {scenario}
        
        Based on our available automation tools (test_connectivity, precheck, postcheck, push_config),
        recommend the optimal workflow including:
        1. Pre-change validation steps
        2. Implementation sequence
        3. Post-change verification
        4. Rollback procedures if needed
        
        Provide specific command sequences and validation checkpoints.
        """
        
        recommendation = self.query_llm(prompt)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'scenario': scenario,
            'ai_recommendation': recommendation,
            'workflow_steps': self._extract_workflow(recommendation)
        }
    
    def _extract_actions(self, analysis: str) -> List[str]:
        """Extract actionable items from AI analysis"""
        # Simple extraction - could be enhanced with more sophisticated parsing
        actions = []
        lines = analysis.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in ['run', 'execute', 'check', 'verify', 'test']):
                actions.append(line.strip())
        return actions
    
    def _extract_workflow(self, recommendation: str) -> List[Dict[str, str]]:
        """Extract workflow steps from AI recommendation"""
        steps = []
        lines = recommendation.split('\n')
        step_num = 1
        
        for line in lines:
            line = line.strip()
            if line and (line.startswith(str(step_num)) or 'step' in line.lower()):
                steps.append({
                    'step': step_num,
                    'description': line,
                    'action': self._identify_action(line)
                })
                step_num += 1
        
        return steps
    
    def _identify_action(self, description: str) -> Optional[str]:
        """Identify automation action from description"""
        desc_lower = description.lower()
        if 'connectivity' in desc_lower or 'ping' in desc_lower:
            return 'test_connectivity'
        elif 'precheck' in desc_lower or 'baseline' in desc_lower:
            return 'run_precheck'
        elif 'postcheck' in desc_lower or 'verify' in desc_lower:
            return 'run_postcheck'
        elif 'push' in desc_lower or 'deploy' in desc_lower:
            return 'push_config'
        return None
    
    def execute_automation_action(self, action: str) -> Dict[str, Any]:
        """Execute automation action and return results"""
        try:
            logger.info(f"Executing automation action: {action}")
            
            if action == 'test_connectivity':
                result = test_connectivity()
                return {'action': action, 'success': result, 'message': 'Connectivity test completed'}
            
            elif action == 'run_precheck':
                result = run_precheck()
                return {'action': action, 'success': result, 'message': 'Precheck completed'}
            
            elif action == 'run_postcheck':
                result = run_postcheck()
                return {'action': action, 'success': result, 'message': 'Postcheck completed'}
            
            elif action == 'push_config':
                result = push_config("AI-agent initiated configuration deployment", requester="ai-agent")
                return {'action': action, 'success': result, 'message': 'Configuration push completed'}
            
            else:
                return {'action': action, 'success': False, 'message': f'Unknown action: {action}'}
                
        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return {'action': action, 'success': False, 'message': f'Execution failed: {str(e)}'}
    
    def chat_interface(self, user_input: str) -> str:
        """Natural language chat interface for network operations"""
        # Check if user is requesting an action
        user_lower = user_input.lower()
        
        if any(keyword in user_lower for keyword in ['test connectivity', 'ping', 'ssh test']):
            result = self.execute_automation_action('test_connectivity')
            return f"Connectivity test executed. Success: {result['success']}. {result['message']}"
        
        elif any(keyword in user_lower for keyword in ['precheck', 'baseline', 'before']):
            result = self.execute_automation_action('run_precheck')
            return f"Precheck executed. Success: {result['success']}. {result['message']}"
        
        elif any(keyword in user_lower for keyword in ['postcheck', 'verify', 'validate']):
            result = self.execute_automation_action('run_postcheck')
            return f"Postcheck executed. Success: {result['success']}. {result['message']}"
        
        elif any(keyword in user_lower for keyword in ['push config', 'deploy', 'apply']):
            result = self.execute_automation_action('push_config')
            return f"Configuration push executed. Success: {result['success']}. {result['message']}"
        
        else:
            # General AI query
            return self.query_llm(user_input)


# Example usage and testing
if __name__ == "__main__":
    # Initialize AI agent
    agent = NetworkAIAgent()
    
    # Test different capabilities
    print("=== Network AI Agent Test ===")
    
    # Test issue analysis
    issue_analysis = agent.analyze_network_issue("OSPF neighbors are flapping on SPINE1")
    print(f"Issue Analysis: {issue_analysis['ai_analysis'][:200]}...")
    
    # Test configuration generation
    config_gen = agent.generate_configuration("Configure BFD on all OSPF interfaces")
    print(f"Config Generation: {config_gen['generated_config'][:200]}...")
    
    # Test automation recommendation
    automation_rec = agent.recommend_automation("Deploy new VLAN across all leaf switches")
    print(f"Automation Recommendation: {automation_rec['ai_recommendation'][:200]}...")
    
    # Test chat interface
    chat_response = agent.chat_interface("What's the status of my network?")
    print(f"Chat Response: {chat_response[:200]}...")
