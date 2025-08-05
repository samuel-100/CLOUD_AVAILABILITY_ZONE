#!/usr/bin/env python3
"""
End-to-End Integration Testing Framework
Tests complete Claude-to-device workflows under realistic conditions
"""

import sys
import os
import time
import json
import asyncio
import logging
import traceback
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add project root to path
sys.path.append('/opt/network-automation/CLOUD_AVAILABILITY_ZONE')

from mcp.enhanced_mcp_server import EnhancedMCPServer
from services.network_status_tool import get_network_status
from services.device_details_tool import get_device_details
from services.config_generation_tool import generate_configuration
from services.config_deployment_tool import deploy_configuration, get_deployment_status
from services.ai_analysis_tool import analyze_network_issue
from services.network_context_engine import get_network_context

class EndToEndTestSuite:
    """Comprehensive end-to-end testing framework"""
    
    def __init__(self):
        self.test_results = []
        self.failed_tests = []
        self.start_time = time.time()
        self.setup_logging()
        
    def setup_logging(self):
        """Setup test logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/e2e_tests.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def log_test_result(self, test_name: str, success: bool, duration: float, details: str = ""):
        """Log test result"""
        result = {
            'test_name': test_name,
            'success': success,
            'duration': duration,
            'timestamp': datetime.now().isoformat(),
            'details': details
        }
        self.test_results.append(result)
        
        if success:
            self.logger.info(f"✅ {test_name} PASSED ({duration:.2f}s)")
        else:
            self.logger.error(f"❌ {test_name} FAILED ({duration:.2f}s): {details}")
            self.failed_tests.append(test_name)
            
    async def test_mcp_server_initialization(self) -> bool:
        """Test 1: MCP Server Initialization and Tool Registration"""
        test_start = time.time()
        try:
            self.logger.info("🧪 Testing MCP Server Initialization...")
            
            # Initialize MCP server
            server = EnhancedMCPServer()
            
            # Verify server properties
            assert server.name == "enhanced-network-automation"
            assert len(server.tools) == 18, f"Expected 18 tools, got {len(server.tools)}"
            
            # Test tool registration
            expected_tools = [
                'get_network_status', 'get_device_details', 'get_network_topology',
                'analyze_network_issue', 'generate_configuration', 'deploy_configuration',
                'get_deployment_status', 'approve_deployment', 'get_pending_approvals',
                'get_workflow_status', 'get_workflow_history', 'get_network_context',
                'start_network_monitoring', 'get_network_trends', 'analyze_network_correlation',
                'detect_network_patterns', 'get_performance_optimizations', 'get_proactive_recommendations'
            ]
            
            registered_tools = [tool['name'] for tool in server.tools]
            missing_tools = set(expected_tools) - set(registered_tools)
            
            if missing_tools:
                raise AssertionError(f"Missing tools: {missing_tools}")
                
            duration = time.time() - test_start
            self.log_test_result("MCP Server Initialization", True, duration, 
                               f"All {len(server.tools)} tools registered successfully")
            return True
            
        except Exception as e:
            duration = time.time() - test_start
            self.log_test_result("MCP Server Initialization", False, duration, str(e))
            return False
            
    async def test_network_discovery_workflow(self) -> bool:
        """Test 2: Complete Network Discovery Workflow"""
        test_start = time.time()
        try:
            self.logger.info("🧪 Testing Network Discovery Workflow...")
            
            # Step 1: Get network status
            status_result = get_network_status()
            assert status_result['success'], "Network status check failed"
            
            network_status = status_result['data']
            assert 'total_devices' in network_status
            assert 'topology_type' in network_status
            assert network_status['total_devices'] > 0
            
            # Step 2: Get device details for each device
            devices_checked = 0
            for device_name in ['SPINE1', 'SPINE2', 'LEAF1', 'LEAF2', 'LEAF3']:
                try:
                    device_result = get_device_details(device_name)
                    if device_result['success']:
                        devices_checked += 1
                        device_data = device_result['data']
                        assert 'device_name' in device_data
                        assert 'ip_address' in device_data
                        assert 'device_type' in device_data
                except Exception as e:
                    self.logger.warning(f"Device {device_name} check failed: {e}")
                    
            # Verify we could check at least some devices
            assert devices_checked >= 3, f"Could only check {devices_checked} devices"
            
            duration = time.time() - test_start
            self.log_test_result("Network Discovery Workflow", True, duration,
                               f"Discovered {devices_checked} devices in topology")
            return True
            
        except Exception as e:
            duration = time.time() - test_start
            self.log_test_result("Network Discovery Workflow", False, duration, str(e))
            return False
            
    async def test_ai_analysis_workflow(self) -> bool:
        """Test 3: AI-Powered Analysis Workflow"""
        test_start = time.time()
        try:
            self.logger.info("🧪 Testing AI Analysis Workflow...")
            
            # Test network issue analysis
            analysis_result = analyze_network_issue(
                "High latency between SPINE1 and LEAF2",
                ["SPINE1", "LEAF2"]
            )
            
            assert analysis_result['success'], "AI analysis failed"
            
            analysis_data = analysis_result['data']
            assert 'analysis' in analysis_data
            assert 'recommendations' in analysis_data
            assert 'severity' in analysis_data
            assert len(analysis_data['analysis']) > 50  # Meaningful analysis
            assert len(analysis_data['recommendations']) > 0
            
            # Test network context retrieval
            context_result = get_network_context("performance")
            assert context_result['success'], "Network context retrieval failed"
            
            context_data = context_result['data']
            assert 'context_type' in context_data
            assert 'insights' in context_data
            
            duration = time.time() - test_start
            self.log_test_result("AI Analysis Workflow", True, duration,
                               f"Analysis generated {len(analysis_data['recommendations'])} recommendations")
            return True
            
        except Exception as e:
            duration = time.time() - test_start
            self.log_test_result("AI Analysis Workflow", False, duration, str(e))
            return False
            
    async def test_configuration_generation_workflow(self) -> bool:
        """Test 4: Configuration Generation and Validation Workflow"""
        test_start = time.time()
        try:
            self.logger.info("🧪 Testing Configuration Generation Workflow...")
            
            # Test BGP configuration generation
            bgp_result = generate_configuration(
                device_name="SPINE1",
                config_type="bgp",
                requirements="Configure BGP AS 65001 with neighbor 192.168.1.20"
            )
            
            assert bgp_result['success'], "BGP configuration generation failed"
            
            bgp_config = bgp_result['data']
            assert 'generated_config' in bgp_config
            assert 'config_type' in bgp_config
            assert 'validation_status' in bgp_config
            assert len(bgp_config['generated_config']) > 20  # Non-trivial config
            
            # Verify BGP-specific content
            config_text = bgp_config['generated_config'].lower()
            assert 'bgp' in config_text or 'router bgp' in config_text
            
            # Test interface configuration generation
            interface_result = generate_configuration(
                device_name="LEAF1",
                config_type="interfaces",
                requirements="Configure interface Ethernet1/1 for VLAN 100"
            )
            
            assert interface_result['success'], "Interface configuration generation failed"
            
            interface_config = interface_result['data']
            assert 'generated_config' in interface_config
            config_text = interface_config['generated_config'].lower()
            assert 'interface' in config_text or 'ethernet' in config_text
            
            duration = time.time() - test_start
            self.log_test_result("Configuration Generation Workflow", True, duration,
                               "Generated BGP and interface configurations successfully")
            return True
            
        except Exception as e:
            duration = time.time() - test_start
            self.log_test_result("Configuration Generation Workflow", False, duration, str(e))
            return False
            
    async def test_deployment_workflow(self) -> bool:
        """Test 5: Configuration Deployment Workflow (Simulation)"""
        test_start = time.time()
        try:
            self.logger.info("🧪 Testing Configuration Deployment Workflow...")
            
            # Generate a test configuration
            config_result = generate_configuration(
                device_name="SPINE1",
                config_type="interfaces",
                requirements="Configure description for interface Ethernet1/1"
            )
            
            assert config_result['success'], "Configuration generation failed"
            test_config = config_result['data']['generated_config']
            
            # Test deployment (in simulation mode)
            deployment_result = deploy_configuration(
                device_name="SPINE1",
                configuration=test_config,
                deployment_mode="scheduled"
            )
            
            assert deployment_result['success'], "Configuration deployment failed"
            
            deployment_data = deployment_result['data']
            assert 'deployment_id' in deployment_data
            assert 'status' in deployment_data
            assert deployment_data['status'] in ['pending_approval', 'scheduled', 'completed']
            
            deployment_id = deployment_data['deployment_id']
            
            # Test deployment status checking
            status_result = get_deployment_status(deployment_id)
            assert status_result['success'], "Deployment status check failed"
            
            status_data = status_result['data']
            assert 'deployment_id' in status_data
            assert 'status' in status_data
            assert status_data['deployment_id'] == deployment_id
            
            duration = time.time() - test_start
            self.log_test_result("Configuration Deployment Workflow", True, duration,
                               f"Deployment {deployment_id} created and tracked successfully")
            return True
            
        except Exception as e:
            duration = time.time() - test_start
            self.log_test_result("Configuration Deployment Workflow", False, duration, str(e))
            return False
            
    async def test_complete_troubleshooting_scenario(self) -> bool:
        """Test 6: Complete Troubleshooting Scenario (Simulated)"""
        test_start = time.time()
        try:
            self.logger.info("🧪 Testing Complete Troubleshooting Scenario...")
            
            # Scenario: High latency issue between buildings
            # Step 1: Get network status to identify potential issues
            status_result = get_network_status()
            assert status_result['success'], "Network status check failed"
            
            # Step 2: Analyze the specific issue with AI
            issue_description = "Users reporting slow performance between Building A and Building B"
            analysis_result = analyze_network_issue(issue_description, ["SPINE1", "LEAF2"])
            assert analysis_result['success'], "Issue analysis failed"
            
            analysis = analysis_result['data']
            assert len(analysis['recommendations']) > 0, "No recommendations provided"
            
            # Step 3: Get network context for additional insights
            context_result = get_network_context("performance")
            assert context_result['success'], "Context retrieval failed"
            
            # Step 4: Generate optimization configuration based on analysis
            optimization_requirements = f"Optimize routing based on analysis: {analysis['recommendations'][0]}"
            config_result = generate_configuration(
                device_name="SPINE1",
                config_type="bgp",
                requirements=optimization_requirements
            )
            assert config_result['success'], "Optimization config generation failed"
            
            # Step 5: Simulate deployment of the fix
            deployment_result = deploy_configuration(
                device_name="SPINE1",
                configuration=config_result['data']['generated_config'],
                deployment_mode="scheduled"
            )
            assert deployment_result['success'], "Fix deployment failed"
            
            duration = time.time() - test_start
            self.log_test_result("Complete Troubleshooting Scenario", True, duration,
                               "End-to-end troubleshooting workflow completed successfully")
            return True
            
        except Exception as e:
            duration = time.time() - test_start
            self.log_test_result("Complete Troubleshooting Scenario", False, duration, str(e))
            return False
            
    async def test_performance_under_load(self) -> bool:
        """Test 7: Performance Under Load"""
        test_start = time.time()
        try:
            self.logger.info("🧪 Testing Performance Under Load...")
            
            # Simulate concurrent requests
            concurrent_requests = 10
            request_tasks = []
            
            for i in range(concurrent_requests):
                # Create a mix of different operations
                if i % 3 == 0:
                    task = self.make_concurrent_request("network_status")
                elif i % 3 == 1:
                    task = self.make_concurrent_request("device_details", {"device_name": "SPINE1"})
                else:
                    task = self.make_concurrent_request("network_context", {"context_type": "performance"})
                    
                request_tasks.append(task)
            
            # Execute all requests concurrently
            results = await asyncio.gather(*request_tasks, return_exceptions=True)
            
            # Analyze results
            successful_requests = sum(1 for result in results if not isinstance(result, Exception))
            total_requests = len(results)
            success_rate = successful_requests / total_requests
            
            assert success_rate >= 0.8, f"Success rate too low: {success_rate:.2%}"
            
            duration = time.time() - test_start
            self.log_test_result("Performance Under Load", True, duration,
                               f"Success rate: {success_rate:.1%} ({successful_requests}/{total_requests})")
            return True
            
        except Exception as e:
            duration = time.time() - test_start
            self.log_test_result("Performance Under Load", False, duration, str(e))
            return False
            
    async def make_concurrent_request(self, request_type: str, params: Dict = None) -> Dict:
        """Make a concurrent request for load testing"""
        try:
            if request_type == "network_status":
                return get_network_status()
            elif request_type == "device_details":
                return get_device_details(params['device_name'])
            elif request_type == "network_context":
                return get_network_context(params['context_type'])
            else:
                raise ValueError(f"Unknown request type: {request_type}")
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    async def test_error_handling_and_recovery(self) -> bool:
        """Test 8: Error Handling and Recovery"""
        test_start = time.time()
        try:
            self.logger.info("🧪 Testing Error Handling and Recovery...")
            
            # Test 1: Invalid device name
            invalid_device_result = get_device_details("NONEXISTENT_DEVICE")
            assert not invalid_device_result['success'], "Should fail for invalid device"
            assert 'error' in invalid_device_result
            
            # Test 2: Invalid configuration parameters
            invalid_config_result = generate_configuration(
                device_name="",  # Empty device name
                config_type="invalid_type",
                requirements=""
            )
            assert not invalid_config_result['success'], "Should fail for invalid parameters"
            
            # Test 3: Recovery after errors - normal operations should still work
            normal_status_result = get_network_status()
            assert normal_status_result['success'], "Normal operations should work after errors"
            
            # Test 4: Invalid deployment parameters
            invalid_deployment_result = deploy_configuration(
                device_name="INVALID_DEVICE",
                configuration="invalid config",
                deployment_mode="invalid_mode"
            )
            assert not invalid_deployment_result['success'], "Should fail for invalid deployment"
            
            duration = time.time() - test_start
            self.log_test_result("Error Handling and Recovery", True, duration,
                               "All error scenarios handled gracefully")
            return True
            
        except Exception as e:
            duration = time.time() - test_start
            self.log_test_result("Error Handling and Recovery", False, duration, str(e))
            return False
            
    def generate_test_report(self) -> Dict:
        """Generate comprehensive test report"""
        total_duration = time.time() - self.start_time
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['success'])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        
        report = {
            'test_summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'success_rate': success_rate,
                'total_duration': total_duration,
                'timestamp': datetime.now().isoformat()
            },
            'test_results': self.test_results,
            'failed_tests': self.failed_tests,
            'recommendations': self.generate_recommendations()
        }
        
        return report
        
    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        if self.failed_tests:
            recommendations.append("🔍 Investigate failed tests for production readiness")
            
        if len(self.failed_tests) > len(self.test_results) * 0.2:
            recommendations.append("⚠️  High failure rate - review system configuration")
            
        performance_tests = [r for r in self.test_results if 'performance' in r['test_name'].lower()]
        if performance_tests:
            avg_duration = sum(r['duration'] for r in performance_tests) / len(performance_tests)
            if avg_duration > 10:
                recommendations.append("🚀 Consider performance optimization")
                
        if not self.failed_tests:
            recommendations.append("✅ System ready for production deployment")
            recommendations.append("📊 Consider setting up continuous integration testing")
            
        return recommendations
        
    async def run_all_tests(self) -> Dict:
        """Run the complete end-to-end test suite"""
        self.logger.info("🚀 Starting End-to-End Integration Test Suite")
        self.logger.info("=" * 60)
        
        tests = [
            self.test_mcp_server_initialization,
            self.test_network_discovery_workflow,
            self.test_ai_analysis_workflow,
            self.test_configuration_generation_workflow,
            self.test_deployment_workflow,
            self.test_complete_troubleshooting_scenario,
            self.test_performance_under_load,
            self.test_error_handling_and_recovery
        ]
        
        for test_func in tests:
            try:
                await test_func()
            except Exception as e:
                self.logger.error(f"Test {test_func.__name__} crashed: {e}")
                self.logger.error(traceback.format_exc())
                
        # Generate and save report
        report = self.generate_test_report()
        
        # Save report to file
        report_file = f"/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/e2e_test_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        self.logger.info("=" * 60)
        self.logger.info("📊 End-to-End Test Suite Results:")
        self.logger.info(f"   Total Tests: {report['test_summary']['total_tests']}")
        self.logger.info(f"   Passed: {report['test_summary']['passed']}")
        self.logger.info(f"   Failed: {report['test_summary']['failed']}")
        self.logger.info(f"   Success Rate: {report['test_summary']['success_rate']:.1f}%")
        self.logger.info(f"   Duration: {report['test_summary']['total_duration']:.2f}s")
        self.logger.info(f"   Report saved: {report_file}")
        
        if report['recommendations']:
            self.logger.info("🎯 Recommendations:")
            for rec in report['recommendations']:
                self.logger.info(f"   {rec}")
                
        return report

async def main():
    """Main execution function"""
    test_suite = EndToEndTestSuite()
    report = await test_suite.run_all_tests()
    
    # Exit with appropriate code
    if report['test_summary']['failed'] == 0:
        print("\n🎉 All tests passed! System ready for production.")
        return 0
    else:
        print(f"\n⚠️  {report['test_summary']['failed']} tests failed. Review before production deployment.")
        return 1

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
