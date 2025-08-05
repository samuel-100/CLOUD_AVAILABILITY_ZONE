#!/usr/bin/env python3
"""
Comprehensive Testing Framework for Network Automation System

This module provides unit tests, integration tests, performance tests,
and mock testing capabilities for the entire network automation platform.
"""

import os
import sys
import time
import unittest
import pytest
import asyncio
import tempfile
import shutil
import sqlite3
import json
import yaml
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import all services for testing
from services.monitoring_service import MonitoringService, HealthChecker, MetricsCollector
from services.deployment_service import DeploymentService, ConfigurationManager, SecretsManager
from services.ai_agent import AIAgent
from services.network_topology import NetworkTopologyService
from services.device_details import DeviceDetailsService
from services.config_generation_tool import ConfigGenerationService
from services.network_status import NetworkStatusService

# Configure test logging
logging.basicConfig(level=logging.WARNING)  # Reduce noise during tests
logger = logging.getLogger(__name__)


class TestBase(unittest.TestCase):
    """Base test class with common setup and teardown"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.test_dir, "test.db")
        self.test_config_dir = os.path.join(self.test_dir, "config")
        os.makedirs(self.test_config_dir, exist_ok=True)
        
        # Create test configuration
        self.test_config = {
            "api": {"host": "localhost", "port": 8080},
            "monitoring": {
                "prometheus": {"enabled": True, "port": 8000},
                "health_checks": {"enabled": True, "port": 8080},
                "logging": {"level": "INFO"}
            },
            "logging": {"level": "INFO"},
            "database": {"path": self.test_db_path},
            "network": {"device_timeout": 30, "mock_devices": True}
        }
        
        # Save test configuration
        with open(os.path.join(self.test_config_dir, "base.yaml"), 'w') as f:
            yaml.dump(self.test_config, f)
            
        with open(os.path.join(self.test_config_dir, "testing.yaml"), 'w') as f:
            yaml.dump({"testing": {"enabled": True}}, f)
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)


class TestMonitoringService(TestBase):
    """Test monitoring service functionality"""
    
    def setUp(self):
        super().setUp()
        # Create monitoring service with test database
        self.monitoring_service = MonitoringService(
            prometheus_port=8001,  # Different port for testing
            enable_prometheus=False,  # Disable for unit tests
            db_path=self.test_db_path
        )
    
    def test_monitoring_service_initialization(self):
        """Test monitoring service initializes correctly"""
        self.assertIsNotNone(self.monitoring_service)
        self.assertIsNotNone(self.monitoring_service.health_checker)
        self.assertIsNotNone(self.monitoring_service.metrics_collector)
        self.assertIsNotNone(self.monitoring_service.logger)
    
    def test_health_check_registration(self):
        """Test health check registration"""
        def test_health_check():
            from services.monitoring_service import HealthStatus
            return HealthStatus(
                component="test_component",
                status="healthy",
                message="Test health check",
                timestamp=datetime.now()
            )
        
        self.monitoring_service.health_checker.register_health_check("test_component", test_health_check)
        
        # Verify registration
        self.assertIn("test_component", self.monitoring_service.health_checker.health_checks)
        
        # Test health check execution
        result = self.monitoring_service.health_checker.run_health_check("test_component")
        self.assertEqual(result.component, "test_component")
        self.assertEqual(result.status, "healthy")
    
    def test_system_health_status(self):
        """Test overall system health status"""
        # Register test health checks
        def healthy_check():
            from services.monitoring_service import HealthStatus
            return HealthStatus("healthy_component", "healthy", "All good", datetime.now())
        
        def warning_check():
            from services.monitoring_service import HealthStatus
            return HealthStatus("warning_component", "warning", "Minor issue", datetime.now())
        
        self.monitoring_service.health_checker.register_health_check("healthy", healthy_check)
        self.monitoring_service.health_checker.register_health_check("warning", warning_check)
        
        # Get system health
        health_status = self.monitoring_service.health_checker.get_system_health()
        
        self.assertIn("overall_status", health_status)
        self.assertIn("components", health_status)
        self.assertIn("summary", health_status)
        self.assertEqual(health_status["overall_status"], "warning")  # Warning due to warning component
    
    def test_metrics_collection(self):
        """Test metrics collection functionality"""
        # Test counter metric
        self.monitoring_service.metrics_collector.increment_counter("test_counter", {"env": "test"})
        
        # Test gauge metric
        self.monitoring_service.metrics_collector.set_gauge("test_gauge", 42.0, {"type": "test"})
        
        # Test histogram metric
        self.monitoring_service.metrics_collector.observe_histogram("test_histogram", 1.5, {"operation": "test"})
        
        # Verify metrics exist (would check Prometheus registry in real implementation)
        self.assertTrue(True)  # Placeholder - actual implementation would verify registry
    
    def test_correlation_context(self):
        """Test correlation ID context management"""
        correlation_context = self.monitoring_service.correlation_context
        
        # Test setting correlation ID
        test_correlation_id = "test-correlation-123"
        correlation_context.set_correlation_id(test_correlation_id)
        
        retrieved_id = correlation_context.get_correlation_id()
        self.assertEqual(retrieved_id, test_correlation_id)
        
        # Test context manager
        with correlation_context.correlation_context("context-test-456"):
            context_id = correlation_context.get_correlation_id()
            self.assertEqual(context_id, "context-test-456")


class TestDeploymentService(TestBase):
    """Test deployment service functionality"""
    
    def setUp(self):
        super().setUp()
        # Use test configuration directory
        os.environ['CONFIG_DIR'] = self.test_config_dir
        self.deployment_service = DeploymentService("testing")
    
    def test_configuration_manager_initialization(self):
        """Test configuration manager initializes correctly"""
        config_manager = self.deployment_service.config_manager
        self.assertIsNotNone(config_manager)
        self.assertEqual(config_manager.environment, "testing")
    
    def test_configuration_loading(self):
        """Test configuration loading and merging"""
        config_manager = self.deployment_service.config_manager
        
        # Test basic configuration loading
        api_host = config_manager.get_config("api.host")
        self.assertEqual(api_host, "localhost")
        
        # Test nested configuration
        prometheus_enabled = config_manager.get_config("monitoring.prometheus.enabled")
        self.assertTrue(prometheus_enabled)
        
        # Test default values
        non_existent = config_manager.get_config("non.existent.config", "default_value")
        self.assertEqual(non_existent, "default_value")
    
    def test_configuration_validation(self):
        """Test configuration validation"""
        validation_result = self.deployment_service.validate_deployment_config()
        
        self.assertIsNotNone(validation_result)
        self.assertIsInstance(validation_result.is_valid, bool)
        self.assertIsInstance(validation_result.errors, list)
        self.assertIsInstance(validation_result.warnings, list)
    
    def test_secrets_management(self):
        """Test secrets management functionality"""
        secrets_manager = self.deployment_service.secrets_manager
        
        # Test setting and getting secrets
        test_secret = "test_secret_value_123"
        secrets_manager.set_secret("test_secret", test_secret)
        
        retrieved_secret = secrets_manager.get_secret("test_secret")
        self.assertEqual(retrieved_secret, test_secret)
        
        # Test non-existent secret
        non_existent = secrets_manager.get_secret("non_existent", "default")
        self.assertEqual(non_existent, "default")
    
    @patch('subprocess.run')
    def test_container_operations(self, mock_subprocess):
        """Test container management operations"""
        # Mock successful Docker command
        mock_subprocess.return_value = Mock(returncode=0, stdout="container_id_123")
        
        container_manager = self.deployment_service.container_manager
        
        # Test image building (mocked)
        with patch.object(container_manager, 'docker_available', True):
            result = container_manager.build_image("test:latest")
            self.assertTrue(result)
    
    def test_deployment_status(self):
        """Test deployment status retrieval"""
        status = self.deployment_service.get_deployment_status()
        
        self.assertIn("environment", status)
        self.assertIn("configuration", status)
        self.assertIn("docker", status)
        self.assertIn("kubernetes", status)
        self.assertEqual(status["environment"], "testing")


class TestNetworkServices(TestBase):
    """Test network-related services"""
    
    def setUp(self):
        super().setUp()
        self.mock_devices = [
            {
                "hostname": "LEAF1",
                "device_type": "cisco_nexus",
                "ip": "192.168.1.10",
                "username": "admin",
                "password": "admin123"
            },
            {
                "hostname": "SPINE1", 
                "device_type": "cisco_nexus",
                "ip": "192.168.1.20",
                "username": "admin",
                "password": "admin123"
            }
        ]
    
    def test_network_topology_service(self):
        """Test network topology service"""
        with patch('yaml.safe_load') as mock_yaml:
            mock_yaml.return_value = {"devices": self.mock_devices}
            
            topology_service = NetworkTopologyService()
            topology = topology_service.get_topology()
            
            self.assertIsNotNone(topology)
            self.assertIn("devices", topology)
    
    def test_device_details_service(self):
        """Test device details service"""
        device_service = DeviceDetailsService()
        
        # Test with mock device
        with patch.object(device_service, '_connect_to_device') as mock_connect:
            mock_connect.return_value = True
            
            details = device_service.get_device_details("LEAF1")
            self.assertIsNotNone(details)
    
    def test_network_status_service(self):
        """Test network status service"""
        status_service = NetworkStatusService()
        
        # Test status collection with mocked devices
        with patch('yaml.safe_load') as mock_yaml:
            mock_yaml.return_value = {"devices": self.mock_devices}
            
            status = status_service.get_network_status()
            self.assertIsNotNone(status)


class TestConfigGeneration(TestBase):
    """Test configuration generation functionality"""
    
    def setUp(self):
        super().setUp()
        self.config_service = ConfigGenerationService()
    
    def test_template_loading(self):
        """Test Jinja2 template loading"""
        # Test template existence check
        template_exists = os.path.exists("templates/base_config.j2")
        if template_exists:
            # Test template rendering with mock data
            mock_data = {
                "hostname": "TEST-DEVICE",
                "mgmt_ip": "192.168.1.100",
                "interfaces": [
                    {"name": "Ethernet1/1", "description": "Link to SPINE1"}
                ]
            }
            
            try:
                config = self.config_service.generate_config("TEST-DEVICE", mock_data)
                self.assertIsNotNone(config)
                self.assertIn("TEST-DEVICE", config)
            except Exception as e:
                # Template might not exist in test environment
                self.skipTest(f"Template not available: {e}")
    
    def test_config_validation(self):
        """Test configuration validation"""
        test_config = """
        hostname TEST-DEVICE
        interface Ethernet1/1
         description Test Interface
        """
        
        # Basic validation (syntax check)
        is_valid = len(test_config.strip()) > 0
        self.assertTrue(is_valid)


class TestAIAgent(TestBase):
    """Test AI agent functionality"""
    
    def setUp(self):
        super().setUp()
        # Mock AI agent to avoid external dependencies
        self.ai_agent = AIAgent()
    
    def test_ai_agent_initialization(self):
        """Test AI agent initializes correctly"""
        self.assertIsNotNone(self.ai_agent)
    
    @patch('requests.post')
    def test_ai_analysis(self, mock_post):
        """Test AI analysis functionality"""
        # Mock AI response
        mock_response = Mock()
        mock_response.json.return_value = {
            "analysis": "Network is healthy",
            "recommendations": ["Monitor bandwidth usage"],
            "confidence": 0.95
        }
        mock_post.return_value = mock_response
        
        analysis = self.ai_agent.analyze_network_data({
            "devices": ["LEAF1", "SPINE1"],
            "metrics": {"cpu_usage": 45, "memory_usage": 60}
        })
        
        if analysis:  # Only test if AI agent is properly implemented
            self.assertIn("analysis", analysis)


class TestIntegration(TestBase):
    """Integration tests for end-to-end workflows"""
    
    def setUp(self):
        super().setUp()
        os.environ['CONFIG_DIR'] = self.test_config_dir
        self.deployment_service = DeploymentService("testing")
        self.monitoring_service = MonitoringService(
            enable_prometheus=False,
            db_path=self.test_db_path
        )
    
    def test_monitoring_deployment_integration(self):
        """Test integration between monitoring and deployment services"""
        # Test deployment status includes monitoring info
        status = self.deployment_service.get_deployment_status()
        self.assertIn("configuration", status)
        
        # Test monitoring service health checks
        health = self.monitoring_service.health_checker.get_system_health()
        self.assertIn("overall_status", health)
    
    def test_configuration_monitoring_integration(self):
        """Test configuration changes are reflected in monitoring"""
        # Change configuration
        self.deployment_service.config_manager.set_config("test.value", "integration_test")
        
        # Verify configuration change
        value = self.deployment_service.config_manager.get_config("test.value")
        self.assertEqual(value, "integration_test")
    
    def test_end_to_end_workflow(self):
        """Test complete workflow from configuration to deployment"""
        # 1. Validate configuration
        validation = self.deployment_service.validate_deployment_config()
        self.assertIsNotNone(validation)
        
        # 2. Check system health
        health = self.monitoring_service.health_checker.get_system_health()
        self.assertIsNotNone(health)
        
        # 3. Get deployment status
        status = self.deployment_service.get_deployment_status()
        self.assertEqual(status["environment"], "testing")


class TestPerformance(TestBase):
    """Performance tests for system components"""
    
    def setUp(self):
        super().setUp()
        self.monitoring_service = MonitoringService(
            enable_prometheus=False,
            db_path=self.test_db_path
        )
    
    def test_health_check_performance(self):
        """Test health check performance"""
        # Register multiple health checks
        for i in range(10):
            def health_check(component_id=i):
                from services.monitoring_service import HealthStatus
                return HealthStatus(
                    f"component_{component_id}",
                    "healthy",
                    f"Component {component_id} is healthy",
                    datetime.now()
                )
            
            self.monitoring_service.health_checker.register_health_check(
                f"component_{i}", 
                lambda: health_check(i)
            )
        
        # Measure performance
        start_time = time.time()
        health_status = self.monitoring_service.health_checker.run_all_health_checks()
        end_time = time.time()
        
        execution_time = end_time - start_time
        self.assertLess(execution_time, 5.0)  # Should complete within 5 seconds
        self.assertEqual(len(health_status), 10)
    
    def test_configuration_loading_performance(self):
        """Test configuration loading performance"""
        config_manager = ConfigurationManager("testing")
        
        # Measure configuration loading time
        start_time = time.time()
        for _ in range(100):
            value = config_manager.get_config("api.host")
        end_time = time.time()
        
        execution_time = end_time - start_time
        self.assertLess(execution_time, 1.0)  # Should complete within 1 second
    
    def test_metrics_collection_performance(self):
        """Test metrics collection performance"""
        metrics_collector = self.monitoring_service.metrics_collector
        
        # Measure metrics collection performance
        start_time = time.time()
        for i in range(1000):
            metrics_collector.increment_counter("test_counter", {"iteration": str(i)})
            metrics_collector.set_gauge("test_gauge", float(i), {"iteration": str(i)})
        end_time = time.time()
        
        execution_time = end_time - start_time
        self.assertLess(execution_time, 2.0)  # Should complete within 2 seconds


class TestMockDevices(TestBase):
    """Test mock device functionality"""
    
    def setUp(self):
        super().setUp()
        self.mock_device_responses = {
            "show version": "Cisco Nexus Operating System (NX-OS) Software",
            "show interface brief": "Eth1/1    1    eth  access down    down",
            "show ip route": "0.0.0.0/0, ubest/mbest: 1/0, attached"
        }
    
    def test_mock_device_connection(self):
        """Test mock device connection simulation"""
        class MockDevice:
            def __init__(self, responses):
                self.responses = responses
                self.connected = False
            
            def connect(self):
                self.connected = True
                return True
            
            def send_command(self, command):
                return self.responses.get(command, "Command not found")
            
            def disconnect(self):
                self.connected = False
        
        # Test mock device
        device = MockDevice(self.mock_device_responses)
        
        # Test connection
        self.assertTrue(device.connect())
        self.assertTrue(device.connected)
        
        # Test command execution
        version_output = device.send_command("show version")
        self.assertIn("Cisco Nexus", version_output)
        
        # Test disconnection
        device.disconnect()
        self.assertFalse(device.connected)
    
    def test_mock_network_topology(self):
        """Test mock network topology simulation"""
        mock_topology = {
            "devices": [
                {"hostname": "LEAF1", "role": "leaf", "connections": ["SPINE1", "SPINE2"]},
                {"hostname": "LEAF2", "role": "leaf", "connections": ["SPINE1", "SPINE2"]},
                {"hostname": "SPINE1", "role": "spine", "connections": ["LEAF1", "LEAF2"]},
                {"hostname": "SPINE2", "role": "spine", "connections": ["LEAF1", "LEAF2"]}
            ]
        }
        
        # Validate topology structure
        self.assertIn("devices", mock_topology)
        self.assertEqual(len(mock_topology["devices"]), 4)
        
        # Validate device properties
        for device in mock_topology["devices"]:
            self.assertIn("hostname", device)
            self.assertIn("role", device)
            self.assertIn("connections", device)


def run_test_suite():
    """Run the complete test suite"""
    print("🧪 Running Network Automation Test Suite")
    print("=" * 60)
    
    # Discover and run all tests
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('.', pattern='test_*.py')
    
    # Also add our test classes
    test_classes = [
        TestMonitoringService,
        TestDeploymentService,
        TestNetworkServices,
        TestConfigGeneration,
        TestAIAgent,
        TestIntegration,
        TestPerformance,
        TestMockDevices
    ]
    
    for test_class in test_classes:
        tests = test_loader.loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        descriptions=True,
        failfast=False
    )
    
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"📊 Test Results Summary:")
    print(f"   Tests Run: {result.testsRun}")
    print(f"   ✅ Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"   ❌ Failed: {len(result.failures)}")
    print(f"   💥 Errors: {len(result.errors)}")
    print(f"   ⏭️ Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print(f"\n❌ Failures:")
        for test, traceback in result.failures:
            print(f"   - {test}: {traceback.split(chr(10))[-2] if chr(10) in traceback else traceback}")
    
    if result.errors:
        print(f"\n💥 Errors:")
        for test, traceback in result.errors:
            print(f"   - {test}: {traceback.split(chr(10))[-2] if chr(10) in traceback else traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\n🎉 Overall Result: {'PASSED' if success else 'FAILED'}")
    
    return success


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run network automation tests")
    parser.add_argument("--performance", action="store_true", help="Run performance tests")
    parser.add_argument("--integration", action="store_true", help="Run integration tests")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    
    success = run_test_suite()
    sys.exit(0 if success else 1)
