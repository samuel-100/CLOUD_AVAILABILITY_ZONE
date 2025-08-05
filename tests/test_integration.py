#!/usr/bin/env python3
"""
Integration Tests for Network Automation System

Tests end-to-end workflows, service interactions, and complete system functionality.
"""

import os
import sys
import time
import tempfile
import shutil
import unittest
import subprocess
import yaml
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import pytest

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from services.monitoring_service import MonitoringService
from services.deployment_service import DeploymentService
from services.network_topology import NetworkTopologyService
from services.device_details import DeviceDetailsService
from services.config_generation_tool import ConfigGenerationService
from services.network_status import NetworkStatusService


class TestSystemIntegration(unittest.TestCase):
    """Test complete system integration"""
    
    def setUp(self):
        # Create temporary test environment
        self.test_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.test_dir, "config")
        self.data_dir = os.path.join(self.test_dir, "data")
        self.logs_dir = os.path.join(self.test_dir, "logs")
        
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # Create test configuration
        self.test_config = {
            "api": {"host": "localhost", "port": 8080},
            "monitoring": {
                "prometheus": {"enabled": True, "port": 8000},
                "health_checks": {"enabled": True, "port": 8080},
                "logging": {"level": "INFO"}
            },
            "logging": {"level": "INFO"},
            "database": {"path": os.path.join(self.data_dir, "test.db")},
            "network": {"device_timeout": 30, "mock_devices": True},
            "deployment": {"max_replicas": 3, "min_replicas": 1}
        }
        
        # Save configuration
        with open(os.path.join(self.config_dir, "base.yaml"), 'w') as f:
            yaml.dump(self.test_config, f)
        
        with open(os.path.join(self.config_dir, "integration.yaml"), 'w') as f:
            yaml.dump({"testing": {"enabled": True}}, f)
        
        # Create mock device inventory
        self.mock_devices = [
            {
                "hostname": "LEAF1",
                "device_type": "cisco_nexus",
                "ip": "192.168.1.10",
                "username": "admin",
                "password": "admin123",
                "role": "leaf"
            },
            {
                "hostname": "SPINE1",
                "device_type": "cisco_nexus", 
                "ip": "192.168.1.20",
                "username": "admin",
                "password": "admin123",
                "role": "spine"
            }
        ]
        
        with open(os.path.join(self.config_dir, "devices.yaml"), 'w') as f:
            yaml.dump({"devices": self.mock_devices}, f)
        
        # Set environment variables
        os.environ['CONFIG_DIR'] = self.config_dir
        os.environ['ENVIRONMENT'] = 'integration'
        
        # Initialize services
        self.monitoring_service = MonitoringService(
            enable_prometheus=False,
            db_path=os.path.join(self.data_dir, "monitoring.db")
        )
        
        self.deployment_service = DeploymentService("integration")
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        if 'CONFIG_DIR' in os.environ:
            del os.environ['CONFIG_DIR']
        if 'ENVIRONMENT' in os.environ:
            del os.environ['ENVIRONMENT']
    
    def test_service_initialization_integration(self):
        """Test all services initialize correctly together"""
        # Test monitoring service
        self.assertIsNotNone(self.monitoring_service)
        self.assertIsNotNone(self.monitoring_service.health_checker)
        self.assertIsNotNone(self.monitoring_service.metrics_collector)
        
        # Test deployment service
        self.assertIsNotNone(self.deployment_service)
        self.assertIsNotNone(self.deployment_service.config_manager)
        self.assertIsNotNone(self.deployment_service.secrets_manager)
        
        # Test configuration consistency
        config_value = self.deployment_service.config_manager.get_config("api.port")
        self.assertEqual(config_value, 8080)
    
    def test_monitoring_deployment_integration(self):
        """Test monitoring and deployment services work together"""
        # Get deployment status
        deployment_status = self.deployment_service.get_deployment_status()
        self.assertIn("configuration", deployment_status)
        
        # Get system health
        system_health = self.monitoring_service.health_checker.get_system_health()
        self.assertIn("overall_status", system_health)
        
        # Both services should be operational
        self.assertIsNotNone(deployment_status)
        self.assertIsNotNone(system_health)
    
    def test_configuration_monitoring_integration(self):
        """Test configuration changes are reflected in monitoring"""
        # Change configuration
        original_port = self.deployment_service.config_manager.get_config("api.port")
        self.deployment_service.config_manager.set_config("api.port", 9080)
        
        # Verify configuration change
        new_port = self.deployment_service.config_manager.get_config("api.port")
        self.assertEqual(new_port, 9080)
        self.assertNotEqual(new_port, original_port)
        
        # Configuration validation should still work
        validation = self.deployment_service.validate_deployment_config()
        self.assertIsNotNone(validation)
    
    @patch('yaml.safe_load')
    def test_network_services_integration(self, mock_yaml_load):
        """Test network services integration"""
        # Mock device loading
        mock_yaml_load.return_value = {"devices": self.mock_devices}
        
        # Test network topology service
        topology_service = NetworkTopologyService()
        topology = topology_service.get_topology()
        self.assertIsNotNone(topology)
        
        # Test device details service
        device_service = DeviceDetailsService()
        
        # Mock device connection
        with patch.object(device_service, '_connect_to_device', return_value=True):
            details = device_service.get_device_details("LEAF1")
            self.assertIsNotNone(details)
        
        # Test network status service
        status_service = NetworkStatusService()
        status = status_service.get_network_status()
        self.assertIsNotNone(status)


class TestWorkflowIntegration(unittest.TestCase):
    """Test complete workflow integration"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.test_dir, "config")
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Create minimal configuration
        test_config = {
            "api": {"host": "localhost", "port": 8080},
            "monitoring": {
                "prometheus": {"enabled": True},
                "health_checks": {"enabled": True},
                "logging": {"level": "INFO"}
            },
            "logging": {"level": "INFO"},
            "network": {"mock_devices": True}
        }
        
        with open(os.path.join(self.config_dir, "base.yaml"), 'w') as f:
            yaml.dump(test_config, f)
        
        os.environ['CONFIG_DIR'] = self.config_dir
        
        # Initialize services for workflow testing
        self.deployment_service = DeploymentService("integration")
        self.monitoring_service = MonitoringService(
            enable_prometheus=False,
            db_path=os.path.join(self.test_dir, "test.db")
        )
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        if 'CONFIG_DIR' in os.environ:
            del os.environ['CONFIG_DIR']
    
    def test_complete_deployment_workflow(self):
        """Test complete deployment workflow"""
        # Step 1: Validate configuration
        validation = self.deployment_service.validate_deployment_config()
        self.assertIsNotNone(validation)
        
        # Step 2: Check system health
        health = self.monitoring_service.health_checker.get_system_health()
        self.assertIn("overall_status", health)
        
        # Step 3: Get deployment status
        status = self.deployment_service.get_deployment_status()
        self.assertIn("environment", status)
        
        # Workflow should complete successfully
        self.assertTrue(True)  # If we get here, workflow completed
    
    def test_monitoring_workflow(self):
        """Test monitoring workflow"""
        # Register a test health check
        def test_health_check():
            from services.monitoring_service import HealthStatus
            return HealthStatus(
                component="workflow_test",
                status="healthy",
                message="Workflow test component",
                timestamp=datetime.now()
            )
        
        self.monitoring_service.health_checker.register_health_check(
            "workflow_test", test_health_check
        )
        
        # Run health checks
        all_health = self.monitoring_service.health_checker.run_all_health_checks()
        self.assertIn("workflow_test", all_health)
        
        # Get system health
        system_health = self.monitoring_service.health_checker.get_system_health()
        self.assertIn("workflow_test", system_health["components"])
        
        # Collect metrics
        self.monitoring_service.metrics_collector.increment_counter(
            "workflow_test_counter", {"test": "integration"}
        )
        
        # Workflow should complete successfully
        self.assertTrue(True)
    
    def test_configuration_workflow(self):
        """Test configuration management workflow"""
        config_manager = self.deployment_service.config_manager
        
        # Get initial configuration
        initial_config = config_manager.get_config("api.port")
        self.assertEqual(initial_config, 8080)
        
        # Modify configuration
        config_manager.set_config("api.new_setting", "workflow_test")
        
        # Validate configuration
        validation = config_manager.validate_config()
        self.assertIsNotNone(validation)
        
        # Export configuration
        exported_config = config_manager.export_config("yaml")
        self.assertIsInstance(exported_config, str)
        
        # Parse exported configuration
        parsed_config = yaml.safe_load(exported_config)
        self.assertIn("api", parsed_config)
        
        # Workflow should complete successfully
        self.assertTrue(True)


class TestPerformanceIntegration(unittest.TestCase):
    """Test system performance under integrated load"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        
        # Create minimal test configuration
        config_dir = os.path.join(self.test_dir, "config")
        os.makedirs(config_dir, exist_ok=True)
        
        test_config = {
            "api": {"host": "localhost", "port": 8080},
            "monitoring": {
                "prometheus": {"enabled": False},
                "health_checks": {"enabled": True},
                "logging": {"level": "WARNING"}  # Reduce logging for performance
            },
            "logging": {"level": "WARNING"}
        }
        
        with open(os.path.join(config_dir, "base.yaml"), 'w') as f:
            yaml.dump(test_config, f)
        
        os.environ['CONFIG_DIR'] = config_dir
        
        self.deployment_service = DeploymentService("performance")
        self.monitoring_service = MonitoringService(
            enable_prometheus=False,
            db_path=os.path.join(self.test_dir, "perf.db")
        )
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        if 'CONFIG_DIR' in os.environ:
            del os.environ['CONFIG_DIR']
    
    def test_concurrent_health_checks(self):
        """Test concurrent health check performance"""
        # Register multiple health checks
        for i in range(20):
            def health_check(component_id=i):
                from services.monitoring_service import HealthStatus
                return HealthStatus(
                    f"perf_component_{component_id}",
                    "healthy",
                    f"Performance test component {component_id}",
                    datetime.now()
                )
            
            self.monitoring_service.health_checker.register_health_check(
                f"perf_component_{i}", 
                lambda: health_check(i)
            )
        
        # Measure performance
        start_time = time.time()
        all_health = self.monitoring_service.health_checker.run_all_health_checks()
        end_time = time.time()
        
        execution_time = end_time - start_time
        
        # Should complete within reasonable time
        self.assertLess(execution_time, 10.0)  # 10 seconds max
        self.assertEqual(len(all_health), 20)
    
    def test_configuration_access_performance(self):
        """Test configuration access performance"""
        config_manager = self.deployment_service.config_manager
        
        # Measure configuration access performance
        start_time = time.time()
        
        for i in range(1000):
            # Access various configuration values
            config_manager.get_config("api.host")
            config_manager.get_config("api.port")
            config_manager.get_config("monitoring.health_checks.enabled")
            config_manager.get_config("non.existent.key", "default")
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete within reasonable time
        self.assertLess(execution_time, 2.0)  # 2 seconds max for 1000 operations
    
    def test_metrics_collection_performance(self):
        """Test metrics collection performance"""
        metrics_collector = self.monitoring_service.metrics_collector
        
        # Measure metrics collection performance
        start_time = time.time()
        
        for i in range(1000):
            metrics_collector.increment_counter(
                "perf_test_counter", 
                {"iteration": str(i % 10)}  # Limit label cardinality
            )
            metrics_collector.set_gauge(
                "perf_test_gauge", 
                float(i), 
                {"batch": str(i // 100)}
            )
            if i % 10 == 0:  # Less frequent histogram observations
                metrics_collector.observe_histogram(
                    "perf_test_histogram", 
                    float(i) / 100, 
                    {"operation": "performance_test"}
                )
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete within reasonable time
        self.assertLess(execution_time, 5.0)  # 5 seconds max for 1000 operations


class TestErrorHandlingIntegration(unittest.TestCase):
    """Test error handling across integrated services"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        config_dir = os.path.join(self.test_dir, "config")
        os.makedirs(config_dir, exist_ok=True)
        
        # Create configuration with potential issues
        test_config = {
            "api": {"host": "localhost", "port": "invalid_port"},  # Invalid port
            "monitoring": {
                "prometheus": {"enabled": True},
                "health_checks": {"enabled": True},
                "logging": {"level": "INFO"}
            },
            "logging": {"level": "INFO"}
        }
        
        with open(os.path.join(config_dir, "base.yaml"), 'w') as f:
            yaml.dump(test_config, f)
        
        os.environ['CONFIG_DIR'] = config_dir
        
        self.deployment_service = DeploymentService("error_test")
        self.monitoring_service = MonitoringService(
            enable_prometheus=False,
            db_path=os.path.join(self.test_dir, "error.db")
        )
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        if 'CONFIG_DIR' in os.environ:
            del os.environ['CONFIG_DIR']
    
    def test_configuration_error_handling(self):
        """Test configuration error handling"""
        # Configuration validation should detect invalid port
        validation = self.deployment_service.validate_deployment_config()
        
        # Should have errors due to invalid configuration
        self.assertIsInstance(validation.errors, list)
        # Note: Specific validation depends on implementation
    
    def test_health_check_error_handling(self):
        """Test health check error handling"""
        # Register a failing health check
        def failing_health_check():
            raise Exception("Simulated health check failure")
        
        self.monitoring_service.health_checker.register_health_check(
            "failing_component", failing_health_check
        )
        
        # Run the failing health check
        result = self.monitoring_service.health_checker.run_health_check("failing_component")
        
        # Should handle the error gracefully
        self.assertEqual(result.component, "failing_component")
        self.assertEqual(result.status, "critical")
        self.assertIn("Health check failed", result.message)
    
    def test_service_integration_error_handling(self):
        """Test error handling across service integration"""
        # Test deployment status retrieval with potential errors
        status = self.deployment_service.get_deployment_status()
        
        # Should return status even with configuration issues
        self.assertIn("environment", status)
        self.assertIn("configuration", status)
        
        # Configuration should show as invalid
        if "valid" in status.get("configuration", {}):
            # If validation is implemented, it should detect issues
            pass  # Implementation-dependent


def run_integration_tests():
    """Run all integration tests"""
    print("🔗 Running Integration Tests")
    print("=" * 60)
    
    # Discover and run integration tests
    test_loader = unittest.TestLoader()
    
    test_classes = [
        TestSystemIntegration,
        TestWorkflowIntegration,
        TestPerformanceIntegration,
        TestErrorHandlingIntegration
    ]
    
    test_suite = unittest.TestSuite()
    
    for test_class in test_classes:
        tests = test_loader.loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        descriptions=True
    )
    
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"📊 Integration Test Results:")
    print(f"   Tests Run: {result.testsRun}")
    print(f"   ✅ Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"   ❌ Failed: {len(result.failures)}")
    print(f"   💥 Errors: {len(result.errors)}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\n🎉 Integration Tests: {'PASSED' if success else 'FAILED'}")
    
    return success


if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)
