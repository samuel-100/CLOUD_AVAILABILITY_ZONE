#!/usr/bin/env python3
"""
Unit Tests for Deployment Service

Tests all components of the deployment service including configuration management,
secrets handling, container operations, and Kubernetes deployment.
"""

import os
import sys
import tempfile
import shutil
import unittest
import yaml
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import pytest

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from services.deployment_service import (
    DeploymentService, ConfigurationManager, SecretsManager, ContainerManager,
    KubernetesManager, ConfigValidationResult, DeploymentConfig
)


class TestConfigurationManager(unittest.TestCase):
    """Test configuration management functionality"""
    
    def setUp(self):
        # Create temporary directory for test configs
        self.test_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.test_dir, "config")
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Create test configuration files
        self.base_config = {
            "api": {
                "host": "0.0.0.0",
                "port": 8080,
                "timeout": 30
            },
            "monitoring": {
                "prometheus": {"enabled": True, "port": 8000},
                "health_checks": {"enabled": True, "port": 8080},
                "logging": {"level": "INFO"}
            },
            "database": {
                "type": "sqlite",
                "path": "data/test.db"
            },
            "security": {
                "authentication": {"enabled": True},
                "encryption": {"enabled": True}
            }
        }
        
        self.dev_config = {
            "api": {
                "debug": True,
                "port": 8081  # Override port for development
            },
            "monitoring": {
                "logging": {"level": "DEBUG"}
            },
            "security": {
                "authentication": {"enabled": False},  # Disable for dev
                "encryption": {"enabled": False}
            },
            "development": {
                "auto_reload": True,
                "mock_devices": True
            }
        }
        
        # Save test configurations
        with open(os.path.join(self.config_dir, "base.yaml"), 'w') as f:
            yaml.dump(self.base_config, f)
        
        with open(os.path.join(self.config_dir, "development.yaml"), 'w') as f:
            yaml.dump(self.dev_config, f)
        
        # Initialize configuration manager
        with patch.object(ConfigurationManager, '__init__', lambda x, env: None):
            self.config_manager = ConfigurationManager("development")
            self.config_manager.environment = "development"
            self.config_manager.config_dir = self.config_dir
            self.config_manager.base_config = self.base_config
            self.config_manager.environment_config = self.dev_config
            self.config_manager.merged_config = self.config_manager._merge_configs(
                self.base_config, self.dev_config
            )
            self.config_manager.secrets_manager = Mock()
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_configuration_loading(self):
        """Test configuration file loading"""
        # Test base configuration values
        api_host = self.config_manager.get_config("api.host")
        self.assertEqual(api_host, "0.0.0.0")
        
        # Test environment override
        api_port = self.config_manager.get_config("api.port")
        self.assertEqual(api_port, 8081)  # Should be development override
        
        # Test nested configuration
        log_level = self.config_manager.get_config("monitoring.logging.level")
        self.assertEqual(log_level, "DEBUG")  # Should be development override
    
    def test_configuration_merging(self):
        """Test hierarchical configuration merging"""
        merged = self.config_manager._merge_configs(self.base_config, self.dev_config)
        
        # Base values should be preserved
        self.assertEqual(merged["api"]["host"], "0.0.0.0")
        
        # Override values should be applied
        self.assertEqual(merged["api"]["port"], 8081)
        self.assertEqual(merged["monitoring"]["logging"]["level"], "DEBUG")
        
        # New sections should be added
        self.assertIn("development", merged)
        self.assertTrue(merged["development"]["auto_reload"])
        
        # Nested merging should work
        self.assertTrue(merged["monitoring"]["prometheus"]["enabled"])  # From base
        self.assertEqual(merged["monitoring"]["health_checks"]["port"], 8080)  # From base
    
    def test_configuration_defaults(self):
        """Test configuration default values"""
        # Test existing configuration
        existing_value = self.config_manager.get_config("api.host")
        self.assertEqual(existing_value, "0.0.0.0")
        
        # Test non-existent configuration with default
        non_existent = self.config_manager.get_config("non.existent.key", "default_value")
        self.assertEqual(non_existent, "default_value")
        
        # Test non-existent configuration without default
        non_existent_no_default = self.config_manager.get_config("non.existent.key")
        self.assertIsNone(non_existent_no_default)
    
    def test_configuration_setting(self):
        """Test setting configuration values"""
        # Set new configuration value
        self.config_manager.set_config("test.new.value", "test_value")
        
        # Retrieve and verify
        retrieved_value = self.config_manager.get_config("test.new.value")
        self.assertEqual(retrieved_value, "test_value")
        
        # Set nested configuration
        self.config_manager.set_config("api.new_setting", "new_value")
        new_setting = self.config_manager.get_config("api.new_setting")
        self.assertEqual(new_setting, "new_value")
    
    def test_configuration_validation(self):
        """Test configuration validation"""
        validation_result = self.config_manager.validate_config()
        
        self.assertIsInstance(validation_result, ConfigValidationResult)
        self.assertIsInstance(validation_result.is_valid, bool)
        self.assertIsInstance(validation_result.errors, list)
        self.assertIsInstance(validation_result.warnings, list)
    
    def test_secret_substitution(self):
        """Test secret placeholder substitution"""
        # Mock secrets manager
        self.config_manager.secrets_manager.get_secret.return_value = "secret_value_123"
        
        # Test configuration with secret placeholder
        test_config = {"database": {"password": "${db_password}"}}
        result = self.config_manager._recursive_substitute(test_config)
        
        self.assertEqual(result["database"]["password"], "secret_value_123")
        self.config_manager.secrets_manager.get_secret.assert_called_with("db_password")
    
    def test_configuration_export(self):
        """Test configuration export functionality"""
        # Test YAML export
        yaml_export = self.config_manager.export_config("yaml")
        self.assertIsInstance(yaml_export, str)
        
        # Verify YAML can be parsed
        parsed_yaml = yaml.safe_load(yaml_export)
        self.assertIn("api", parsed_yaml)
        
        # Test JSON export
        json_export = self.config_manager.export_config("json")
        self.assertIsInstance(json_export, str)
        
        # Verify JSON can be parsed
        parsed_json = json.loads(json_export)
        self.assertIn("api", parsed_json)


class TestSecretsManager(unittest.TestCase):
    """Test secrets management functionality"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.secrets_file = os.path.join(self.test_dir, ".secrets.yaml")
        
        # Create secrets manager with test file
        with patch.object(SecretsManager, '__init__', lambda x, backend: None):
            self.secrets_manager = SecretsManager("file")
            self.secrets_manager.secrets_backend = "file"
            self.secrets_manager.secrets_file = self.secrets_file
            self.secrets_manager.secrets_cache = {}
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_file_secrets_storage(self):
        """Test file-based secrets storage"""
        # Set a secret
        self.secrets_manager.set_secret("test_secret", "test_value")
        
        # Verify secret is in cache
        self.assertEqual(self.secrets_manager.secrets_cache["test_secret"], "test_value")
        
        # Get the secret
        retrieved_secret = self.secrets_manager.get_secret("test_secret")
        self.assertEqual(retrieved_secret, "test_value")
    
    def test_environment_secrets(self):
        """Test environment variable secrets"""
        with patch.dict(os.environ, {"NETAUTO_SECRET_TEST_KEY": "env_secret_value"}):
            # Create environment secrets manager
            with patch.object(SecretsManager, '__init__', lambda x, backend: None):
                env_secrets_manager = SecretsManager("env")
                env_secrets_manager.secrets_backend = "env"
                env_secrets_manager.secrets_cache = {}
            
            # Load secrets from environment
            secrets = env_secrets_manager._load_env_secrets()
            
            self.assertIn("test_key", secrets)
            self.assertEqual(secrets["test_key"], "env_secret_value")
    
    def test_secret_defaults(self):
        """Test secret default values"""
        # Test non-existent secret with default
        default_value = self.secrets_manager.get_secret("non_existent", "default_secret")
        self.assertEqual(default_value, "default_secret")
        
        # Test non-existent secret without default
        no_default = self.secrets_manager.get_secret("non_existent")
        self.assertIsNone(no_default)
    
    @patch('os.path.exists')
    @patch('builtins.open')
    @patch('yaml.safe_load')
    def test_secrets_file_loading(self, mock_yaml_load, mock_open, mock_exists):
        """Test secrets file loading"""
        mock_exists.return_value = True
        mock_yaml_load.return_value = {"api_key": "secret123", "db_password": "pass456"}
        
        secrets = self.secrets_manager._load_file_secrets()
        
        self.assertEqual(secrets["api_key"], "secret123")
        self.assertEqual(secrets["db_password"], "pass456")


class TestContainerManager(unittest.TestCase):
    """Test container management functionality"""
    
    def setUp(self):
        self.container_manager = ContainerManager()
    
    @patch('subprocess.run')
    def test_docker_availability_check(self, mock_subprocess):
        """Test Docker availability checking"""
        # Test Docker available
        mock_subprocess.return_value = Mock(returncode=0)
        with patch.object(ContainerManager, '__init__', lambda x: None):
            container_manager = ContainerManager()
            container_manager.docker_available = container_manager._check_docker()
        
        self.assertTrue(container_manager.docker_available)
        
        # Test Docker not available
        mock_subprocess.side_effect = FileNotFoundError()
        with patch.object(ContainerManager, '__init__', lambda x: None):
            container_manager = ContainerManager()
            container_manager.docker_available = container_manager._check_docker()
        
        self.assertFalse(container_manager.docker_available)
    
    @patch('subprocess.run')
    def test_image_building(self, mock_subprocess):
        """Test Docker image building"""
        # Mock successful build
        mock_subprocess.return_value = Mock(returncode=0, stderr="")
        
        with patch.object(self.container_manager, 'docker_available', True):
            result = self.container_manager.build_image("test:latest")
            self.assertTrue(result)
        
        # Mock failed build
        mock_subprocess.return_value = Mock(returncode=1, stderr="Build failed")
        
        with patch.object(self.container_manager, 'docker_available', True):
            result = self.container_manager.build_image("test:latest")
            self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_container_operations(self, mock_subprocess):
        """Test container run/stop operations"""
        # Mock successful container run
        mock_subprocess.return_value = Mock(returncode=0, stdout="container_id_123\n")
        
        with patch.object(self.container_manager, 'docker_available', True):
            container_id = self.container_manager.run_container("test:latest", "testing")
            self.assertEqual(container_id, "container_id_123")
        
        # Mock container stop
        mock_subprocess.return_value = Mock(returncode=0)
        
        with patch.object(self.container_manager, 'docker_available', True):
            result = self.container_manager.stop_container("test_container")
            self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_container_logs(self, mock_subprocess):
        """Test container log retrieval"""
        mock_subprocess.return_value = Mock(stdout="Container log output\nMultiple lines")
        
        with patch.object(self.container_manager, 'docker_available', True):
            logs = self.container_manager.get_container_logs("test_container", 50)
            self.assertIn("Container log output", logs)


class TestKubernetesManager(unittest.TestCase):
    """Test Kubernetes management functionality"""
    
    def setUp(self):
        self.k8s_manager = KubernetesManager()
    
    @patch('subprocess.run')
    def test_kubectl_availability_check(self, mock_subprocess):
        """Test kubectl availability checking"""
        # Test kubectl available
        mock_subprocess.return_value = Mock(returncode=0)
        with patch.object(KubernetesManager, '__init__', lambda x: None):
            k8s_manager = KubernetesManager()
            k8s_manager.kubectl_available = k8s_manager._check_kubectl()
        
        self.assertTrue(k8s_manager.kubectl_available)
        
        # Test kubectl not available
        mock_subprocess.side_effect = FileNotFoundError()
        with patch.object(KubernetesManager, '__init__', lambda x: None):
            k8s_manager = KubernetesManager()
            k8s_manager.kubectl_available = k8s_manager._check_kubectl()
        
        self.assertFalse(k8s_manager.kubectl_available)
    
    @patch('subprocess.run')
    def test_manifest_application(self, mock_subprocess):
        """Test Kubernetes manifest application"""
        # Mock successful apply
        mock_subprocess.return_value = Mock(returncode=0, stderr="")
        
        with patch.object(self.k8s_manager, 'kubectl_available', True):
            result = self.k8s_manager.apply_manifests("k8s")
            self.assertTrue(result)
        
        # Mock failed apply
        mock_subprocess.return_value = Mock(returncode=1, stderr="Apply failed")
        
        with patch.object(self.k8s_manager, 'kubectl_available', True):
            result = self.k8s_manager.apply_manifests("k8s")
            self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_deployment_status(self, mock_subprocess):
        """Test deployment status retrieval"""
        # Mock deployment status response
        mock_response = {
            "items": [{
                "metadata": {"name": "network-automation"},
                "spec": {"replicas": 2},
                "status": {"readyReplicas": 2}
            }]
        }
        mock_subprocess.return_value = Mock(
            returncode=0, 
            stdout=json.dumps(mock_response)
        )
        
        with patch.object(self.k8s_manager, 'kubectl_available', True):
            status = self.k8s_manager.get_deployment_status()
            self.assertIn("items", status)
            self.assertEqual(len(status["items"]), 1)
    
    @patch('subprocess.run')
    def test_deployment_scaling(self, mock_subprocess):
        """Test deployment scaling"""
        mock_subprocess.return_value = Mock(returncode=0, stderr="")
        
        with patch.object(self.k8s_manager, 'kubectl_available', True):
            result = self.k8s_manager.scale_deployment("network-automation", 3)
            self.assertTrue(result)


class TestDeploymentServiceIntegration(unittest.TestCase):
    """Test complete deployment service integration"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        
        # Create test configuration
        config_dir = os.path.join(self.test_dir, "config")
        os.makedirs(config_dir, exist_ok=True)
        
        test_config = {
            "api": {"host": "localhost", "port": 8080},
            "monitoring": {
                "prometheus": {"enabled": True, "port": 8000},
                "health_checks": {"enabled": True, "port": 8080},
                "logging": {"level": "INFO"}
            },
            "logging": {"level": "INFO"},
            "database": {"path": os.path.join(self.test_dir, "test.db")},
            "deployment": {"max_replicas": 3, "min_replicas": 1}
        }
        
        with open(os.path.join(config_dir, "base.yaml"), 'w') as f:
            yaml.dump(test_config, f)
        
        with open(os.path.join(config_dir, "testing.yaml"), 'w') as f:
            yaml.dump({"testing": {"enabled": True}}, f)
        
        # Set environment variable for config directory
        os.environ['CONFIG_DIR'] = config_dir
        
        self.deployment_service = DeploymentService("testing")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        if 'CONFIG_DIR' in os.environ:
            del os.environ['CONFIG_DIR']
    
    def test_service_initialization(self):
        """Test deployment service initialization"""
        self.assertIsNotNone(self.deployment_service.config_manager)
        self.assertIsNotNone(self.deployment_service.secrets_manager)
        self.assertIsNotNone(self.deployment_service.container_manager)
        self.assertIsNotNone(self.deployment_service.k8s_manager)
        self.assertEqual(self.deployment_service.environment, "testing")
    
    def test_deployment_validation(self):
        """Test deployment configuration validation"""
        validation_result = self.deployment_service.validate_deployment_config()
        
        self.assertIsInstance(validation_result, ConfigValidationResult)
        self.assertIsInstance(validation_result.is_valid, bool)
        self.assertIsInstance(validation_result.errors, list)
        self.assertIsInstance(validation_result.warnings, list)
    
    def test_deployment_status(self):
        """Test deployment status retrieval"""
        status = self.deployment_service.get_deployment_status()
        
        self.assertIn("environment", status)
        self.assertIn("configuration", status)
        self.assertIn("docker", status)
        self.assertIn("kubernetes", status)
        self.assertEqual(status["environment"], "testing")
    
    def test_configuration_export(self):
        """Test configuration export"""
        # Test YAML export
        yaml_config = self.deployment_service.export_configuration("yaml")
        self.assertIsInstance(yaml_config, str)
        
        # Verify YAML is valid
        parsed_yaml = yaml.safe_load(yaml_config)
        self.assertIn("api", parsed_yaml)
        
        # Test JSON export
        json_config = self.deployment_service.export_configuration("json")
        self.assertIsInstance(json_config, str)
        
        # Verify JSON is valid
        parsed_json = json.loads(json_config)
        self.assertIn("api", parsed_json)


if __name__ == "__main__":
    # Run deployment service tests
    unittest.main(verbosity=2)
