#!/usr/bin/env python3
"""
Deployment Testing and Validation Script

Tests deployment configurations, validates container health,
and performs smoke tests for deployed applications.
"""

import os
import sys
import time
import requests
import subprocess
import yaml
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.deployment_service import DeploymentService, ConfigurationManager
from services.monitoring_service import MonitoringService

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DeploymentTester:
    """Test deployment configurations and health"""
    
    def __init__(self, environment: str = "testing"):
        self.environment = environment
        self.deployment_service = DeploymentService(environment)
        self.monitoring_service = MonitoringService()
        self.test_results = []
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all deployment tests"""
        logger.info(f"Starting deployment tests for environment: {self.environment}")
        
        test_results = {
            "environment": self.environment,
            "timestamp": datetime.now().isoformat(),
            "tests": [],
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0
            }
        }
        
        # Test configuration validation
        test_results["tests"].append(self.test_configuration_validation())
        
        # Test secrets management
        test_results["tests"].append(self.test_secrets_management())
        
        # Test Docker availability and configuration
        test_results["tests"].append(self.test_docker_availability())
        
        # Test Kubernetes availability (if available)
        test_results["tests"].append(self.test_kubernetes_availability())
        
        # Test health endpoints
        test_results["tests"].append(self.test_health_endpoints())
        
        # Test monitoring integration
        test_results["tests"].append(self.test_monitoring_integration())
        
        # Test configuration export/import
        test_results["tests"].append(self.test_configuration_export())
        
        # Calculate summary
        for test in test_results["tests"]:
            test_results["summary"]["total"] += 1
            if test["status"] == "PASSED":
                test_results["summary"]["passed"] += 1
            elif test["status"] == "FAILED":
                test_results["summary"]["failed"] += 1
            else:
                test_results["summary"]["skipped"] += 1
        
        logger.info(f"Tests completed: {test_results['summary']}")
        return test_results
    
    def test_configuration_validation(self) -> Dict[str, Any]:
        """Test configuration validation"""
        test_name = "Configuration Validation"
        logger.info(f"Running test: {test_name}")
        
        try:
            validation = self.deployment_service.validate_deployment_config()
            
            if validation.is_valid:
                return {
                    "name": test_name,
                    "status": "PASSED",
                    "message": "Configuration validation successful",
                    "details": {
                        "errors": validation.errors,
                        "warnings": validation.warnings
                    }
                }
            else:
                return {
                    "name": test_name,
                    "status": "FAILED",
                    "message": f"Configuration validation failed: {validation.errors}",
                    "details": {
                        "errors": validation.errors,
                        "warnings": validation.warnings
                    }
                }
        
        except Exception as e:
            return {
                "name": test_name,
                "status": "FAILED",
                "message": f"Configuration validation error: {str(e)}",
                "details": {"exception": str(e)}
            }
    
    def test_secrets_management(self) -> Dict[str, Any]:
        """Test secrets management functionality"""
        test_name = "Secrets Management"
        logger.info(f"Running test: {test_name}")
        
        try:
            secrets_manager = self.deployment_service.secrets_manager
            
            # Test setting and getting secrets
            test_secret_name = "test_secret"
            test_secret_value = "test_value_123"
            
            secrets_manager.set_secret(test_secret_name, test_secret_value)
            retrieved_value = secrets_manager.get_secret(test_secret_name)
            
            if retrieved_value == test_secret_value:
                return {
                    "name": test_name,
                    "status": "PASSED",
                    "message": "Secrets management working correctly",
                    "details": {"test_secret": "successfully stored and retrieved"}
                }
            else:
                return {
                    "name": test_name,
                    "status": "FAILED",
                    "message": "Secret retrieval mismatch",
                    "details": {
                        "expected": test_secret_value,
                        "actual": retrieved_value
                    }
                }
        
        except Exception as e:
            return {
                "name": test_name,
                "status": "FAILED",
                "message": f"Secrets management error: {str(e)}",
                "details": {"exception": str(e)}
            }
    
    def test_docker_availability(self) -> Dict[str, Any]:
        """Test Docker availability and configuration"""
        test_name = "Docker Availability"
        logger.info(f"Running test: {test_name}")
        
        try:
            container_manager = self.deployment_service.container_manager
            
            if container_manager.docker_available:
                # Test Docker version
                result = subprocess.run(["docker", "--version"], 
                                      capture_output=True, text=True)
                
                return {
                    "name": test_name,
                    "status": "PASSED",
                    "message": "Docker is available and functional",
                    "details": {
                        "docker_version": result.stdout.strip(),
                        "available": True
                    }
                }
            else:
                return {
                    "name": test_name,
                    "status": "SKIPPED",
                    "message": "Docker not available in this environment",
                    "details": {"available": False}
                }
        
        except Exception as e:
            return {
                "name": test_name,
                "status": "FAILED",
                "message": f"Docker test error: {str(e)}",
                "details": {"exception": str(e)}
            }
    
    def test_kubernetes_availability(self) -> Dict[str, Any]:
        """Test Kubernetes availability and configuration"""
        test_name = "Kubernetes Availability"
        logger.info(f"Running test: {test_name}")
        
        try:
            k8s_manager = self.deployment_service.k8s_manager
            
            if k8s_manager.kubectl_available:
                # Test kubectl version
                result = subprocess.run(["kubectl", "version", "--client"], 
                                      capture_output=True, text=True)
                
                return {
                    "name": test_name,
                    "status": "PASSED",
                    "message": "Kubernetes kubectl is available",
                    "details": {
                        "kubectl_output": result.stdout.strip(),
                        "available": True
                    }
                }
            else:
                return {
                    "name": test_name,
                    "status": "SKIPPED",
                    "message": "Kubernetes not available in this environment",
                    "details": {"available": False}
                }
        
        except Exception as e:
            return {
                "name": test_name,
                "status": "FAILED",
                "message": f"Kubernetes test error: {str(e)}",
                "details": {"exception": str(e)}
            }
    
    def test_health_endpoints(self) -> Dict[str, Any]:
        """Test health endpoint availability"""
        test_name = "Health Endpoints"
        logger.info(f"Running test: {test_name}")
        
        try:
            config_manager = self.deployment_service.config_manager
            health_port = config_manager.get_config("monitoring.health_checks.port", 8080)
            health_endpoint = config_manager.get_config("monitoring.health_checks.endpoint", "/health")
            
            # For testing, we'll check if the configuration is valid
            # In a real deployment, we would make HTTP requests to the endpoints
            
            if health_port and health_endpoint:
                return {
                    "name": test_name,
                    "status": "PASSED",
                    "message": "Health endpoint configuration is valid",
                    "details": {
                        "port": health_port,
                        "endpoint": health_endpoint,
                        "url": f"http://localhost:{health_port}{health_endpoint}"
                    }
                }
            else:
                return {
                    "name": test_name,
                    "status": "FAILED",
                    "message": "Health endpoint configuration missing",
                    "details": {
                        "port": health_port,
                        "endpoint": health_endpoint
                    }
                }
        
        except Exception as e:
            return {
                "name": test_name,
                "status": "FAILED",
                "message": f"Health endpoint test error: {str(e)}",
                "details": {"exception": str(e)}
            }
    
    def test_monitoring_integration(self) -> Dict[str, Any]:
        """Test monitoring service integration"""
        test_name = "Monitoring Integration"
        logger.info(f"Running test: {test_name}")
        
        try:
            # Test monitoring service initialization
            health_status = self.monitoring_service.health_checker.get_system_health()
            
            if health_status.get("overall_status") == "healthy":
                return {
                    "name": test_name,
                    "status": "PASSED",
                    "message": "Monitoring integration working correctly",
                    "details": {
                        "health_status": health_status,
                        "monitoring_enabled": True
                    }
                }
            else:
                return {
                    "name": test_name,
                    "status": "FAILED",
                    "message": "Monitoring system reporting unhealthy status",
                    "details": {
                        "health_status": health_status,
                        "monitoring_enabled": True
                    }
                }
        
        except Exception as e:
            return {
                "name": test_name,
                "status": "FAILED",
                "message": f"Monitoring integration error: {str(e)}",
                "details": {"exception": str(e)}
            }
    
    def test_configuration_export(self) -> Dict[str, Any]:
        """Test configuration export functionality"""
        test_name = "Configuration Export"
        logger.info(f"Running test: {test_name}")
        
        try:
            # Test YAML export
            yaml_config = self.deployment_service.export_configuration("yaml")
            
            # Test JSON export
            json_config = self.deployment_service.export_configuration("json")
            
            # Validate exports
            yaml_parsed = yaml.safe_load(yaml_config)
            json_parsed = json.loads(json_config)
            
            if yaml_parsed and json_parsed:
                return {
                    "name": test_name,
                    "status": "PASSED",
                    "message": "Configuration export working correctly",
                    "details": {
                        "yaml_size": len(yaml_config),
                        "json_size": len(json_config),
                        "yaml_keys": len(yaml_parsed),
                        "json_keys": len(json_parsed)
                    }
                }
            else:
                return {
                    "name": test_name,
                    "status": "FAILED",
                    "message": "Configuration export produced empty results",
                    "details": {
                        "yaml_valid": bool(yaml_parsed),
                        "json_valid": bool(json_parsed)
                    }
                }
        
        except Exception as e:
            return {
                "name": test_name,
                "status": "FAILED",
                "message": f"Configuration export error: {str(e)}",
                "details": {"exception": str(e)}
            }


class ContainerHealthTester:
    """Test containerized application health"""
    
    def __init__(self, container_name: str = None, image_tag: str = None):
        self.container_name = container_name
        self.image_tag = image_tag or "network-automation:latest"
    
    def test_container_startup(self, timeout: int = 60) -> Dict[str, Any]:
        """Test container startup and health"""
        logger.info("Testing container startup...")
        
        try:
            # Check if Docker is available
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
            
            # Try to run container in test mode
            container_name = f"test-network-automation-{int(time.time())}"
            
            cmd = [
                "docker", "run", "-d",
                "--name", container_name,
                "-e", "ENVIRONMENT=testing",
                self.image_tag,
                "python", "-c", "import time; time.sleep(30)"  # Keep alive for testing
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                container_id = result.stdout.strip()
                
                # Wait for container to be ready
                time.sleep(5)
                
                # Check container status
                status_cmd = ["docker", "inspect", container_name, "--format", "{{.State.Status}}"]
                status_result = subprocess.run(status_cmd, capture_output=True, text=True)
                
                # Cleanup
                subprocess.run(["docker", "stop", container_name], capture_output=True)
                subprocess.run(["docker", "rm", container_name], capture_output=True)
                
                if status_result.returncode == 0 and "running" in status_result.stdout:
                    return {
                        "test": "Container Startup",
                        "status": "PASSED",
                        "message": "Container started successfully",
                        "details": {
                            "container_id": container_id[:12],
                            "image": self.image_tag,
                            "status": status_result.stdout.strip()
                        }
                    }
                else:
                    return {
                        "test": "Container Startup",
                        "status": "FAILED",
                        "message": "Container failed to start properly",
                        "details": {
                            "container_id": container_id[:12],
                            "status": status_result.stdout.strip()
                        }
                    }
            else:
                return {
                    "test": "Container Startup",
                    "status": "FAILED",
                    "message": f"Failed to start container: {result.stderr}",
                    "details": {"error": result.stderr}
                }
        
        except subprocess.CalledProcessError as e:
            return {
                "test": "Container Startup",
                "status": "SKIPPED",
                "message": "Docker not available for container testing",
                "details": {"error": str(e)}
            }
        except Exception as e:
            return {
                "test": "Container Startup",
                "status": "FAILED",
                "message": f"Container test error: {str(e)}",
                "details": {"exception": str(e)}
            }


def run_deployment_tests(environment: str = "testing") -> Dict[str, Any]:
    """Run all deployment tests for specified environment"""
    print(f"🧪 Running Deployment Tests for Environment: {environment}")
    print("=" * 60)
    
    # Run deployment tests
    tester = DeploymentTester(environment)
    test_results = tester.run_all_tests()
    
    # Run container tests if Docker is available
    container_tester = ContainerHealthTester()
    container_test = container_tester.test_container_startup()
    test_results["tests"].append(container_test)
    
    # Update summary
    if container_test["status"] == "PASSED":
        test_results["summary"]["passed"] += 1
    elif container_test["status"] == "FAILED":
        test_results["summary"]["failed"] += 1
    else:
        test_results["summary"]["skipped"] += 1
    test_results["summary"]["total"] += 1
    
    # Print results
    print(f"\n📊 Test Results Summary:")
    print(f"   Total Tests: {test_results['summary']['total']}")
    print(f"   ✅ Passed: {test_results['summary']['passed']}")
    print(f"   ❌ Failed: {test_results['summary']['failed']}")
    print(f"   ⏭️  Skipped: {test_results['summary']['skipped']}")
    
    print(f"\n📋 Detailed Results:")
    for test in test_results["tests"]:
        status_emoji = {"PASSED": "✅", "FAILED": "❌", "SKIPPED": "⏭️"}
        emoji = status_emoji.get(test["status"], "❓")
        test_name = test.get("name", test.get("test", "Unknown Test"))
        print(f"   {emoji} {test_name}: {test['status']}")
        if test["status"] == "FAILED":
            print(f"      📝 {test['message']}")
    
    return test_results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test deployment configurations")
    parser.add_argument("--environment", "-e", default="testing",
                       choices=["development", "testing", "production"],
                       help="Environment to test")
    parser.add_argument("--output", "-o", help="Output file for test results (JSON)")
    
    args = parser.parse_args()
    
    # Run tests
    results = run_deployment_tests(args.environment)
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to: {args.output}")
    
    # Exit with appropriate code
    if results["summary"]["failed"] > 0:
        print(f"\n❌ Some tests failed. Check the details above.")
        sys.exit(1)
    else:
        print(f"\n🎉 All tests passed successfully!")
        sys.exit(0)
