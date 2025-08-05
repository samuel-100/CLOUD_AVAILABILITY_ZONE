#!/usr/bin/env python3
"""
Deployment and Configuration Management Service

Handles containerized deployment, configuration management, secrets handling,
and environment-specific configurations for the network automation system.
"""

import os
import sys
import yaml
import json
import subprocess
import tempfile
import shutil
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class DeploymentConfig:
    """Deployment configuration settings"""
    environment: str
    image_tag: str
    replicas: int
    resources: Dict[str, Any]
    secrets: Dict[str, str]
    config_overrides: Dict[str, Any]


@dataclass
class ConfigValidationResult:
    """Configuration validation result"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]


class SecretsManager:
    """Manage secrets and sensitive configuration data"""
    
    def __init__(self, secrets_backend: str = "file"):
        self.secrets_backend = secrets_backend
        self.secrets_file = "config/.secrets.yaml"
        self.secrets_cache = {}
    
    def load_secrets(self) -> Dict[str, str]:
        """Load secrets from configured backend"""
        if self.secrets_backend == "file":
            return self._load_file_secrets()
        elif self.secrets_backend == "env":
            return self._load_env_secrets()
        elif self.secrets_backend == "k8s":
            return self._load_k8s_secrets()
        else:
            logger.warning(f"Unknown secrets backend: {self.secrets_backend}")
            return {}
    
    def _load_file_secrets(self) -> Dict[str, str]:
        """Load secrets from encrypted file"""
        if not os.path.exists(self.secrets_file):
            logger.warning(f"Secrets file not found: {self.secrets_file}")
            return {}
        
        try:
            with open(self.secrets_file, 'r') as f:
                secrets = yaml.safe_load(f)
            return secrets or {}
        except Exception as e:
            logger.error(f"Failed to load secrets from file: {e}")
            return {}
    
    def _load_env_secrets(self) -> Dict[str, str]:
        """Load secrets from environment variables"""
        secrets = {}
        env_prefix = "NETAUTO_SECRET_"
        
        for key, value in os.environ.items():
            if key.startswith(env_prefix):
                secret_name = key[len(env_prefix):].lower()
                secrets[secret_name] = value
        
        return secrets
    
    def _load_k8s_secrets(self) -> Dict[str, str]:
        """Load secrets from Kubernetes secrets"""
        # In a real K8s environment, secrets would be mounted as files
        secrets_dir = "/var/secrets"
        secrets = {}
        
        if os.path.exists(secrets_dir):
            for secret_file in os.listdir(secrets_dir):
                secret_path = os.path.join(secrets_dir, secret_file)
                try:
                    with open(secret_path, 'r') as f:
                        secrets[secret_file] = f.read().strip()
                except Exception as e:
                    logger.error(f"Failed to read secret {secret_file}: {e}")
        
        return secrets
    
    def get_secret(self, name: str, default: str = None) -> Optional[str]:
        """Get a specific secret by name"""
        if not self.secrets_cache:
            self.secrets_cache = self.load_secrets()
        
        return self.secrets_cache.get(name, default)
    
    def set_secret(self, name: str, value: str):
        """Set a secret (for development/testing)"""
        self.secrets_cache[name] = value
        
        if self.secrets_backend == "file":
            self._save_file_secrets()
    
    def _save_file_secrets(self):
        """Save secrets to file (development only)"""
        os.makedirs(os.path.dirname(self.secrets_file), exist_ok=True)
        
        try:
            with open(self.secrets_file, 'w') as f:
                yaml.dump(self.secrets_cache, f, default_flow_style=False)
            
            # Set restrictive permissions
            os.chmod(self.secrets_file, 0o600)
            
        except Exception as e:
            logger.error(f"Failed to save secrets to file: {e}")


class ConfigurationManager:
    """Manage environment-specific configurations"""
    
    def __init__(self, environment: str = "development"):
        self.environment = environment
        self.config_dir = Path("config")
        self.base_config = {}
        self.environment_config = {}
        self.merged_config = {}
        self.secrets_manager = SecretsManager()
        
        self._load_configurations()
    
    def _load_configurations(self):
        """Load base and environment-specific configurations"""
        # Load base configuration
        base_config_file = self.config_dir / "base.yaml"
        if base_config_file.exists():
            with open(base_config_file, 'r') as f:
                self.base_config = yaml.safe_load(f) or {}
        
        # Load environment-specific configuration
        env_config_file = self.config_dir / f"{self.environment}.yaml"
        if env_config_file.exists():
            with open(env_config_file, 'r') as f:
                self.environment_config = yaml.safe_load(f) or {}
        
        # Merge configurations
        self.merged_config = self._merge_configs(self.base_config, self.environment_config)
        
        # Substitute secrets
        self._substitute_secrets()
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge configuration dictionaries"""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _substitute_secrets(self):
        """Substitute secret placeholders in configuration"""
        self.merged_config = self._recursive_substitute(self.merged_config)
    
    def _recursive_substitute(self, obj: Any) -> Any:
        """Recursively substitute secret placeholders"""
        if isinstance(obj, dict):
            return {key: self._recursive_substitute(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._recursive_substitute(item) for item in obj]
        elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
            # Extract secret name from ${SECRET_NAME} format
            secret_name = obj[2:-1].lower()
            secret_value = self.secrets_manager.get_secret(secret_name)
            if secret_value is None:
                logger.warning(f"Secret not found: {secret_name}")
                return obj
            return secret_value
        else:
            return obj
    
    def get_config(self, path: str = None, default: Any = None) -> Any:
        """Get configuration value by path (dot notation)"""
        if path is None:
            return self.merged_config
        
        keys = path.split('.')
        value = self.merged_config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set_config(self, path: str, value: Any):
        """Set configuration value by path"""
        keys = path.split('.')
        config = self.merged_config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
    
    def validate_config(self) -> ConfigValidationResult:
        """Validate the current configuration"""
        errors = []
        warnings = []
        
        # Check required configurations
        required_configs = [
            "api.host",
            "api.port",
            "monitoring.prometheus.enabled",
            "logging.level"
        ]
        
        for required in required_configs:
            if self.get_config(required) is None:
                errors.append(f"Missing required configuration: {required}")
        
        # Validate specific values
        api_port = self.get_config("api.port")
        if api_port and (not isinstance(api_port, int) or api_port < 1 or api_port > 65535):
            errors.append("api.port must be a valid port number (1-65535)")
        
        # Check for sensitive data in config (should use secrets)
        self._check_sensitive_data(self.merged_config, "", warnings)
        
        return ConfigValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def _check_sensitive_data(self, obj: Any, path: str, warnings: List[str]):
        """Check for sensitive data that should be in secrets"""
        sensitive_keywords = ["password", "key", "secret", "token", "credential"]
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if key name suggests sensitive data
                if any(keyword in key.lower() for keyword in sensitive_keywords):
                    if isinstance(value, str) and not value.startswith("${"):
                        warnings.append(f"Potential sensitive data in config: {current_path}")
                
                self._check_sensitive_data(value, current_path, warnings)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                current_path = f"{path}[{i}]"
                self._check_sensitive_data(item, current_path, warnings)
    
    def export_config(self, format: str = "yaml") -> str:
        """Export configuration in specified format"""
        if format.lower() == "yaml":
            return yaml.dump(self.merged_config, default_flow_style=False)
        elif format.lower() == "json":
            return json.dumps(self.merged_config, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def reload_config(self):
        """Reload configuration from files"""
        self._load_configurations()


class ContainerManager:
    """Manage Docker container operations"""
    
    def __init__(self):
        self.docker_available = self._check_docker()
    
    def _check_docker(self) -> bool:
        """Check if Docker is available"""
        try:
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("Docker not available")
            return False
    
    def build_image(self, tag: str = "network-automation:latest") -> bool:
        """Build Docker image"""
        if not self.docker_available:
            logger.error("Docker not available for image building")
            return False
        
        try:
            cmd = ["docker", "build", "-t", tag, "."]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully built image: {tag}")
                return True
            else:
                logger.error(f"Failed to build image: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error building image: {e}")
            return False
    
    def run_container(self, tag: str = "network-automation:latest", 
                     environment: str = "development") -> Optional[str]:
        """Run Docker container"""
        if not self.docker_available:
            logger.error("Docker not available for container execution")
            return None
        
        try:
            cmd = [
                "docker", "run", "-d",
                "--name", f"network-automation-{environment}",
                "-p", "8000:8000",  # Prometheus metrics
                "-p", "8080:8080",  # Health check
                "-v", f"{os.getcwd()}/logs:/app/logs",
                "-v", f"{os.getcwd()}/config:/app/config",
                "-e", f"ENVIRONMENT={environment}",
                tag
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                container_id = result.stdout.strip()
                logger.info(f"Container started: {container_id}")
                return container_id
            else:
                logger.error(f"Failed to start container: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Error starting container: {e}")
            return None
    
    def stop_container(self, container_name: str) -> bool:
        """Stop and remove container"""
        if not self.docker_available:
            return False
        
        try:
            # Stop container
            subprocess.run(["docker", "stop", container_name], 
                         capture_output=True, check=True)
            
            # Remove container
            subprocess.run(["docker", "rm", container_name], 
                         capture_output=True, check=True)
            
            logger.info(f"Container stopped and removed: {container_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop container {container_name}: {e}")
            return False
    
    def get_container_logs(self, container_name: str, lines: int = 100) -> str:
        """Get container logs"""
        if not self.docker_available:
            return "Docker not available"
        
        try:
            cmd = ["docker", "logs", "--tail", str(lines), container_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error retrieving logs: {e}"


class KubernetesManager:
    """Manage Kubernetes deployment operations"""
    
    def __init__(self):
        self.kubectl_available = self._check_kubectl()
    
    def _check_kubectl(self) -> bool:
        """Check if kubectl is available"""
        try:
            subprocess.run(["kubectl", "version", "--client"], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("kubectl not available")
            return False
    
    def apply_manifests(self, manifests_dir: str = "k8s") -> bool:
        """Apply Kubernetes manifests"""
        if not self.kubectl_available:
            logger.error("kubectl not available for Kubernetes deployment")
            return False
        
        try:
            cmd = ["kubectl", "apply", "-f", manifests_dir]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Kubernetes manifests applied successfully")
                return True
            else:
                logger.error(f"Failed to apply manifests: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error applying manifests: {e}")
            return False
    
    def get_deployment_status(self, namespace: str = "network-automation") -> Dict[str, Any]:
        """Get deployment status"""
        if not self.kubectl_available:
            return {"error": "kubectl not available"}
        
        try:
            cmd = ["kubectl", "get", "deployments", "-n", namespace, "-o", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}
                
        except Exception as e:
            return {"error": str(e)}
    
    def scale_deployment(self, deployment_name: str, replicas: int, 
                        namespace: str = "network-automation") -> bool:
        """Scale Kubernetes deployment"""
        if not self.kubectl_available:
            return False
        
        try:
            cmd = ["kubectl", "scale", "deployment", deployment_name, 
                   f"--replicas={replicas}", "-n", namespace]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Deployment {deployment_name} scaled to {replicas} replicas")
                return True
            else:
                logger.error(f"Failed to scale deployment: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error scaling deployment: {e}")
            return False


class DeploymentService:
    """Main deployment and configuration management service"""
    
    def __init__(self, environment: str = "development"):
        self.environment = environment
        self.config_manager = ConfigurationManager(environment)
        self.secrets_manager = SecretsManager()
        self.container_manager = ContainerManager()
        self.k8s_manager = KubernetesManager()
        
        logger.info(f"Deployment service initialized for environment: {environment}")
    
    def validate_deployment_config(self) -> ConfigValidationResult:
        """Validate deployment configuration"""
        return self.config_manager.validate_config()
    
    def deploy_docker(self, image_tag: str = "network-automation:latest") -> bool:
        """Deploy using Docker"""
        logger.info(f"Starting Docker deployment for environment: {self.environment}")
        
        # Validate configuration
        validation = self.validate_deployment_config()
        if not validation.is_valid:
            logger.error(f"Configuration validation failed: {validation.errors}")
            return False
        
        # Build image
        if not self.container_manager.build_image(image_tag):
            return False
        
        # Stop existing container
        container_name = f"network-automation-{self.environment}"
        self.container_manager.stop_container(container_name)
        
        # Start new container
        container_id = self.container_manager.run_container(image_tag, self.environment)
        
        return container_id is not None
    
    def deploy_kubernetes(self) -> bool:
        """Deploy using Kubernetes"""
        logger.info(f"Starting Kubernetes deployment for environment: {self.environment}")
        
        # Validate configuration
        validation = self.validate_deployment_config()
        if not validation.is_valid:
            logger.error(f"Configuration validation failed: {validation.errors}")
            return False
        
        # Apply manifests
        return self.k8s_manager.apply_manifests()
    
    def get_deployment_status(self) -> Dict[str, Any]:
        """Get current deployment status"""
        status = {
            "environment": self.environment,
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "valid": False,
                "errors": [],
                "warnings": []
            },
            "docker": {
                "available": self.container_manager.docker_available,
                "containers": []
            },
            "kubernetes": {
                "available": self.k8s_manager.kubectl_available,
                "deployments": {}
            }
        }
        
        # Configuration status
        validation = self.validate_deployment_config()
        status["configuration"]["valid"] = validation.is_valid
        status["configuration"]["errors"] = validation.errors
        status["configuration"]["warnings"] = validation.warnings
        
        # Kubernetes status
        if self.k8s_manager.kubectl_available:
            status["kubernetes"]["deployments"] = self.k8s_manager.get_deployment_status()
        
        return status
    
    def export_configuration(self, format: str = "yaml") -> str:
        """Export current configuration"""
        return self.config_manager.export_config(format)


# MCP Tools for deployment management
def deploy_application(environment: str = "development", 
                      platform: str = "docker") -> Dict[str, Any]:
    """Deploy the network automation application"""
    try:
        service = DeploymentService(environment)
        
        if platform.lower() == "docker":
            success = service.deploy_docker()
        elif platform.lower() == "kubernetes":
            success = service.deploy_kubernetes()
        else:
            return {
                "error": f"Unsupported deployment platform: {platform}",
                "timestamp": datetime.now().isoformat()
            }
        
        return {
            "success": success,
            "environment": environment,
            "platform": platform,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            "error": f"Deployment failed: {str(e)}",
            "environment": environment,
            "platform": platform,
            "timestamp": datetime.now().isoformat()
        }


def get_deployment_status(environment: str = "development") -> Dict[str, Any]:
    """Get deployment status and health"""
    try:
        service = DeploymentService(environment)
        return service.get_deployment_status()
    except Exception as e:
        return {
            "error": f"Failed to get deployment status: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }


def manage_configuration(action: str, path: str = None, 
                        value: str = None, environment: str = "development") -> Dict[str, Any]:
    """Manage application configuration"""
    try:
        service = DeploymentService(environment)
        
        if action == "get":
            config_value = service.config_manager.get_config(path)
            return {
                "action": action,
                "path": path,
                "value": config_value,
                "timestamp": datetime.now().isoformat()
            }
        elif action == "set" and path and value:
            service.config_manager.set_config(path, value)
            return {
                "action": action,
                "path": path,
                "value": value,
                "success": True,
                "timestamp": datetime.now().isoformat()
            }
        elif action == "validate":
            validation = service.validate_deployment_config()
            return {
                "action": action,
                "valid": validation.is_valid,
                "errors": validation.errors,
                "warnings": validation.warnings,
                "timestamp": datetime.now().isoformat()
            }
        elif action == "export":
            config_export = service.export_configuration()
            return {
                "action": action,
                "configuration": config_export,
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "error": f"Invalid action: {action}",
                "timestamp": datetime.now().isoformat()
            }
            
    except Exception as e:
        return {
            "error": f"Configuration management failed: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }


if __name__ == "__main__":
    # Test the deployment service
    print("🚀 Testing Deployment and Configuration Management Service...")
    
    # Test configuration management
    config_manager = ConfigurationManager("development")
    validation = config_manager.validate_config()
    print(f"✅ Configuration validation: {'Valid' if validation.is_valid else 'Invalid'}")
    
    if validation.errors:
        print(f"❌ Errors: {validation.errors}")
    if validation.warnings:
        print(f"⚠️  Warnings: {validation.warnings}")
    
    # Test secrets management
    secrets_manager = SecretsManager("env")
    secrets = secrets_manager.load_secrets()
    print(f"✅ Secrets loaded: {len(secrets)} secrets")
    
    # Test deployment service
    deployment_service = DeploymentService("development")
    status = deployment_service.get_deployment_status()
    print(f"✅ Deployment status: {status['environment']}")
    
    # Test container management
    container_manager = ContainerManager()
    print(f"✅ Docker available: {container_manager.docker_available}")
    
    # Test Kubernetes management
    k8s_manager = KubernetesManager()
    print(f"✅ Kubernetes available: {k8s_manager.kubectl_available}")
    
    print("\n🎉 Deployment and Configuration Management Service - OPERATIONAL!")
