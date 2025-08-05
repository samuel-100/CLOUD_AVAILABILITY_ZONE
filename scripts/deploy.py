#!/usr/bin/env python3
"""
Deployment Automation Script

Automates the deployment process for different environments,
including building, testing, and deploying the network automation system.
"""

import os
import sys
import time
import subprocess
import yaml
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import argparse

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.deployment_service import DeploymentService
from scripts.test_deployment import run_deployment_tests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DeploymentAutomation:
    """Automate deployment processes"""
    
    def __init__(self, environment: str = "development"):
        self.environment = environment
        self.deployment_service = DeploymentService(environment)
        self.deployment_log = []
        
    def log_step(self, step: str, status: str, message: str, details: Dict[str, Any] = None):
        """Log deployment step"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "step": step,
            "status": status,
            "message": message,
            "details": details or {}
        }
        self.deployment_log.append(log_entry)
        
        status_emoji = {"SUCCESS": "✅", "FAILED": "❌", "INFO": "ℹ️", "WARNING": "⚠️"}
        emoji = status_emoji.get(status, "📝")
        logger.info(f"{emoji} {step}: {message}")
    
    def deploy_docker(self, build_image: bool = True, run_tests: bool = True) -> bool:
        """Deploy using Docker with full automation"""
        self.log_step("Docker Deployment", "INFO", f"Starting Docker deployment for {self.environment}")
        
        try:
            # Step 1: Validate configuration
            if not self._validate_configuration():
                return False
            
            # Step 2: Run pre-deployment tests
            if run_tests and not self._run_pre_deployment_tests():
                return False
            
            # Step 3: Build Docker image
            if build_image and not self._build_docker_image():
                return False
            
            # Step 4: Deploy container
            if not self._deploy_docker_container():
                return False
            
            # Step 5: Run post-deployment tests
            if run_tests and not self._run_post_deployment_tests():
                return False
            
            self.log_step("Docker Deployment", "SUCCESS", "Docker deployment completed successfully")
            return True
            
        except Exception as e:
            self.log_step("Docker Deployment", "FAILED", f"Docker deployment failed: {str(e)}")
            return False
    
    def deploy_kubernetes(self, build_image: bool = True, run_tests: bool = True) -> bool:
        """Deploy using Kubernetes with full automation"""
        self.log_step("Kubernetes Deployment", "INFO", f"Starting Kubernetes deployment for {self.environment}")
        
        try:
            # Step 1: Validate configuration
            if not self._validate_configuration():
                return False
            
            # Step 2: Run pre-deployment tests
            if run_tests and not self._run_pre_deployment_tests():
                return False
            
            # Step 3: Build and push Docker image (if required)
            if build_image and not self._build_and_push_image():
                return False
            
            # Step 4: Apply Kubernetes manifests
            if not self._apply_kubernetes_manifests():
                return False
            
            # Step 5: Wait for deployment to be ready
            if not self._wait_for_kubernetes_deployment():
                return False
            
            # Step 6: Run post-deployment tests
            if run_tests and not self._run_post_deployment_tests():
                return False
            
            self.log_step("Kubernetes Deployment", "SUCCESS", "Kubernetes deployment completed successfully")
            return True
            
        except Exception as e:
            self.log_step("Kubernetes Deployment", "FAILED", f"Kubernetes deployment failed: {str(e)}")
            return False
    
    def _validate_configuration(self) -> bool:
        """Validate deployment configuration"""
        self.log_step("Configuration Validation", "INFO", "Validating deployment configuration")
        
        try:
            validation = self.deployment_service.validate_deployment_config()
            
            if validation.is_valid:
                self.log_step("Configuration Validation", "SUCCESS", "Configuration is valid")
                if validation.warnings:
                    for warning in validation.warnings:
                        self.log_step("Configuration Validation", "WARNING", f"Warning: {warning}")
                return True
            else:
                for error in validation.errors:
                    self.log_step("Configuration Validation", "FAILED", f"Error: {error}")
                return False
                
        except Exception as e:
            self.log_step("Configuration Validation", "FAILED", f"Validation error: {str(e)}")
            return False
    
    def _run_pre_deployment_tests(self) -> bool:
        """Run pre-deployment tests"""
        self.log_step("Pre-deployment Tests", "INFO", "Running pre-deployment tests")
        
        try:
            test_results = run_deployment_tests(self.environment)
            
            if test_results["summary"]["failed"] == 0:
                self.log_step("Pre-deployment Tests", "SUCCESS", 
                            f"All tests passed ({test_results['summary']['passed']}/{test_results['summary']['total']})")
                return True
            else:
                self.log_step("Pre-deployment Tests", "FAILED", 
                            f"Tests failed ({test_results['summary']['failed']}/{test_results['summary']['total']})")
                return False
                
        except Exception as e:
            self.log_step("Pre-deployment Tests", "FAILED", f"Test execution error: {str(e)}")
            return False
    
    def _build_docker_image(self, tag: str = None) -> bool:
        """Build Docker image"""
        if tag is None:
            tag = f"network-automation:{self.environment}"
        
        self.log_step("Docker Build", "INFO", f"Building Docker image: {tag}")
        
        try:
            success = self.deployment_service.container_manager.build_image(tag)
            
            if success:
                self.log_step("Docker Build", "SUCCESS", f"Image built successfully: {tag}")
                return True
            else:
                self.log_step("Docker Build", "FAILED", "Failed to build Docker image")
                return False
                
        except Exception as e:
            self.log_step("Docker Build", "FAILED", f"Build error: {str(e)}")
            return False
    
    def _deploy_docker_container(self, tag: str = None) -> bool:
        """Deploy Docker container"""
        if tag is None:
            tag = f"network-automation:{self.environment}"
        
        self.log_step("Container Deployment", "INFO", f"Deploying container: {tag}")
        
        try:
            container_id = self.deployment_service.container_manager.run_container(tag, self.environment)
            
            if container_id:
                self.log_step("Container Deployment", "SUCCESS", 
                            f"Container deployed: {container_id[:12]}")
                return True
            else:
                self.log_step("Container Deployment", "FAILED", "Failed to deploy container")
                return False
                
        except Exception as e:
            self.log_step("Container Deployment", "FAILED", f"Deployment error: {str(e)}")
            return False
    
    def _build_and_push_image(self, registry: str = None) -> bool:
        """Build and push Docker image to registry"""
        tag = f"network-automation:{self.environment}"
        
        # Build image
        if not self._build_docker_image(tag):
            return False
        
        # Push to registry if specified
        if registry:
            self.log_step("Image Push", "INFO", f"Pushing image to registry: {registry}")
            
            try:
                # Tag for registry
                registry_tag = f"{registry}/network-automation:{self.environment}"
                subprocess.run(["docker", "tag", tag, registry_tag], check=True)
                
                # Push to registry
                subprocess.run(["docker", "push", registry_tag], check=True)
                
                self.log_step("Image Push", "SUCCESS", f"Image pushed: {registry_tag}")
                return True
                
            except subprocess.CalledProcessError as e:
                self.log_step("Image Push", "FAILED", f"Push failed: {str(e)}")
                return False
        
        return True
    
    def _apply_kubernetes_manifests(self) -> bool:
        """Apply Kubernetes manifests"""
        self.log_step("Kubernetes Apply", "INFO", "Applying Kubernetes manifests")
        
        try:
            success = self.deployment_service.k8s_manager.apply_manifests()
            
            if success:
                self.log_step("Kubernetes Apply", "SUCCESS", "Manifests applied successfully")
                return True
            else:
                self.log_step("Kubernetes Apply", "FAILED", "Failed to apply manifests")
                return False
                
        except Exception as e:
            self.log_step("Kubernetes Apply", "FAILED", f"Apply error: {str(e)}")
            return False
    
    def _wait_for_kubernetes_deployment(self, timeout: int = 300) -> bool:
        """Wait for Kubernetes deployment to be ready"""
        self.log_step("Deployment Readiness", "INFO", "Waiting for deployment to be ready")
        
        try:
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                status = self.deployment_service.k8s_manager.get_deployment_status()
                
                if "items" in status and len(status["items"]) > 0:
                    deployment = status["items"][0]
                    ready_replicas = deployment.get("status", {}).get("readyReplicas", 0)
                    desired_replicas = deployment.get("spec", {}).get("replicas", 1)
                    
                    if ready_replicas >= desired_replicas:
                        self.log_step("Deployment Readiness", "SUCCESS", 
                                    f"Deployment ready: {ready_replicas}/{desired_replicas} replicas")
                        return True
                
                time.sleep(10)  # Wait 10 seconds before checking again
            
            self.log_step("Deployment Readiness", "FAILED", f"Timeout waiting for deployment (>{timeout}s)")
            return False
            
        except Exception as e:
            self.log_step("Deployment Readiness", "FAILED", f"Readiness check error: {str(e)}")
            return False
    
    def _run_post_deployment_tests(self) -> bool:
        """Run post-deployment tests"""
        self.log_step("Post-deployment Tests", "INFO", "Running post-deployment tests")
        
        try:
            # Wait a bit for services to stabilize
            time.sleep(10)
            
            test_results = run_deployment_tests(self.environment)
            
            if test_results["summary"]["failed"] == 0:
                self.log_step("Post-deployment Tests", "SUCCESS", 
                            f"All tests passed ({test_results['summary']['passed']}/{test_results['summary']['total']})")
                return True
            else:
                self.log_step("Post-deployment Tests", "FAILED", 
                            f"Tests failed ({test_results['summary']['failed']}/{test_results['summary']['total']})")
                return False
                
        except Exception as e:
            self.log_step("Post-deployment Tests", "FAILED", f"Test execution error: {str(e)}")
            return False
    
    def rollback_deployment(self, platform: str = "docker") -> bool:
        """Rollback deployment"""
        self.log_step("Rollback", "INFO", f"Starting rollback for {platform} deployment")
        
        try:
            if platform.lower() == "docker":
                # Stop current container
                container_name = f"network-automation-{self.environment}"
                success = self.deployment_service.container_manager.stop_container(container_name)
                
                if success:
                    self.log_step("Rollback", "SUCCESS", "Docker container stopped")
                    return True
                else:
                    self.log_step("Rollback", "FAILED", "Failed to stop Docker container")
                    return False
                    
            elif platform.lower() == "kubernetes":
                # Scale down deployment
                success = self.deployment_service.k8s_manager.scale_deployment(
                    "network-automation", 0)
                
                if success:
                    self.log_step("Rollback", "SUCCESS", "Kubernetes deployment scaled down")
                    return True
                else:
                    self.log_step("Rollback", "FAILED", "Failed to scale down Kubernetes deployment")
                    return False
            
            else:
                self.log_step("Rollback", "FAILED", f"Unsupported platform: {platform}")
                return False
                
        except Exception as e:
            self.log_step("Rollback", "FAILED", f"Rollback error: {str(e)}")
            return False
    
    def get_deployment_status(self) -> Dict[str, Any]:
        """Get comprehensive deployment status"""
        return self.deployment_service.get_deployment_status()
    
    def export_deployment_log(self, filename: str = None) -> str:
        """Export deployment log"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"deployment_log_{self.environment}_{timestamp}.json"
        
        log_data = {
            "environment": self.environment,
            "deployment_timestamp": datetime.now().isoformat(),
            "steps": self.deployment_log
        }
        
        with open(filename, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        return filename


def main():
    """Main deployment automation function"""
    parser = argparse.ArgumentParser(description="Automate deployment process")
    parser.add_argument("--environment", "-e", default="development",
                       choices=["development", "testing", "production"],
                       help="Target environment")
    parser.add_argument("--platform", "-p", default="docker",
                       choices=["docker", "kubernetes"],
                       help="Deployment platform")
    parser.add_argument("--no-build", action="store_true",
                       help="Skip image building")
    parser.add_argument("--no-tests", action="store_true",
                       help="Skip tests")
    parser.add_argument("--rollback", action="store_true",
                       help="Rollback deployment")
    parser.add_argument("--status", action="store_true",
                       help="Get deployment status")
    parser.add_argument("--registry", help="Docker registry for image push")
    
    args = parser.parse_args()
    
    # Initialize deployment automation
    deployment_automation = DeploymentAutomation(args.environment)
    
    try:
        if args.status:
            # Get deployment status
            print("🔍 Getting Deployment Status...")
            status = deployment_automation.get_deployment_status()
            print(json.dumps(status, indent=2))
            return
        
        if args.rollback:
            # Rollback deployment
            print(f"🔄 Rolling back {args.platform} deployment...")
            success = deployment_automation.rollback_deployment(args.platform)
            
            if success:
                print("✅ Rollback completed successfully")
            else:
                print("❌ Rollback failed")
                sys.exit(1)
            return
        
        # Deploy application
        print(f"🚀 Starting {args.platform} deployment for {args.environment}...")
        print("=" * 60)
        
        if args.platform == "docker":
            success = deployment_automation.deploy_docker(
                build_image=not args.no_build,
                run_tests=not args.no_tests
            )
        elif args.platform == "kubernetes":
            success = deployment_automation.deploy_kubernetes(
                build_image=not args.no_build,
                run_tests=not args.no_tests
            )
        else:
            print(f"❌ Unsupported platform: {args.platform}")
            sys.exit(1)
        
        # Export deployment log
        log_file = deployment_automation.export_deployment_log()
        print(f"\n📋 Deployment log saved to: {log_file}")
        
        if success:
            print(f"\n🎉 Deployment completed successfully!")
            print(f"   Environment: {args.environment}")
            print(f"   Platform: {args.platform}")
            
            # Show final status
            status = deployment_automation.get_deployment_status()
            print(f"   Configuration Valid: {status['configuration']['valid']}")
            print(f"   Docker Available: {status['docker']['available']}")
            print(f"   Kubernetes Available: {status['kubernetes']['available']}")
            
        else:
            print(f"\n❌ Deployment failed!")
            print(f"   Check the deployment log for details: {log_file}")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n🛑 Deployment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Deployment error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
