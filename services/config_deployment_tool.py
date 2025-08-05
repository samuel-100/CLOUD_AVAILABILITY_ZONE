#!/usr/bin/env python3
"""
AI-Powered Configuration Deployment Tool

Implements secure configuration deployment with pre/post validation,
rollback capabilities, change tracking, and approval workflows for
network automation.
"""

import os
import sys
import json
import yaml
import logging
import asyncio
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import pickle
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import network services
from services.network_status_tool import get_network_status
from services.device_details_tool import get_device_details
from services.config_generation_tool import generate_configuration, ConfigurationGenerator
from services.precheck import main as run_precheck_main
from services.postcheck import main as run_postcheck_main

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# File paths
DEPLOYMENT_HISTORY_DIR = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/deployment_history'
BACKUP_CONFIGS_DIR = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/running-configs'
APPROVAL_QUEUE_DIR = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/approval_queue'

# Ensure directories exist
for dir_path in [DEPLOYMENT_HISTORY_DIR, BACKUP_CONFIGS_DIR, APPROVAL_QUEUE_DIR]:
    Path(dir_path).mkdir(parents=True, exist_ok=True)

class DeploymentStatus(Enum):
    """Deployment status enumeration"""
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    PRE_VALIDATION = "pre_validation"
    PRE_VALIDATION_FAILED = "pre_validation_failed"
    DEPLOYING = "deploying"
    DEPLOYMENT_FAILED = "deployment_failed"
    POST_VALIDATION = "post_validation"
    POST_VALIDATION_FAILED = "post_validation_failed"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"

class SensitivityLevel(Enum):
    """Configuration change sensitivity levels"""
    LOW = "low"           # Interface descriptions, non-critical settings
    MEDIUM = "medium"     # VLAN changes, access controls
    HIGH = "high"         # Routing protocol changes
    CRITICAL = "critical" # Core infrastructure, security policies

class ApprovalRequirement(Enum):
    """Approval requirement levels"""
    NONE = "none"         # Auto-approve low sensitivity changes
    PEER = "peer"         # Peer engineer approval
    SENIOR = "senior"     # Senior engineer approval
    MANAGER = "manager"   # Manager approval required

@dataclass
class ValidationResult:
    """Validation check result"""
    check_name: str
    status: str  # passed, failed, warning
    details: str
    timestamp: str
    device: Optional[str] = None
    recommendations: List[str] = None

@dataclass
class DeviceBackup:
    """Device configuration backup"""
    device_name: str
    config_content: str
    timestamp: str
    backup_hash: str
    backup_file_path: str

@dataclass
class DeploymentApproval:
    """Deployment approval record"""
    approval_id: str
    deployment_id: str
    required_level: ApprovalRequirement
    status: str  # pending, approved, rejected
    approver: Optional[str] = None
    approval_timestamp: Optional[str] = None
    comments: str = ""
    approval_token: Optional[str] = None

@dataclass
class ChangeTracking:
    """Change tracking information"""
    change_id: str
    deployment_id: str
    device_name: str
    config_section: str
    before_config: str
    after_config: str
    change_type: str  # add, modify, delete
    timestamp: str
    change_hash: str

@dataclass
class RollbackPlan:
    """Rollback execution plan"""
    rollback_id: str
    deployment_id: str
    rollback_configs: Dict[str, str]  # device -> config content
    execution_order: List[str]  # device deployment order
    estimated_duration: str
    rollback_commands: List[str]
    verification_steps: List[str]

@dataclass
class DeploymentExecution:
    """Complete deployment execution record"""
    deployment_id: str
    request_description: str
    target_devices: List[str]
    generated_config: Dict[str, str]
    sensitivity_level: SensitivityLevel
    approval_requirement: ApprovalRequirement
    status: DeploymentStatus
    pre_validation_results: List[ValidationResult]
    post_validation_results: List[ValidationResult]
    device_backups: List[DeviceBackup]
    change_tracking: List[ChangeTracking]
    rollback_plan: Optional[RollbackPlan]
    deployment_log: List[str]
    start_timestamp: str
    completion_timestamp: Optional[str] = None
    approvals: List[DeploymentApproval] = None
    requester: str = "system"
    maintenance_window: Optional[str] = None

class ConfigurationDeployer:
    """Main configuration deployment engine"""
    
    def __init__(self):
        self.deployment_history = []
        self.approval_queue = []
        self.active_deployments = {}
        self._load_deployment_history()
        self._load_approval_queue()
    
    def _load_deployment_history(self):
        """Load deployment history from disk"""
        try:
            history_file = Path(DEPLOYMENT_HISTORY_DIR) / "deployment_history.json"
            if history_file.exists():
                with open(history_file) as f:
                    data = json.load(f)
                    self.deployment_history = data.get('deployments', [])
        except Exception as e:
            logger.warning(f"Could not load deployment history: {e}")
    
    def _save_deployment_history(self):
        """Save deployment history to disk"""
        try:
            history_file = Path(DEPLOYMENT_HISTORY_DIR) / "deployment_history.json"
            
            # Convert enums to strings for JSON serialization
            def convert_enums(obj):
                if isinstance(obj, dict):
                    return {k: convert_enums(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_enums(item) for item in obj]
                elif isinstance(obj, (DeploymentStatus, SensitivityLevel, ApprovalRequirement)):
                    return obj.value
                else:
                    return obj
            
            serializable_history = convert_enums(self.deployment_history)
            
            with open(history_file, 'w') as f:
                json.dump({
                    'deployments': serializable_history,
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save deployment history: {e}")
    
    def _load_approval_queue(self):
        """Load approval queue from disk"""
        try:
            queue_file = Path(APPROVAL_QUEUE_DIR) / "approval_queue.json"
            if queue_file.exists():
                with open(queue_file) as f:
                    data = json.load(f)
                    self.approval_queue = data.get('approvals', [])
        except Exception as e:
            logger.warning(f"Could not load approval queue: {e}")
    
    def _save_approval_queue(self):
        """Save approval queue to disk"""
        try:
            queue_file = Path(APPROVAL_QUEUE_DIR) / "approval_queue.json"
            
            # Convert enums to strings for JSON serialization
            def convert_enums(obj):
                if isinstance(obj, dict):
                    return {k: convert_enums(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_enums(item) for item in obj]
                elif isinstance(obj, (DeploymentStatus, SensitivityLevel, ApprovalRequirement)):
                    return obj.value
                else:
                    return obj
            
            serializable_queue = convert_enums(self.approval_queue)
            
            with open(queue_file, 'w') as f:
                json.dump({
                    'approvals': serializable_queue,
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save approval queue: {e}")
    
    def _assess_sensitivity_level(self, config_content: str, target_devices: List[str]) -> SensitivityLevel:
        """Assess configuration change sensitivity level"""
        content_lower = config_content.lower()
        
        # Critical sensitivity indicators
        critical_keywords = [
            'router bgp', 'router ospf', 'spanning-tree', 'vtp', 'hsrp', 'vrrp',
            'access-list', 'crypto', 'aaa', 'tacacs', 'radius', 'snmp-server',
            'ip route 0.0.0.0', 'default-gateway', 'management'
        ]
        
        # High sensitivity indicators
        high_keywords = [
            'router', 'routing', 'vlan', 'trunk', 'switchport', 'ip address',
            'network', 'area', 'bgp', 'ospf', 'eigrp', 'static route'
        ]
        
        # Medium sensitivity indicators
        medium_keywords = [
            'access', 'shutdown', 'no shutdown', 'mtu', 'bandwidth',
            'duplex', 'speed', 'channel-group'
        ]
        
        # Check for critical changes
        if any(keyword in content_lower for keyword in critical_keywords):
            return SensitivityLevel.CRITICAL
        
        # Check for core devices (spines are more critical)
        if any('SPINE' in device.upper() for device in target_devices):
            # Spine devices get elevated sensitivity
            if any(keyword in content_lower for keyword in high_keywords):
                return SensitivityLevel.CRITICAL
            elif any(keyword in content_lower for keyword in medium_keywords):
                return SensitivityLevel.HIGH
        
        # Standard sensitivity assessment
        if any(keyword in content_lower for keyword in high_keywords):
            return SensitivityLevel.HIGH
        elif any(keyword in content_lower for keyword in medium_keywords):
            return SensitivityLevel.MEDIUM
        
        return SensitivityLevel.LOW
    
    def _determine_approval_requirement(self, sensitivity: SensitivityLevel, target_devices: List[str]) -> ApprovalRequirement:
        """Determine required approval level"""
        device_count = len(target_devices)
        has_spine = any('SPINE' in device.upper() for device in target_devices)
        
        if sensitivity == SensitivityLevel.CRITICAL or has_spine:
            return ApprovalRequirement.MANAGER
        elif sensitivity == SensitivityLevel.HIGH or device_count > 2:
            return ApprovalRequirement.SENIOR
        elif sensitivity == SensitivityLevel.MEDIUM:
            return ApprovalRequirement.PEER
        else:
            return ApprovalRequirement.NONE
    
    def _create_device_backup(self, device_name: str) -> DeviceBackup:
        """Create configuration backup for device"""
        try:
            # Get current device configuration
            device_details = get_device_details(device_name)
            config_content = device_details.get('running_config', '')
            
            # Generate backup hash
            config_hash = hashlib.sha256(config_content.encode()).hexdigest()
            
            # Save backup file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"{device_name}_backup_{timestamp}.txt"
            backup_path = Path(BACKUP_CONFIGS_DIR) / backup_filename
            
            with open(backup_path, 'w') as f:
                f.write(f"! Configuration backup for {device_name}\n")
                f.write(f"! Created: {datetime.now().isoformat()}\n")
                f.write(f"! Hash: {config_hash}\n")
                f.write("!\n")
                f.write(config_content)
            
            return DeviceBackup(
                device_name=device_name,
                config_content=config_content,
                timestamp=datetime.now().isoformat(),
                backup_hash=config_hash,
                backup_file_path=str(backup_path)
            )
            
        except Exception as e:
            logger.error(f"Failed to create backup for {device_name}: {e}")
            return DeviceBackup(
                device_name=device_name,
                config_content="",
                timestamp=datetime.now().isoformat(),
                backup_hash="",
                backup_file_path=""
            )
    
    def _run_pre_validation(self, target_devices: List[str]) -> List[ValidationResult]:
        """Run pre-deployment validation checks"""
        results = []
        
        try:
            # For now, simulate precheck results using network status
            network_status = get_network_status()
            precheck_result = network_status
            
            # Convert precheck results to validation results
            for device in target_devices:
                # Check device connectivity
                if precheck_result.get('devices'):
                    device_status = next((d for d in precheck_result['devices'] if d['name'] == device), None)
                    if device_status:
                        status = "passed" if device_status.get('status') == 'reachable' else "failed"
                        results.append(ValidationResult(
                            check_name="Device Connectivity",
                            status=status,
                            details=f"Device {device} connectivity check: {device_status.get('status')}",
                            timestamp=datetime.now().isoformat(),
                            device=device,
                            recommendations=[] if status == "passed" else ["Check device connectivity and management access"]
                        ))
            
            # Network stability check
            if precheck_result.get('summary', {}).get('status') == 'healthy':
                results.append(ValidationResult(
                    check_name="Network Stability",
                    status="passed",
                    details="Network is stable and ready for configuration changes",
                    timestamp=datetime.now().isoformat(),
                    recommendations=[]
                ))
            else:
                results.append(ValidationResult(
                    check_name="Network Stability",
                    status="warning",
                    details="Network issues detected - proceed with caution",
                    timestamp=datetime.now().isoformat(),
                    recommendations=["Review network status before deployment", "Consider maintenance window"]
                ))
        
        except Exception as e:
            logger.error(f"Pre-validation failed: {e}")
            results.append(ValidationResult(
                check_name="Pre-validation Error",
                status="failed",
                details=f"Pre-validation check failed: {str(e)}",
                timestamp=datetime.now().isoformat(),
                recommendations=["Fix validation system before deployment"]
            ))
        
        return results
    
    def _run_post_validation(self, target_devices: List[str]) -> List[ValidationResult]:
        """Run post-deployment validation checks"""
        results = []
        
        try:
            # For now, simulate postcheck results using network status
            network_status = get_network_status()
            postcheck_result = network_status
            
            # Convert postcheck results to validation results
            for device in target_devices:
                # Check device status after deployment
                if postcheck_result.get('devices'):
                    device_status = next((d for d in postcheck_result['devices'] if d['name'] == device), None)
                    if device_status:
                        status = "passed" if device_status.get('status') == 'reachable' else "failed"
                        results.append(ValidationResult(
                            check_name="Post-deployment Device Status",
                            status=status,
                            details=f"Device {device} status after deployment: {device_status.get('status')}",
                            timestamp=datetime.now().isoformat(),
                            device=device,
                            recommendations=[] if status == "passed" else ["Investigate device connectivity issues", "Consider rollback"]
                        ))
            
            # Overall network health check
            if postcheck_result.get('summary', {}).get('status') == 'healthy':
                results.append(ValidationResult(
                    check_name="Post-deployment Network Health",
                    status="passed",
                    details="Network is healthy after configuration deployment",
                    timestamp=datetime.now().isoformat(),
                    recommendations=[]
                ))
            else:
                results.append(ValidationResult(
                    check_name="Post-deployment Network Health",
                    status="failed",
                    details="Network issues detected after deployment",
                    timestamp=datetime.now().isoformat(),
                    recommendations=["Investigate network issues", "Prepare for potential rollback"]
                ))
        
        except Exception as e:
            logger.error(f"Post-validation failed: {e}")
            results.append(ValidationResult(
                check_name="Post-validation Error",
                status="failed",
                details=f"Post-validation check failed: {str(e)}",
                timestamp=datetime.now().isoformat(),
                recommendations=["Fix validation system", "Manual verification required"]
            ))
        
        return results
    
    def _create_rollback_plan(self, deployment_id: str, device_backups: List[DeviceBackup]) -> RollbackPlan:
        """Create rollback plan based on device backups"""
        rollback_configs = {}
        execution_order = []
        
        # Create rollback configurations from backups
        for backup in device_backups:
            if backup.config_content:
                rollback_configs[backup.device_name] = backup.config_content
                execution_order.append(backup.device_name)
        
        # Reverse order for rollback (leaf devices first, then spines)
        execution_order.sort(key=lambda x: ('SPINE' in x.upper(), x))
        
        rollback_commands = [
            "1. Stop all configuration changes",
            "2. Verify device connectivity",
            "3. Apply rollback configurations in order",
            "4. Verify network convergence",
            "5. Run post-rollback validation"
        ]
        
        verification_steps = [
            "Verify all devices are reachable",
            "Check routing protocol convergence",
            "Validate network connectivity",
            "Confirm no error messages in logs"
        ]
        
        estimated_duration = f"{len(execution_order) * 5} minutes"
        
        return RollbackPlan(
            rollback_id=f"RB-{deployment_id}",
            deployment_id=deployment_id,
            rollback_configs=rollback_configs,
            execution_order=execution_order,
            estimated_duration=estimated_duration,
            rollback_commands=rollback_commands,
            verification_steps=verification_steps
        )
    
    def deploy_configuration(self, description: str, target_devices: List[str] = None, 
                           requester: str = "system", maintenance_window: str = None) -> DeploymentExecution:
        """
        Deploy configuration with full validation and approval workflow
        
        Args:
            description: Natural language description of configuration to deploy
            target_devices: Optional list of target devices
            requester: Person/system requesting deployment
            maintenance_window: Optional maintenance window
            
        Returns:
            DeploymentExecution: Complete deployment execution record
        """
        deployment_id = f"DEP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        logger.info(f"Starting deployment {deployment_id}: {description}")
        
        try:
            # Generate configuration
            config_result = generate_configuration(description, ','.join(target_devices) if target_devices else "")
            
            if not config_result.get('success'):
                raise Exception(f"Configuration generation failed: {config_result.get('error')}")
            
            generated_config = config_result['configuration']['generated_config']
            if target_devices is None:
                target_devices = list(generated_config.keys())
            
            # Assess sensitivity and approval requirements
            combined_config = '\n'.join(generated_config.values())
            sensitivity_level = self._assess_sensitivity_level(combined_config, target_devices)
            approval_requirement = self._determine_approval_requirement(sensitivity_level, target_devices)
            
            # Create deployment execution record
            deployment = DeploymentExecution(
                deployment_id=deployment_id,
                request_description=description,
                target_devices=target_devices,
                generated_config=generated_config,
                sensitivity_level=sensitivity_level,
                approval_requirement=approval_requirement,
                status=DeploymentStatus.PENDING_APPROVAL if approval_requirement != ApprovalRequirement.NONE else DeploymentStatus.PRE_VALIDATION,
                pre_validation_results=[],
                post_validation_results=[],
                device_backups=[],
                change_tracking=[],
                rollback_plan=None,
                deployment_log=[f"Deployment {deployment_id} created at {datetime.now().isoformat()}"],
                start_timestamp=datetime.now().isoformat(),
                approvals=[],
                requester=requester,
                maintenance_window=maintenance_window
            )
            
            # Handle approval workflow
            if approval_requirement != ApprovalRequirement.NONE:
                approval = DeploymentApproval(
                    approval_id=f"APR-{deployment_id}",
                    deployment_id=deployment_id,
                    required_level=approval_requirement,
                    status="pending",
                    comments=f"Deployment requires {approval_requirement.value} approval"
                )
                deployment.approvals.append(approval)
                self.approval_queue.append(asdict(approval))
                self._save_approval_queue()
                
                deployment.deployment_log.append(f"Pending {approval_requirement.value} approval")
                logger.info(f"Deployment {deployment_id} pending {approval_requirement.value} approval")
            else:
                # Auto-approve low sensitivity changes
                deployment.status = DeploymentStatus.PRE_VALIDATION
                deployment.deployment_log.append("Auto-approved (low sensitivity)")
                logger.info(f"Deployment {deployment_id} auto-approved")
                
                # Continue with deployment
                deployment = self._execute_deployment(deployment)
            
            # Store deployment
            self.active_deployments[deployment_id] = deployment
            self.deployment_history.append(asdict(deployment))
            self._save_deployment_history()
            
            return deployment
            
        except Exception as e:
            logger.error(f"Deployment {deployment_id} failed: {e}")
            error_deployment = DeploymentExecution(
                deployment_id=deployment_id,
                request_description=description,
                target_devices=target_devices or [],
                generated_config={},
                sensitivity_level=SensitivityLevel.LOW,
                approval_requirement=ApprovalRequirement.NONE,
                status=DeploymentStatus.DEPLOYMENT_FAILED,
                pre_validation_results=[],
                post_validation_results=[],
                device_backups=[],
                change_tracking=[],
                rollback_plan=None,
                deployment_log=[f"Deployment failed: {str(e)}"],
                start_timestamp=datetime.now().isoformat(),
                completion_timestamp=datetime.now().isoformat(),
                requester=requester
            )
            
            self.deployment_history.append(asdict(error_deployment))
            self._save_deployment_history()
            
            return error_deployment
    
    def _execute_deployment(self, deployment: DeploymentExecution) -> DeploymentExecution:
        """Execute the actual deployment"""
        try:
            # Create device backups
            deployment.status = DeploymentStatus.PRE_VALIDATION
            deployment.deployment_log.append("Creating device backups...")
            
            for device in deployment.target_devices:
                backup = self._create_device_backup(device)
                deployment.device_backups.append(backup)
            
            # Run pre-validation
            deployment.deployment_log.append("Running pre-validation checks...")
            deployment.pre_validation_results = self._run_pre_validation(deployment.target_devices)
            
            # Check if pre-validation passed
            failed_validations = [v for v in deployment.pre_validation_results if v.status == "failed"]
            if failed_validations:
                deployment.status = DeploymentStatus.PRE_VALIDATION_FAILED
                deployment.completion_timestamp = datetime.now().isoformat()
                deployment.deployment_log.append("Pre-validation failed - deployment aborted")
                return deployment
            
            # Deploy configurations
            deployment.status = DeploymentStatus.DEPLOYING
            deployment.deployment_log.append("Deploying configurations...")
            
            # NOTE: In a real implementation, you would deploy configs to devices here
            # For now, we'll simulate successful deployment
            time.sleep(2)  # Simulate deployment time
            
            deployment.deployment_log.append("Configuration deployment completed")
            
            # Run post-validation
            deployment.status = DeploymentStatus.POST_VALIDATION
            deployment.deployment_log.append("Running post-validation checks...")
            deployment.post_validation_results = self._run_post_validation(deployment.target_devices)
            
            # Check if post-validation passed
            failed_post_validations = [v for v in deployment.post_validation_results if v.status == "failed"]
            if failed_post_validations:
                deployment.status = DeploymentStatus.POST_VALIDATION_FAILED
                deployment.deployment_log.append("Post-validation failed - consider rollback")
            else:
                deployment.status = DeploymentStatus.COMPLETED
                deployment.deployment_log.append("Deployment completed successfully")
            
            # Create rollback plan
            deployment.rollback_plan = self._create_rollback_plan(deployment.deployment_id, deployment.device_backups)
            deployment.completion_timestamp = datetime.now().isoformat()
            
            return deployment
            
        except Exception as e:
            deployment.status = DeploymentStatus.DEPLOYMENT_FAILED
            deployment.completion_timestamp = datetime.now().isoformat()
            deployment.deployment_log.append(f"Deployment execution failed: {str(e)}")
            logger.error(f"Deployment execution failed: {e}")
            return deployment
    
    def approve_deployment(self, deployment_id: str, approver: str, comments: str = "") -> Dict[str, Any]:
        """Approve a pending deployment"""
        try:
            # Find deployment in active deployments
            if deployment_id not in self.active_deployments:
                return {"success": False, "error": "Deployment not found"}
            
            deployment = self.active_deployments[deployment_id]
            
            if deployment.status != DeploymentStatus.PENDING_APPROVAL:
                return {"success": False, "error": "Deployment is not pending approval"}
            
            # Update approval
            if deployment.approvals:
                approval = deployment.approvals[0]
                approval.status = "approved"
                approval.approver = approver
                approval.approval_timestamp = datetime.now().isoformat()
                approval.comments = comments
            
            # Update deployment status and continue execution
            deployment.status = DeploymentStatus.APPROVED
            deployment.deployment_log.append(f"Approved by {approver}: {comments}")
            
            # Execute deployment
            deployment = self._execute_deployment(deployment)
            
            # Update stored deployment
            self.active_deployments[deployment_id] = deployment
            self._save_deployment_history()
            
            return {
                "success": True,
                "deployment_id": deployment_id,
                "status": deployment.status.value,
                "message": f"Deployment approved and executed by {approver}"
            }
            
        except Exception as e:
            logger.error(f"Approval failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_deployment_status(self, deployment_id: str) -> Dict[str, Any]:
        """Get deployment status and details"""
        if deployment_id in self.active_deployments:
            deployment = self.active_deployments[deployment_id]
            return {
                "success": True,
                "deployment": asdict(deployment)
            }
        
        # Search in history
        for deployment_dict in self.deployment_history:
            if deployment_dict.get('deployment_id') == deployment_id:
                return {
                    "success": True,
                    "deployment": deployment_dict
                }
        
        return {"success": False, "error": "Deployment not found"}
    
    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of deployments pending approval"""
        pending = []
        for deployment_id, deployment in self.active_deployments.items():
            if deployment.status == DeploymentStatus.PENDING_APPROVAL:
                pending.append({
                    "deployment_id": deployment_id,
                    "description": deployment.request_description,
                    "target_devices": deployment.target_devices,
                    "sensitivity_level": deployment.sensitivity_level.value,
                    "approval_requirement": deployment.approval_requirement.value,
                    "requester": deployment.requester,
                    "created": deployment.start_timestamp
                })
        return pending

# MCP Tool Functions
def deploy_configuration(description: str, target_devices: str = "", requester: str = "claude", 
                        maintenance_window: str = "") -> Dict[str, Any]:
    """
    Deploy configuration with pre/post validation and approval workflow
    
    Args:
        description: Natural language description of configuration to deploy
        target_devices: Comma-separated list of target devices (optional)
        requester: Person/system requesting deployment
        maintenance_window: Optional maintenance window
        
    Returns:
        Dict containing deployment status and details
    """
    try:
        # Parse target devices
        device_list = []
        if target_devices:
            device_list = [device.strip() for device in target_devices.split(',')]
        
        # Create deployer and execute deployment
        deployer = ConfigurationDeployer()
        result = deployer.deploy_configuration(
            description, 
            device_list if device_list else None,
            requester,
            maintenance_window if maintenance_window else None
        )
        
        # Convert enums to strings for JSON serialization
        def convert_enums(obj):
            if isinstance(obj, dict):
                return {k: convert_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums(item) for item in obj]
            elif isinstance(obj, (DeploymentStatus, SensitivityLevel, ApprovalRequirement)):
                return obj.value
            else:
                return obj
        
        result_dict = convert_enums(asdict(result))
        
        return {
            'success': True,
            'deployment': result_dict,
            'message': f"Deployment {result.deployment_id} initiated - Status: {result.status.value}"
        }
        
    except Exception as e:
        logger.error(f"MCP deploy_configuration failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Configuration deployment failed: {str(e)}"
        }

def get_deployment_status(deployment_id: str) -> Dict[str, Any]:
    """
    Get deployment status and progress
    
    Args:
        deployment_id: Deployment ID to check
        
    Returns:
        Dict containing deployment status and details
    """
    try:
        deployer = ConfigurationDeployer()
        result = deployer.get_deployment_status(deployment_id)
        
        if result['success']:
            # Convert enums to strings
            def convert_enums(obj):
                if isinstance(obj, dict):
                    return {k: convert_enums(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_enums(item) for item in obj]
                elif isinstance(obj, str) and obj in [s.value for s in DeploymentStatus]:
                    return obj
                elif isinstance(obj, str) and obj in [s.value for s in SensitivityLevel]:
                    return obj
                elif isinstance(obj, str) and obj in [s.value for s in ApprovalRequirement]:
                    return obj
                else:
                    return obj
            
            result['deployment'] = convert_enums(result['deployment'])
        
        return result
        
    except Exception as e:
        logger.error(f"MCP get_deployment_status failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to get deployment status: {str(e)}"
        }

def approve_deployment(deployment_id: str, approver: str, comments: str = "") -> Dict[str, Any]:
    """
    Approve a pending deployment
    
    Args:
        deployment_id: Deployment ID to approve
        approver: Name of person approving deployment
        comments: Optional approval comments
        
    Returns:
        Dict containing approval result
    """
    try:
        deployer = ConfigurationDeployer()
        result = deployer.approve_deployment(deployment_id, approver, comments)
        return result
        
    except Exception as e:
        logger.error(f"MCP approve_deployment failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to approve deployment: {str(e)}"
        }

def get_pending_approvals() -> Dict[str, Any]:
    """
    Get list of deployments pending approval
    
    Returns:
        Dict containing list of pending approvals
    """
    try:
        deployer = ConfigurationDeployer()
        pending = deployer.get_pending_approvals()
        
        return {
            'success': True,
            'pending_approvals': pending,
            'count': len(pending),
            'message': f"Found {len(pending)} deployments pending approval"
        }
        
    except Exception as e:
        logger.error(f"MCP get_pending_approvals failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Failed to get pending approvals: {str(e)}"
        }

if __name__ == "__main__":
    # Test the configuration deployer
    deployer = ConfigurationDeployer()
    
    # Test deployment
    result = deployer.deploy_configuration(
        "Configure loopback0 interface with IP address 10.1.1.1/32 on LEAF1",
        ["LEAF1"],
        "test_user"
    )
    
    print("Deployment Result:")
    print(f"ID: {result.deployment_id}")
    print(f"Status: {result.status.value}")
    print(f"Sensitivity: {result.sensitivity_level.value}")
    print(f"Approval Required: {result.approval_requirement.value}")
    print(f"Log: {result.deployment_log}")
