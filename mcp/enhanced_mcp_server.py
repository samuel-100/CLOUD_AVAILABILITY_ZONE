#!/usr/bin/env python3
"""
Enhanced MCP Server with Security and Authentication

Implements secure API key management, role-based access control,
session management, and comprehensive audit logging for the network automation MCP server.
"""

import os
import sys
import json
import yaml
import logging
import asyncio
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import jwt
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import existing services
from services.network_status_tool import get_network_status
from services.device_details_tool import get_device_details
from services.network_topology_tool import get_network_topology
from services.ai_analysis_tool import analyze_network_issue
from services.config_generation_tool import generate_configuration
from services.config_deployment_tool import deploy_configuration, get_deployment_status, approve_deployment, get_pending_approvals
from services.workflow_monitoring import get_workflow_status, get_workflow_history
from services.network_context_engine import get_network_context, start_network_monitoring, get_network_trends
from services.network_correlation_engine import analyze_network_correlation, detect_network_patterns, get_performance_optimizations, get_proactive_recommendations
from services.proactive_monitoring import start_proactive_monitoring, stop_proactive_monitoring, get_active_alerts, acknowledge_alert, get_proactive_monitoring_status
from services.data_protection import filter_claude_response, encrypt_sensitive_data, decrypt_sensitive_data, apply_retention_policy, validate_data_export_request, get_data_protection_status

# File paths
AUTH_CONFIG_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/config/auth_config.yaml'
API_KEYS_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/config/api_keys.yaml'
AUDIT_LOG_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/audit.log'
SESSION_STORE_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/sessions.json'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Setup audit logger
audit_logger = logging.getLogger('audit')
audit_handler = logging.FileHandler(AUDIT_LOG_FILE)
audit_handler.setFormatter(logging.Formatter('%(asctime)s - AUDIT - %(message)s'))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

class UserRole(Enum):
    """User roles for RBAC"""
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMINISTRATOR = "administrator"
    SUPERUSER = "superuser"

class Permission(Enum):
    """System permissions"""
    READ_STATUS = "read_status"
    READ_CONFIG = "read_config"
    EXECUTE_COMMAND = "execute_command"
    DEPLOY_CONFIG = "deploy_config"
    MANAGE_USERS = "manage_users"
    MANAGE_SYSTEM = "manage_system"
    EMERGENCY_ACCESS = "emergency_access"

@dataclass
class User:
    """User account definition"""
    username: str
    email: str
    role: UserRole
    permissions: Set[Permission]
    created_at: str
    last_login: Optional[str] = None
    active: bool = True
    password_hash: Optional[str] = None

@dataclass
class APIKey:
    """API key definition"""
    key_id: str
    name: str
    key_hash: str
    user: str
    permissions: Set[Permission]
    created_at: str
    expires_at: Optional[str] = None
    last_used: Optional[str] = None
    active: bool = True
    usage_count: int = 0

@dataclass
class Session:
    """User session definition"""
    session_id: str
    user: str
    permissions: Set[Permission]
    created_at: str
    expires_at: str
    last_activity: str
    ip_address: str
    user_agent: str
    active: bool = True

@dataclass
class AuditEvent:
    """Audit event for logging"""
    event_id: str
    timestamp: str
    user: str
    action: str
    resource: str
    outcome: str  # success, failure, error
    details: Dict[str, Any]
    ip_address: str
    user_agent: str

class SecurityManager:
    """Security and authentication manager"""
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.api_keys: Dict[str, APIKey] = {}
        self.sessions: Dict[str, Session] = {}
        self.role_permissions = self._initialize_role_permissions()
        self._load_configuration()
        self._load_sessions()
        
    def _initialize_role_permissions(self) -> Dict[UserRole, Set[Permission]]:
        """Initialize default role permissions"""
        return {
            UserRole.VIEWER: {
                Permission.READ_STATUS,
            },
            UserRole.OPERATOR: {
                Permission.READ_STATUS,
                Permission.READ_CONFIG,
                Permission.EXECUTE_COMMAND,
            },
            UserRole.ADMINISTRATOR: {
                Permission.READ_STATUS,
                Permission.READ_CONFIG,
                Permission.EXECUTE_COMMAND,
                Permission.DEPLOY_CONFIG,
                Permission.MANAGE_USERS,
            },
            UserRole.SUPERUSER: {
                Permission.READ_STATUS,
                Permission.READ_CONFIG,
                Permission.EXECUTE_COMMAND,
                Permission.DEPLOY_CONFIG,
                Permission.MANAGE_USERS,
                Permission.MANAGE_SYSTEM,
                Permission.EMERGENCY_ACCESS,
            }
        }
    
    def _load_configuration(self):
        """Load authentication configuration"""
        try:
            # Load users
            if os.path.exists(AUTH_CONFIG_FILE):
                with open(AUTH_CONFIG_FILE, 'r') as f:
                    config = yaml.safe_load(f)
                    for user_data in config.get('users', []):
                        permissions = set()
                        if 'permissions' in user_data:
                            permissions = {Permission(p) for p in user_data['permissions']}
                        else:
                            # Use role-based permissions
                            role = UserRole(user_data['role'])
                            permissions = self.role_permissions.get(role, set())
                        
                        user = User(
                            username=user_data['username'],
                            email=user_data['email'],
                            role=UserRole(user_data['role']),
                            permissions=permissions,
                            created_at=user_data['created_at'],
                            last_login=user_data.get('last_login'),
                            active=user_data.get('active', True),
                            password_hash=user_data.get('password_hash')
                        )
                        self.users[user.username] = user
            
            # Load API keys
            if os.path.exists(API_KEYS_FILE):
                with open(API_KEYS_FILE, 'r') as f:
                    keys_config = yaml.safe_load(f)
                    for key_data in keys_config.get('api_keys', []):
                        permissions = {Permission(p) for p in key_data['permissions']}
                        api_key = APIKey(
                            key_id=key_data['key_id'],
                            name=key_data['name'],
                            key_hash=key_data['key_hash'],
                            user=key_data['user'],
                            permissions=permissions,
                            created_at=key_data['created_at'],
                            expires_at=key_data.get('expires_at'),
                            last_used=key_data.get('last_used'),
                            active=key_data.get('active', True),
                            usage_count=key_data.get('usage_count', 0)
                        )
                        self.api_keys[api_key.key_id] = api_key
                        
        except Exception as e:
            logger.error(f"Failed to load authentication configuration: {e}")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration"""
        try:
            # Create default admin user
            admin_user = User(
                username="admin",
                email="admin@network-automation.local",
                role=UserRole.SUPERUSER,
                permissions=self.role_permissions[UserRole.SUPERUSER],
                created_at=datetime.now().isoformat(),
                active=True
            )
            self.users["admin"] = admin_user
            
            # Create default API key
            api_key_value = secrets.token_urlsafe(32)
            api_key_hash = hashlib.sha256(api_key_value.encode()).hexdigest()
            
            default_api_key = APIKey(
                key_id="default-admin-key",
                name="Default Admin API Key",
                key_hash=api_key_hash,
                user="admin",
                permissions=self.role_permissions[UserRole.SUPERUSER],
                created_at=datetime.now().isoformat(),
                active=True
            )
            self.api_keys["default-admin-key"] = default_api_key
            
            # Save configuration
            self._save_configuration()
            
            logger.info("Created default authentication configuration")
            logger.info(f"Default API key: {api_key_value}")
            
        except Exception as e:
            logger.error(f"Failed to create default configuration: {e}")
    
    def _save_configuration(self):
        """Save authentication configuration"""
        try:
            # Save users
            os.makedirs(os.path.dirname(AUTH_CONFIG_FILE), exist_ok=True)
            users_config = {
                'users': []
            }
            
            for user in self.users.values():
                user_data = {
                    'username': user.username,
                    'email': user.email,
                    'role': user.role.value,
                    'permissions': [p.value for p in user.permissions],
                    'created_at': user.created_at,
                    'last_login': user.last_login,
                    'active': user.active
                }
                if user.password_hash:
                    user_data['password_hash'] = user.password_hash
                users_config['users'].append(user_data)
            
            with open(AUTH_CONFIG_FILE, 'w') as f:
                yaml.dump(users_config, f, default_flow_style=False)
            
            # Save API keys
            keys_config = {
                'api_keys': []
            }
            
            for api_key in self.api_keys.values():
                key_data = {
                    'key_id': api_key.key_id,
                    'name': api_key.name,
                    'key_hash': api_key.key_hash,
                    'user': api_key.user,
                    'permissions': [p.value for p in api_key.permissions],
                    'created_at': api_key.created_at,
                    'expires_at': api_key.expires_at,
                    'last_used': api_key.last_used,
                    'active': api_key.active,
                    'usage_count': api_key.usage_count
                }
                keys_config['api_keys'].append(key_data)
            
            with open(API_KEYS_FILE, 'w') as f:
                yaml.dump(keys_config, f, default_flow_style=False)
                
        except Exception as e:
            logger.error(f"Failed to save authentication configuration: {e}")
    
    def _load_sessions(self):
        """Load active sessions"""
        try:
            if os.path.exists(SESSION_STORE_FILE):
                with open(SESSION_STORE_FILE, 'r') as f:
                    sessions_data = json.load(f)
                    for session_data in sessions_data:
                        permissions = {Permission(p) for p in session_data['permissions']}
                        session = Session(
                            session_id=session_data['session_id'],
                            user=session_data['user'],
                            permissions=permissions,
                            created_at=session_data['created_at'],
                            expires_at=session_data['expires_at'],
                            last_activity=session_data['last_activity'],
                            ip_address=session_data['ip_address'],
                            user_agent=session_data['user_agent'],
                            active=session_data['active']
                        )
                        self.sessions[session.session_id] = session
        except Exception as e:
            logger.error(f"Failed to load sessions: {e}")
    
    def _save_sessions(self):
        """Save active sessions"""
        try:
            sessions_data = []
            for session in self.sessions.values():
                session_data = {
                    'session_id': session.session_id,
                    'user': session.user,
                    'permissions': [p.value for p in session.permissions],
                    'created_at': session.created_at,
                    'expires_at': session.expires_at,
                    'last_activity': session.last_activity,
                    'ip_address': session.ip_address,
                    'user_agent': session.user_agent,
                    'active': session.active
                }
                sessions_data.append(session_data)
            
            with open(SESSION_STORE_FILE, 'w') as f:
                json.dump(sessions_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save sessions: {e}")
    
    def validate_api_key(self, api_key: str) -> Optional[APIKey]:
        """Validate API key and return key info"""
        try:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            for key_obj in self.api_keys.values():
                if key_obj.key_hash == key_hash and key_obj.active:
                    # Check expiration
                    if key_obj.expires_at:
                        expires = datetime.fromisoformat(key_obj.expires_at)
                        if datetime.now() > expires:
                            logger.warning(f"API key {key_obj.key_id} has expired")
                            return None
                    
                    # Update usage
                    key_obj.last_used = datetime.now().isoformat()
                    key_obj.usage_count += 1
                    self._save_configuration()
                    
                    return key_obj
            
            return None
            
        except Exception as e:
            logger.error(f"API key validation failed: {e}")
            return None
    
    def create_session(self, user: str, ip_address: str, user_agent: str) -> Session:
        """Create new user session"""
        session_id = str(uuid.uuid4())
        user_obj = self.users.get(user)
        
        if not user_obj:
            raise ValueError(f"User {user} not found")
        
        session = Session(
            session_id=session_id,
            user=user,
            permissions=user_obj.permissions,
            created_at=datetime.now().isoformat(),
            expires_at=(datetime.now() + timedelta(hours=8)).isoformat(),
            last_activity=datetime.now().isoformat(),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.sessions[session_id] = session
        self._save_sessions()
        
        return session
    
    def validate_session(self, session_id: str) -> Optional[Session]:
        """Validate session and update activity"""
        session = self.sessions.get(session_id)
        
        if not session or not session.active:
            return None
        
        # Check expiration
        expires = datetime.fromisoformat(session.expires_at)
        if datetime.now() > expires:
            logger.warning(f"Session {session_id} has expired")
            session.active = False
            self._save_sessions()
            return None
        
        # Update activity
        session.last_activity = datetime.now().isoformat()
        self._save_sessions()
        
        return session
    
    def has_permission(self, user_permissions: Set[Permission], required_permission: Permission) -> bool:
        """Check if user has required permission"""
        return required_permission in user_permissions or Permission.EMERGENCY_ACCESS in user_permissions
    
    def audit_log(self, user: str, action: str, resource: str, outcome: str, 
                  details: Dict[str, Any], ip_address: str = "", user_agent: str = ""):
        """Log audit event"""
        try:
            event = AuditEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now().isoformat(),
                user=user,
                action=action,
                resource=resource,
                outcome=outcome,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            audit_logger.info(json.dumps(asdict(event)))
            
        except Exception as e:
            logger.error(f"Audit logging failed: {e}")

class EnhancedMCPServer:
    """Enhanced MCP server with security and authentication"""
    
    def __init__(self, name: str = "enhanced-network-automation"):
        self.name = name
        self.security_manager = SecurityManager()
        self.tools = self._register_tools()
        
    def _register_tools(self) -> Dict[str, Dict[str, Any]]:
        """Register available MCP tools with permissions"""
        return {
            "get_network_status": {
                "function": get_network_status,
                "required_permission": Permission.READ_STATUS,
                "description": "Get real-time network status and device connectivity"
            },
            "get_device_details": {
                "function": get_device_details,
                "required_permission": Permission.READ_STATUS,
                "description": "Get detailed information about specific network device"
            },
            "get_network_topology": {
                "function": get_network_topology,
                "required_permission": Permission.READ_STATUS,
                "description": "Get network topology and device relationships"
            },
            "analyze_network_issue": {
                "function": analyze_network_issue,
                "required_permission": Permission.EXECUTE_COMMAND,
                "description": "AI-powered network issue analysis and recommendations"
            },
            "generate_configuration": {
                "function": generate_configuration,
                "required_permission": Permission.DEPLOY_CONFIG,
                "description": "AI-powered configuration generation from natural language"
            },
            "deploy_configuration": {
                "function": deploy_configuration,
                "required_permission": Permission.DEPLOY_CONFIG,
                "description": "Deploy configuration with pre/post validation and approval workflow"
            },
            "get_deployment_status": {
                "function": get_deployment_status,
                "required_permission": Permission.READ_STATUS,
                "description": "Get deployment status and progress details"
            },
            "approve_deployment": {
                "function": approve_deployment,
                "required_permission": Permission.MANAGE_SYSTEM,
                "description": "Approve a pending configuration deployment"
            },
            "get_pending_approvals": {
                "function": get_pending_approvals,
                "required_permission": Permission.READ_STATUS,
                "description": "Get list of deployments pending approval"
            },
            "get_network_context": {
                "function": get_network_context,
                "required_permission": Permission.READ_STATUS,
                "description": "Get comprehensive network context and intelligent state tracking"
            },
            "start_network_monitoring": {
                "function": start_network_monitoring,
                "required_permission": Permission.MANAGE_SYSTEM,
                "description": "Start continuous network monitoring with intelligent analysis"
            },
            "get_network_trends": {
                "function": get_network_trends,
                "required_permission": Permission.READ_STATUS,
                "description": "Get network performance trends and predictive analysis"
            },
            "get_workflow_status": {
                "function": get_workflow_status,
                "required_permission": Permission.READ_STATUS,
                "description": "Get workflow execution status and progress"
            },
            "get_workflow_history": {
                "function": get_workflow_history,
                "required_permission": Permission.READ_STATUS,
                "description": "Get workflow execution history"
            },
            "analyze_network_correlation": {
                "function": analyze_network_correlation,
                "required_permission": Permission.READ_STATUS,
                "description": "Analyze correlations between network changes and events"
            },
            "detect_network_patterns": {
                "function": detect_network_patterns,
                "required_permission": Permission.READ_STATUS,
                "description": "Detect patterns in network behavior and performance"
            },
            "get_performance_optimizations": {
                "function": get_performance_optimizations,
                "required_permission": Permission.READ_STATUS,
                "description": "Get performance optimization recommendations"
            },
            "get_proactive_recommendations": {
                "function": get_proactive_recommendations,
                "required_permission": Permission.READ_STATUS,
                "description": "Get proactive network management recommendations"
            },
            "start_proactive_monitoring": {
                "function": start_proactive_monitoring,
                "required_permission": Permission.MANAGE_SYSTEM,
                "description": "Start proactive network monitoring with intelligent alerting"
            },
            "stop_proactive_monitoring": {
                "function": stop_proactive_monitoring,
                "required_permission": Permission.MANAGE_SYSTEM,
                "description": "Stop proactive network monitoring service"
            },
            "get_active_alerts": {
                "function": get_active_alerts,
                "required_permission": Permission.READ_STATUS,
                "description": "Get current active network alerts with filtering and prioritization"
            },
            "acknowledge_alert": {
                "function": acknowledge_alert,
                "required_permission": Permission.EXECUTE_COMMAND,
                "description": "Acknowledge a network alert to stop escalation"
            },
            "get_proactive_monitoring_status": {
                "function": get_proactive_monitoring_status,
                "required_permission": Permission.READ_STATUS,
                "description": "Get proactive monitoring service status and configuration"
            },
            "filter_claude_response": {
                "function": filter_claude_response,
                "required_permission": Permission.READ_STATUS,
                "description": "Filter sensitive data from responses for Claude interface"
            },
            "encrypt_sensitive_data": {
                "function": encrypt_sensitive_data,
                "required_permission": Permission.MANAGE_SYSTEM,
                "description": "Encrypt sensitive data for secure storage"
            },
            "decrypt_sensitive_data": {
                "function": decrypt_sensitive_data,
                "required_permission": Permission.MANAGE_SYSTEM,
                "description": "Decrypt sensitive data from storage"
            },
            "apply_retention_policy": {
                "function": apply_retention_policy,
                "required_permission": Permission.MANAGE_SYSTEM,
                "description": "Apply data retention policy to files and data"
            },
            "validate_data_export_request": {
                "function": validate_data_export_request,
                "required_permission": Permission.EXECUTE_COMMAND,
                "description": "Validate data export requests for compliance"
            },
            "get_data_protection_status": {
                "function": get_data_protection_status,
                "required_permission": Permission.READ_STATUS,
                "description": "Get data protection service status and configuration"
            }
        }
    
    def authenticate_request(self, api_key: str = "", session_id: str = "") -> Optional[Dict[str, Any]]:
        """Authenticate API request"""
        try:
            if api_key:
                # API key authentication
                key_obj = self.security_manager.validate_api_key(api_key)
                if key_obj:
                    user_obj = self.security_manager.users.get(key_obj.user)
                    if user_obj and user_obj.active:
                        return {
                            'auth_type': 'api_key',
                            'user': user_obj.username,
                            'permissions': key_obj.permissions,
                            'key_id': key_obj.key_id
                        }
            
            elif session_id:
                # Session authentication
                session = self.security_manager.validate_session(session_id)
                if session:
                    return {
                        'auth_type': 'session',
                        'user': session.user,
                        'permissions': session.permissions,
                        'session_id': session.session_id
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return None
    
    def execute_tool(self, tool_name: str, auth_context: Dict[str, Any], 
                    args: Dict[str, Any], ip_address: str = "", user_agent: str = "") -> Dict[str, Any]:
        """Execute MCP tool with authentication and authorization"""
        try:
            # Check if tool exists
            if tool_name not in self.tools:
                self.security_manager.audit_log(
                    user=auth_context.get('user', 'unknown'),
                    action=f"execute_tool_{tool_name}",
                    resource=tool_name,
                    outcome="failure",
                    details={"error": "Tool not found", "args": args},
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return {
                    'success': False,
                    'error': 'Tool not found',
                    'message': f"Tool '{tool_name}' is not available"
                }
            
            tool_info = self.tools[tool_name]
            required_permission = tool_info['required_permission']
            user_permissions = auth_context.get('permissions', set())
            
            # Check permissions
            if not self.security_manager.has_permission(user_permissions, required_permission):
                self.security_manager.audit_log(
                    user=auth_context.get('user', 'unknown'),
                    action=f"execute_tool_{tool_name}",
                    resource=tool_name,
                    outcome="failure",
                    details={"error": "Insufficient permissions", "required": required_permission.value, "args": args},
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return {
                    'success': False,
                    'error': 'Insufficient permissions',
                    'message': f"Tool '{tool_name}' requires {required_permission.value} permission"
                }
            
            # Execute tool
            start_time = time.time()
            tool_function = tool_info['function']
            
            # Call tool function with appropriate arguments
            if tool_name == "get_device_details":
                result = tool_function(args.get('device_name', ''))
            elif tool_name == "analyze_network_issue":
                result = tool_function(
                    args.get('issue_description', ''),
                    args.get('focus_devices', '')
                )
            elif tool_name == "generate_configuration":
                result = tool_function(
                    args.get('description', ''),
                    args.get('target_devices', '')
                )
            elif tool_name == "deploy_configuration":
                result = tool_function(
                    args.get('description', ''),
                    args.get('target_devices', ''),
                    args.get('requester', auth_context.get('user', 'unknown')),
                    args.get('maintenance_window', '')
                )
            elif tool_name == "get_deployment_status":
                result = tool_function(args.get('deployment_id', ''))
            elif tool_name == "approve_deployment":
                result = tool_function(
                    args.get('deployment_id', ''),
                    auth_context.get('user', 'unknown'),
                    args.get('comments', '')
                )
            elif tool_name == "get_pending_approvals":
                result = tool_function()
            elif tool_name == "get_network_context":
                result = tool_function()
            elif tool_name == "start_network_monitoring":
                result = tool_function(args.get('monitoring_interval', 60))
            elif tool_name == "get_network_trends":
                result = tool_function(
                    args.get('device_name', ''),
                    args.get('metric_name', ''),
                    args.get('hours', 24)
                )
            elif tool_name == "get_workflow_status":
                result = tool_function(args.get('execution_id', ''))
            elif tool_name == "get_workflow_history":
                result = tool_function(
                    args.get('workflow_id', ''),
                    args.get('limit', 50)
                )
            elif tool_name == "analyze_network_correlation":
                result = tool_function(args.get('time_window_hours', 2))
            elif tool_name == "detect_network_patterns":
                result = tool_function(args.get('analysis_days', 7))
            elif tool_name == "get_performance_optimizations":
                result = tool_function()
            elif tool_name == "get_proactive_recommendations":
                result = tool_function()
            else:
                result = tool_function()
            
            execution_time = time.time() - start_time
            
            # Log successful execution
            self.security_manager.audit_log(
                user=auth_context.get('user', 'unknown'),
                action=f"execute_tool_{tool_name}",
                resource=tool_name,
                outcome="success",
                details={"execution_time": execution_time, "args": args},
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            return {
                'success': True,
                'result': result,
                'execution_time': execution_time,
                'message': f"Tool '{tool_name}' executed successfully"
            }
            
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            
            # Log failed execution
            self.security_manager.audit_log(
                user=auth_context.get('user', 'unknown'),
                action=f"execute_tool_{tool_name}",
                resource=tool_name,
                outcome="error",
                details={"error": str(e), "args": args},
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            return {
                'success': False,
                'error': str(e),
                'message': f"Tool '{tool_name}' execution failed: {str(e)}"
            }
    
    def get_available_tools(self, auth_context: Dict[str, Any] = None) -> List[Dict[str, str]]:
        """Get list of available tools for user"""
        available_tools = []
        user_permissions = auth_context.get('permissions', set()) if auth_context else set()
        
        for tool_name, tool_info in self.tools.items():
            if not auth_context or self.security_manager.has_permission(user_permissions, tool_info['required_permission']):
                available_tools.append({
                    'name': tool_name,
                    'description': tool_info['description'],
                    'required_permission': tool_info['required_permission'].value
                })
        
        return available_tools
    
    def generate_client_api_key(self, client_name: str, permissions: List[str]) -> str:
        """Generate new API key for external client"""
        try:
            api_key_value = secrets.token_urlsafe(32)
            key_id = f"client-{client_name}-{int(time.time())}"
            key_hash = hashlib.sha256(api_key_value.encode()).hexdigest()
            
            permission_set = set()
            for perm_str in permissions:
                try:
                    permission_set.add(Permission(perm_str))
                except ValueError:
                    logger.warning(f"Invalid permission: {perm_str}")
            
            api_key_obj = APIKey(
                key_id=key_id,
                name=f"Client API Key - {client_name}",
                key_hash=key_hash,
                user="system",
                permissions=permission_set,
                created_at=datetime.now().isoformat(),
                active=True
            )
            
            self.security_manager.api_keys[key_id] = api_key_obj
            self.security_manager._save_configuration()
            
            logger.info(f"Generated API key for client: {client_name}")
            return api_key_value
            
        except Exception as e:
            logger.error(f"Failed to generate API key: {e}")
            return ""

# Global enhanced MCP server instance
enhanced_mcp_server = EnhancedMCPServer()

# MCP Integration Functions
def secure_mcp_request(tool_name: str, api_key: str = "", session_id: str = "", 
                      args: Dict[str, Any] = None, ip_address: str = "", 
                      user_agent: str = "") -> Dict[str, Any]:
    """
    Secure MCP request handler with authentication and authorization
    
    Args:
        tool_name: Name of the MCP tool to execute
        api_key: API key for authentication
        session_id: Session ID for authentication
        args: Tool arguments
        ip_address: Client IP address
        user_agent: Client user agent
        
    Returns:
        Dict containing tool execution result
    """
    try:
        # Authenticate request
        auth_context = enhanced_mcp_server.authenticate_request(api_key, session_id)
        if not auth_context:
            return {
                'success': False,
                'error': 'Authentication failed',
                'message': 'Invalid API key or session'
            }
        
        # Execute tool
        result = enhanced_mcp_server.execute_tool(
            tool_name=tool_name,
            auth_context=auth_context,
            args=args or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Secure MCP request failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"MCP request failed: {str(e)}"
        }

if __name__ == "__main__":
    # Test the enhanced MCP server
    server = EnhancedMCPServer()
    print(f"Enhanced MCP Server '{server.name}' initialized")
    print(f"Available tools: {len(server.tools)}")
    
    # Generate test API key
    test_key = server.generate_client_api_key("test-client", ["read_status", "execute_command"])
    print(f"Test API key: {test_key}")
