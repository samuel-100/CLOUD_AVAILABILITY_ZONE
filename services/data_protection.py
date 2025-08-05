#!/usr/bin/env python3
"""
Data Protection and Filtering Service

Implements sensitive data filtering for Claude responses, encryption for data
at rest and in transit, privacy controls, and data retention policies for
network automation security and compliance.
"""

import os
import sys
import json
import yaml
import logging
import re
import hashlib
import base64
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import ipaddress
import socket

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# File paths
PROTECTION_CONFIG_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/config/data_protection.yaml'
ENCRYPTION_KEY_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/config/.encryption_key'
RETENTION_LOG_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/data_retention.log'
AUDIT_LOG_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/data_protection_audit.log'


class SensitivityLevel(Enum):
    """Data sensitivity classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class FilterAction(Enum):
    """Actions to take when sensitive data is detected"""
    REDACT = "redact"
    MASK = "mask"
    HASH = "hash"
    ENCRYPT = "encrypt"
    REMOVE = "remove"
    ALLOW = "allow"


class DataCategory(Enum):
    """Categories of data for filtering"""
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    HOSTNAME = "hostname"
    USERNAME = "username"
    PASSWORD = "password"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    SNMP_COMMUNITY = "snmp_community"
    VLAN_INFO = "vlan_info"
    BGP_ASN = "bgp_asn"
    NETWORK_TOPOLOGY = "network_topology"
    DEVICE_CONFIG = "device_config"
    SERIAL_NUMBER = "serial_number"
    FINANCIAL_DATA = "financial_data"
    PERSONAL_DATA = "personal_data"


@dataclass
class FilterRule:
    """Data filtering rule configuration"""
    rule_id: str
    name: str
    description: str
    category: DataCategory
    pattern: str  # regex pattern
    sensitivity: SensitivityLevel
    action: FilterAction
    replacement: str = "[REDACTED]"
    enabled: bool = True
    context_aware: bool = False  # Consider context when filtering
    whitelist_patterns: List[str] = None  # Patterns to exclude from filtering


@dataclass
class RetentionPolicy:
    """Data retention policy configuration"""
    policy_id: str
    name: str
    description: str
    data_types: List[str]
    retention_period_days: int
    archive_before_delete: bool = True
    encryption_required: bool = True
    compliance_tags: List[str] = None


@dataclass
class PrivacyControl:
    """Privacy control configuration"""
    control_id: str
    name: str
    description: str
    data_subject_rights: List[str]  # access, rectification, erasure, portability
    consent_required: bool = False
    purpose_limitation: bool = True
    data_minimization: bool = True


class DataProtectionService:
    """Comprehensive data protection and filtering service"""
    
    def __init__(self):
        self.config = self._load_configuration()
        self.filter_rules: Dict[str, FilterRule] = {}
        self.retention_policies: Dict[str, RetentionPolicy] = {}
        self.privacy_controls: Dict[str, PrivacyControl] = {}
        
        # Encryption key management
        self.encryption_key = self._load_or_generate_key()
        
        # Load rules and policies
        self._load_filter_rules()
        self._load_retention_policies()
        self._load_privacy_controls()
        
        # Compiled regex patterns for performance
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._compile_patterns()
        
        logger.info("Data protection service initialized")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load data protection configuration"""
        default_config = {
            'encryption': {
                'enabled': True,
                'algorithm': 'fernet',
                'key_rotation_days': 90
            },
            'filtering': {
                'enabled': True,
                'strict_mode': False,
                'log_filtered_data': True,
                'context_analysis': True
            },
            'retention': {
                'enabled': True,
                'default_retention_days': 365,
                'automatic_cleanup': True,
                'backup_before_delete': True
            },
            'privacy': {
                'gdpr_compliance': True,
                'ccpa_compliance': True,
                'data_subject_rights': True,
                'consent_tracking': True
            },
            'audit': {
                'log_all_access': True,
                'log_data_exports': True,
                'log_deletions': True,
                'alert_on_violations': True
            }
        }
        
        try:
            if os.path.exists(PROTECTION_CONFIG_FILE):
                with open(PROTECTION_CONFIG_FILE, 'r') as f:
                    config = yaml.safe_load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                return config
            else:
                # Create default config file
                os.makedirs(os.path.dirname(PROTECTION_CONFIG_FILE), exist_ok=True)
                with open(PROTECTION_CONFIG_FILE, 'w') as f:
                    yaml.dump(default_config, f, default_flow_style=False)
                return default_config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return default_config
    
    def _load_or_generate_key(self) -> Optional[bytes]:
        """Load existing encryption key or generate new one"""
        if not CRYPTO_AVAILABLE:
            logger.warning("Cryptography library not available - encryption disabled")
            return None
        
        try:
            # Try to load existing key
            if os.path.exists(ENCRYPTION_KEY_FILE):
                with open(ENCRYPTION_KEY_FILE, 'rb') as f:
                    return base64.urlsafe_b64decode(f.read())
            else:
                # Generate new key
                key = Fernet.generate_key()
                os.makedirs(os.path.dirname(ENCRYPTION_KEY_FILE), exist_ok=True)
                with open(ENCRYPTION_KEY_FILE, 'wb') as f:
                    f.write(key)
                os.chmod(ENCRYPTION_KEY_FILE, 0o600)  # Restrict permissions
                logger.info("Generated new encryption key")
                return base64.urlsafe_b64decode(key)
        except Exception as e:
            logger.error(f"Failed to load/generate encryption key: {e}")
            return None
    
    def _load_filter_rules(self):
        """Load data filtering rules"""
        default_rules = [
            FilterRule(
                rule_id="ip_private",
                name="Private IP Addresses",
                description="Filter private IP addresses",
                category=DataCategory.IP_ADDRESS,
                pattern=r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
                sensitivity=SensitivityLevel.CONFIDENTIAL,
                action=FilterAction.MASK,
                replacement="[PRIVATE_IP]"
            ),
            FilterRule(
                rule_id="ip_public",
                name="Public IP Addresses",
                description="Filter public IP addresses",
                category=DataCategory.IP_ADDRESS,
                pattern=r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                sensitivity=SensitivityLevel.RESTRICTED,
                action=FilterAction.REDACT,
                replacement="[PUBLIC_IP]"
            ),
            FilterRule(
                rule_id="mac_address",
                name="MAC Addresses",
                description="Filter MAC addresses",
                category=DataCategory.MAC_ADDRESS,
                pattern=r'\b[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}\b',
                sensitivity=SensitivityLevel.CONFIDENTIAL,
                action=FilterAction.MASK,
                replacement="[MAC_ADDRESS]"
            ),
            FilterRule(
                rule_id="password",
                name="Passwords",
                description="Filter password fields",
                category=DataCategory.PASSWORD,
                pattern=r'(?i)(?:password|passwd|pwd|secret|key)\s*[:=]\s*\S+',
                sensitivity=SensitivityLevel.TOP_SECRET,
                action=FilterAction.REDACT,
                replacement="[PASSWORD_REDACTED]"
            ),
            FilterRule(
                rule_id="api_key",
                name="API Keys",
                description="Filter API keys and tokens",
                category=DataCategory.API_KEY,
                pattern=r'(?i)(?:api[_-]?key|token|bearer)\s*[:=]\s*[a-zA-Z0-9+/=]{20,}',
                sensitivity=SensitivityLevel.TOP_SECRET,
                action=FilterAction.REDACT,
                replacement="[API_KEY_REDACTED]"
            ),
            FilterRule(
                rule_id="snmp_community",
                name="SNMP Community Strings",
                description="Filter SNMP community strings",
                category=DataCategory.SNMP_COMMUNITY,
                pattern=r'(?i)(?:community|snmp[-_]?string)\s*[:=]\s*\S+',
                sensitivity=SensitivityLevel.RESTRICTED,
                action=FilterAction.REDACT,
                replacement="[SNMP_COMMUNITY_REDACTED]"
            ),
            FilterRule(
                rule_id="serial_number",
                name="Device Serial Numbers",
                description="Filter device serial numbers",
                category=DataCategory.SERIAL_NUMBER,
                pattern=r'(?i)(?:serial|s/n|sn)\s*[:=]\s*[A-Z0-9]{8,}',
                sensitivity=SensitivityLevel.CONFIDENTIAL,
                action=FilterAction.MASK,
                replacement="[SERIAL_NUMBER]"
            ),
            FilterRule(
                rule_id="certificate",
                name="Certificates",
                description="Filter SSL/TLS certificates",
                category=DataCategory.CERTIFICATE,
                pattern=r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                sensitivity=SensitivityLevel.RESTRICTED,
                action=FilterAction.REDACT,
                replacement="[CERTIFICATE_REDACTED]"
            ),
            FilterRule(
                rule_id="private_key",
                name="Private Keys",
                description="Filter private keys",
                category=DataCategory.PRIVATE_KEY,
                pattern=r'-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----',
                sensitivity=SensitivityLevel.TOP_SECRET,
                action=FilterAction.REMOVE,
                replacement=""
            )
        ]
        
        # Store rules
        for rule in default_rules:
            self.filter_rules[rule.rule_id] = rule
        
        logger.info(f"Loaded {len(self.filter_rules)} filter rules")
    
    def _load_retention_policies(self):
        """Load data retention policies"""
        default_policies = [
            RetentionPolicy(
                policy_id="logs_standard",
                name="Standard Log Retention",
                description="Standard retention for operational logs",
                data_types=["audit_logs", "application_logs", "access_logs"],
                retention_period_days=365,
                archive_before_delete=True,
                encryption_required=True,
                compliance_tags=["SOX", "GDPR"]
            ),
            RetentionPolicy(
                policy_id="config_backups",
                name="Configuration Backup Retention",
                description="Retention for device configuration backups",
                data_types=["device_configs", "config_backups"],
                retention_period_days=1095,  # 3 years
                archive_before_delete=True,
                encryption_required=True,
                compliance_tags=["SOX", "HIPAA"]
            ),
            RetentionPolicy(
                policy_id="monitoring_data",
                name="Monitoring Data Retention",
                description="Retention for monitoring and performance data",
                data_types=["metrics", "alerts", "performance_data"],
                retention_period_days=730,  # 2 years
                archive_before_delete=False,
                encryption_required=False,
                compliance_tags=["GDPR"]
            ),
            RetentionPolicy(
                policy_id="security_logs",
                name="Security Log Retention",
                description="Extended retention for security-related logs",
                data_types=["security_logs", "auth_logs", "incident_logs"],
                retention_period_days=2555,  # 7 years
                archive_before_delete=True,
                encryption_required=True,
                compliance_tags=["SOX", "PCI", "GDPR", "HIPAA"]
            )
        ]
        
        # Store policies
        for policy in default_policies:
            self.retention_policies[policy.policy_id] = policy
        
        logger.info(f"Loaded {len(self.retention_policies)} retention policies")
    
    def _load_privacy_controls(self):
        """Load privacy control configurations"""
        default_controls = [
            PrivacyControl(
                control_id="gdpr_compliance",
                name="GDPR Compliance Control",
                description="Controls for GDPR compliance",
                data_subject_rights=["access", "rectification", "erasure", "portability", "restriction"],
                consent_required=True,
                purpose_limitation=True,
                data_minimization=True
            ),
            PrivacyControl(
                control_id="ccpa_compliance",
                name="CCPA Compliance Control",
                description="Controls for CCPA compliance",
                data_subject_rights=["access", "deletion", "opt_out"],
                consent_required=False,
                purpose_limitation=True,
                data_minimization=True
            )
        ]
        
        # Store controls
        for control in default_controls:
            self.privacy_controls[control.control_id] = control
        
        logger.info(f"Loaded {len(self.privacy_controls)} privacy controls")
    
    def _compile_patterns(self):
        """Compile regex patterns for performance"""
        for rule_id, rule in self.filter_rules.items():
            if rule.enabled:
                try:
                    flags = re.IGNORECASE if rule.category in [DataCategory.PASSWORD, DataCategory.API_KEY] else 0
                    self._compiled_patterns[rule_id] = re.compile(rule.pattern, flags | re.DOTALL)
                except re.error as e:
                    logger.error(f"Invalid regex pattern in rule {rule_id}: {e}")
    
    def filter_sensitive_data(self, data: Union[str, Dict, List], context: str = "general") -> Union[str, Dict, List]:
        """
        Filter sensitive data from various data types
        
        Args:
            data: Data to filter (string, dict, or list)
            context: Context for filtering decisions
            
        Returns:
            Filtered data with sensitive information protected
        """
        if not self.config.get('filtering', {}).get('enabled', True):
            return data
        
        try:
            if isinstance(data, str):
                return self._filter_string(data, context)
            elif isinstance(data, dict):
                return self._filter_dict(data, context)
            elif isinstance(data, list):
                return self._filter_list(data, context)
            else:
                return data
        except Exception as e:
            logger.error(f"Error filtering data: {e}")
            return "[DATA_FILTERING_ERROR]"
    
    def _filter_string(self, text: str, context: str = "general") -> str:
        """Filter sensitive data from string"""
        if not text or not isinstance(text, str):
            return text
        
        filtered_text = text
        filtered_items = []
        
        for rule_id, rule in self.filter_rules.items():
            if not rule.enabled:
                continue
            
            pattern = self._compiled_patterns.get(rule_id)
            if not pattern:
                continue
            
            # Apply context-aware filtering if enabled
            if rule.context_aware and not self._should_filter_in_context(rule, context):
                continue
            
            # Find matches
            matches = pattern.findall(filtered_text)
            if matches:
                for match in matches:
                    # Check whitelist patterns
                    if rule.whitelist_patterns:
                        skip_match = False
                        for whitelist_pattern in rule.whitelist_patterns:
                            if re.search(whitelist_pattern, match, re.IGNORECASE):
                                skip_match = True
                                break
                        if skip_match:
                            continue
                    
                    # Apply filtering action
                    replacement = self._apply_filter_action(match, rule)
                    filtered_text = filtered_text.replace(match, replacement)
                    
                    # Log filtered item
                    filtered_items.append({
                        'rule_id': rule_id,
                        'category': rule.category.value,
                        'action': rule.action.value,
                        'context': context,
                        'timestamp': datetime.now().isoformat()
                    })
        
        # Log filtering activity if enabled
        if filtered_items and self.config.get('filtering', {}).get('log_filtered_data', True):
            self._log_filtering_activity(filtered_items, context)
        
        return filtered_text
    
    def _filter_dict(self, data: Dict, context: str = "general") -> Dict:
        """Filter sensitive data from dictionary"""
        filtered_dict = {}
        
        for key, value in data.items():
            # Filter key if it's sensitive
            filtered_key = self._filter_string(str(key), f"{context}.key") if isinstance(key, str) else key
            
            # Filter value based on type
            if isinstance(value, str):
                filtered_value = self._filter_string(value, f"{context}.{key}")
            elif isinstance(value, dict):
                filtered_value = self._filter_dict(value, f"{context}.{key}")
            elif isinstance(value, list):
                filtered_value = self._filter_list(value, f"{context}.{key}")
            else:
                filtered_value = value
            
            filtered_dict[filtered_key] = filtered_value
        
        return filtered_dict
    
    def _filter_list(self, data: List, context: str = "general") -> List:
        """Filter sensitive data from list"""
        filtered_list = []
        
        for i, item in enumerate(data):
            if isinstance(item, str):
                filtered_item = self._filter_string(item, f"{context}[{i}]")
            elif isinstance(item, dict):
                filtered_item = self._filter_dict(item, f"{context}[{i}]")
            elif isinstance(item, list):
                filtered_item = self._filter_list(item, f"{context}[{i}]")
            else:
                filtered_item = item
            
            filtered_list.append(filtered_item)
        
        return filtered_list
    
    def _should_filter_in_context(self, rule: FilterRule, context: str) -> bool:
        """Determine if rule should be applied in given context"""
        # Context-aware filtering logic
        sensitive_contexts = ["config", "credentials", "security", "admin"]
        public_contexts = ["status", "topology", "general"]
        
        if rule.sensitivity == SensitivityLevel.TOP_SECRET:
            return True  # Always filter top secret data
        elif rule.sensitivity == SensitivityLevel.RESTRICTED:
            return context not in public_contexts
        elif rule.sensitivity == SensitivityLevel.CONFIDENTIAL:
            return any(ctx in context.lower() for ctx in sensitive_contexts)
        else:
            return False
    
    def _apply_filter_action(self, data: str, rule: FilterRule) -> str:
        """Apply filtering action to matched data"""
        if rule.action == FilterAction.REDACT:
            return rule.replacement
        elif rule.action == FilterAction.MASK:
            # Keep first and last characters, mask middle
            if len(data) <= 4:
                return "*" * len(data)
            else:
                return data[:2] + "*" * (len(data) - 4) + data[-2:]
        elif rule.action == FilterAction.HASH:
            return self._hash_data(data)
        elif rule.action == FilterAction.ENCRYPT:
            return self._encrypt_data(data)
        elif rule.action == FilterAction.REMOVE:
            return ""
        elif rule.action == FilterAction.ALLOW:
            return data
        else:
            return rule.replacement
    
    def _hash_data(self, data: str) -> str:
        """Create hash of sensitive data"""
        hash_object = hashlib.sha256(data.encode())
        return f"[HASH:{hash_object.hexdigest()[:16]}]"
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not CRYPTO_AVAILABLE or not self.encryption_key:
            return "[ENCRYPTION_UNAVAILABLE]"
        
        try:
            fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key))
            encrypted = fernet.encrypt(data.encode())
            return f"[ENCRYPTED:{base64.urlsafe_b64encode(encrypted).decode()[:32]}...]"
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return "[ENCRYPTION_FAILED]"
    
    def encrypt_for_storage(self, data: str) -> Optional[str]:
        """Encrypt data for storage"""
        if not CRYPTO_AVAILABLE or not self.encryption_key:
            return None
        
        try:
            fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key))
            encrypted = fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Storage encryption failed: {e}")
            return None
    
    def decrypt_from_storage(self, encrypted_data: str) -> Optional[str]:
        """Decrypt data from storage"""
        if not CRYPTO_AVAILABLE or not self.encryption_key:
            return None
        
        try:
            fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key))
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Storage decryption failed: {e}")
            return None
    
    def _log_filtering_activity(self, filtered_items: List[Dict], context: str):
        """Log data filtering activity"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'context': context,
                'filtered_count': len(filtered_items),
                'items': filtered_items
            }
            
            with open(AUDIT_LOG_FILE, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to log filtering activity: {e}")
    
    def check_data_retention(self, data_type: str, timestamp: datetime) -> Dict[str, Any]:
        """Check if data should be retained or deleted based on retention policies"""
        try:
            applicable_policies = []
            
            for policy_id, policy in self.retention_policies.items():
                if data_type in policy.data_types:
                    applicable_policies.append(policy)
            
            if not applicable_policies:
                # Use default retention
                default_days = self.config.get('retention', {}).get('default_retention_days', 365)
                cutoff_date = datetime.now() - timedelta(days=default_days)
                
                return {
                    'should_retain': timestamp > cutoff_date,
                    'policy': 'default',
                    'retention_days': default_days,
                    'action_required': timestamp <= cutoff_date
                }
            
            # Use most restrictive policy (longest retention)
            max_retention_policy = max(applicable_policies, key=lambda p: p.retention_period_days)
            cutoff_date = datetime.now() - timedelta(days=max_retention_policy.retention_period_days)
            
            return {
                'should_retain': timestamp > cutoff_date,
                'policy': max_retention_policy.policy_id,
                'retention_days': max_retention_policy.retention_period_days,
                'archive_required': max_retention_policy.archive_before_delete,
                'encryption_required': max_retention_policy.encryption_required,
                'compliance_tags': max_retention_policy.compliance_tags,
                'action_required': timestamp <= cutoff_date
            }
            
        except Exception as e:
            logger.error(f"Error checking data retention: {e}")
            return {
                'should_retain': True,
                'error': str(e)
            }
    
    def apply_data_retention(self, data_path: str, data_type: str) -> Dict[str, Any]:
        """Apply data retention policy to specific data"""
        try:
            # Get file timestamp
            if os.path.exists(data_path):
                file_timestamp = datetime.fromtimestamp(os.path.getmtime(data_path))
            else:
                return {'success': False, 'error': 'File not found'}
            
            # Check retention policy
            retention_check = self.check_data_retention(data_type, file_timestamp)
            
            if not retention_check.get('action_required', False):
                return {'success': True, 'action': 'retained', 'reason': 'within_retention_period'}
            
            # Action required - archive or delete
            actions_taken = []
            
            if retention_check.get('archive_required', False):
                # Archive the file
                archive_result = self._archive_file(data_path, retention_check)
                if archive_result['success']:
                    actions_taken.append('archived')
                else:
                    return {'success': False, 'error': f"Archive failed: {archive_result['error']}"}
            
            # Delete the original file
            try:
                os.remove(data_path)
                actions_taken.append('deleted')
            except Exception as e:
                return {'success': False, 'error': f"Deletion failed: {e}"}
            
            # Log retention action
            self._log_retention_action(data_path, data_type, actions_taken, retention_check)
            
            return {
                'success': True,
                'actions': actions_taken,
                'policy': retention_check['policy'],
                'retention_days': retention_check['retention_days']
            }
            
        except Exception as e:
            logger.error(f"Error applying data retention: {e}")
            return {'success': False, 'error': str(e)}
    
    def _archive_file(self, file_path: str, retention_info: Dict) -> Dict[str, Any]:
        """Archive file before deletion"""
        try:
            # Create archive directory
            archive_dir = os.path.join(os.path.dirname(file_path), 'archive')
            os.makedirs(archive_dir, exist_ok=True)
            
            # Create archive filename with timestamp
            base_name = os.path.basename(file_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            archive_name = f"{timestamp}_{base_name}"
            archive_path = os.path.join(archive_dir, archive_name)
            
            # Read and potentially encrypt file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            if retention_info.get('encryption_required', False):
                # Encrypt content before archiving
                encrypted_content = self.encrypt_for_storage(content.decode('utf-8', errors='ignore'))
                if encrypted_content:
                    content = encrypted_content.encode()
            
            # Write to archive
            with open(archive_path, 'wb') as f:
                f.write(content)
            
            return {'success': True, 'archive_path': archive_path}
            
        except Exception as e:
            logger.error(f"File archiving failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _log_retention_action(self, file_path: str, data_type: str, actions: List[str], retention_info: Dict):
        """Log data retention action"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'file_path': file_path,
                'data_type': data_type,
                'actions': actions,
                'policy': retention_info.get('policy'),
                'retention_days': retention_info.get('retention_days'),
                'compliance_tags': retention_info.get('compliance_tags', [])
            }
            
            with open(RETENTION_LOG_FILE, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Failed to log retention action: {e}")
    
    def validate_data_export(self, data: Any, export_purpose: str, requester: str) -> Dict[str, Any]:
        """Validate data export for compliance"""
        try:
            # Check privacy controls
            applicable_controls = []
            for control in self.privacy_controls.values():
                if export_purpose in control.data_subject_rights:
                    applicable_controls.append(control)
            
            # Validate purpose limitation
            allowed_purposes = ['legal_compliance', 'data_subject_request', 'legitimate_interest', 'consent']
            if export_purpose not in allowed_purposes:
                return {
                    'allowed': False,
                    'reason': 'Invalid export purpose',
                    'valid_purposes': allowed_purposes
                }
            
            # Apply data minimization
            filtered_data = self.filter_sensitive_data(data, f"export.{export_purpose}")
            
            # Log export
            self._log_data_export(export_purpose, requester, type(data).__name__)
            
            return {
                'allowed': True,
                'filtered_data': filtered_data,
                'controls_applied': [c.control_id for c in applicable_controls],
                'purpose': export_purpose,
                'requester': requester
            }
            
        except Exception as e:
            logger.error(f"Data export validation failed: {e}")
            return {
                'allowed': False,
                'error': str(e)
            }
    
    def _log_data_export(self, purpose: str, requester: str, data_type: str):
        """Log data export activity"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'event': 'data_export',
                'purpose': purpose,
                'requester': requester,
                'data_type': data_type
            }
            
            with open(AUDIT_LOG_FILE, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Failed to log data export: {e}")
    
    def get_protection_status(self) -> Dict[str, Any]:
        """Get data protection service status"""
        return {
            'success': True,
            'protection_status': {
                'encryption_enabled': CRYPTO_AVAILABLE and self.encryption_key is not None,
                'filtering_enabled': self.config.get('filtering', {}).get('enabled', True),
                'retention_enabled': self.config.get('retention', {}).get('enabled', True),
                'privacy_controls_enabled': self.config.get('privacy', {}).get('gdpr_compliance', True),
                'filter_rules_count': len(self.filter_rules),
                'retention_policies_count': len(self.retention_policies),
                'privacy_controls_count': len(self.privacy_controls),
                'last_check': datetime.now().isoformat()
            }
        }


# Global data protection service instance
_protection_service = None


def get_protection_service() -> DataProtectionService:
    """Get global data protection service instance"""
    global _protection_service
    if _protection_service is None:
        _protection_service = DataProtectionService()
    return _protection_service


# MCP Tool Functions
def filter_claude_response(data: Union[str, Dict, List], context: str = "claude_response") -> Union[str, Dict, List]:
    """
    Filter sensitive data from Claude responses
    
    Args:
        data: Response data to filter
        context: Context for filtering decisions
        
    Returns:
        Filtered data safe for Claude interface
    """
    try:
        service = get_protection_service()
        filtered_data = service.filter_sensitive_data(data, context)
        
        # Log the filtering activity
        logger.info(f"Filtered Claude response data in context: {context}")
        
        return filtered_data
        
    except Exception as e:
        logger.error(f"Failed to filter Claude response: {e}")
        return "[DATA_FILTERING_ERROR]"


def encrypt_sensitive_data(data: str) -> Dict[str, Any]:
    """
    Encrypt sensitive data for secure storage
    
    Args:
        data: Data to encrypt
        
    Returns:
        Dict containing encryption result
    """
    try:
        service = get_protection_service()
        encrypted = service.encrypt_for_storage(data)
        
        if encrypted:
            return {
                'success': True,
                'encrypted_data': encrypted,
                'message': 'Data encrypted successfully'
            }
        else:
            return {
                'success': False,
                'error': 'Encryption failed - check service configuration'
            }
            
    except Exception as e:
        logger.error(f"Failed to encrypt data: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def decrypt_sensitive_data(encrypted_data: str) -> Dict[str, Any]:
    """
    Decrypt sensitive data from storage
    
    Args:
        encrypted_data: Encrypted data to decrypt
        
    Returns:
        Dict containing decryption result
    """
    try:
        service = get_protection_service()
        decrypted = service.decrypt_from_storage(encrypted_data)
        
        if decrypted:
            return {
                'success': True,
                'decrypted_data': decrypted,
                'message': 'Data decrypted successfully'
            }
        else:
            return {
                'success': False,
                'error': 'Decryption failed - check data integrity'
            }
            
    except Exception as e:
        logger.error(f"Failed to decrypt data: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def apply_retention_policy(file_path: str, data_type: str) -> Dict[str, Any]:
    """
    Apply data retention policy to file
    
    Args:
        file_path: Path to file to check
        data_type: Type of data for policy lookup
        
    Returns:
        Dict containing retention action results
    """
    try:
        service = get_protection_service()
        result = service.apply_data_retention(file_path, data_type)
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to apply retention policy: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def validate_data_export_request(data: Any, purpose: str, requester: str) -> Dict[str, Any]:
    """
    Validate data export request for compliance
    
    Args:
        data: Data to export
        purpose: Purpose of export
        requester: Person/system requesting export
        
    Returns:
        Dict containing validation result and filtered data
    """
    try:
        service = get_protection_service()
        result = service.validate_data_export(data, purpose, requester)
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to validate data export: {e}")
        return {
            'allowed': False,
            'error': str(e)
        }


def get_data_protection_status() -> Dict[str, Any]:
    """
    Get data protection service status and configuration
    
    Returns:
        Dict containing protection service status
    """
    try:
        service = get_protection_service()
        result = service.get_protection_status()
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to get protection status: {e}")
        return {
            'success': False,
            'error': str(e)
        }


if __name__ == "__main__":
    # Command-line interface for testing
    import argparse
    
    parser = argparse.ArgumentParser(description='Data Protection and Filtering Service')
    parser.add_argument('--test-filter', type=str, help='Test filtering on provided text')
    parser.add_argument('--status', action='store_true', help='Get protection status')
    parser.add_argument('--encrypt', type=str, help='Encrypt provided text')
    parser.add_argument('--decrypt', type=str, help='Decrypt provided text')
    
    args = parser.parse_args()
    
    if args.test_filter:
        result = filter_claude_response(args.test_filter, "test")
        print(f"Original: {args.test_filter}")
        print(f"Filtered: {result}")
    
    elif args.encrypt:
        result = encrypt_sensitive_data(args.encrypt)
        print(json.dumps(result, indent=2))
    
    elif args.decrypt:
        result = decrypt_sensitive_data(args.decrypt)
        print(json.dumps(result, indent=2))
    
    elif args.status:
        result = get_data_protection_status()
        print(json.dumps(result, indent=2))
    
    else:
        parser.print_help()
