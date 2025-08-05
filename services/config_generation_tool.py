#!/usr/bin/env python3
"""
AI-Powered Configuration Generation Tool

Implements natural language to network configuration translation,
configuration validation, best practice checking, deployment planning,
and risk assessment for network automation.
"""

import os
import sys
import json
import yaml
import logging
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import network services
from services.network_topology_tool import get_network_topology
from services.device_details_tool import get_device_details

# File paths
TOPOLOGY_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/network_topology.yaml'
TEMPLATES_DIR = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/templates'
CONFIG_VALIDATION_RULES = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/config/validation_rules.yaml'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigType(Enum):
    """Configuration types"""
    INTERFACE = "interface"
    ROUTING = "routing"
    VLAN = "vlan"
    SECURITY = "security"
    QOS = "qos"
    MONITORING = "monitoring"
    GENERAL = "general"

class RiskLevel(Enum):
    """Risk levels for configuration changes"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ValidationSeverity(Enum):
    """Validation issue severity"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class ConfigurationRequest:
    """Natural language configuration request"""
    request_id: str
    description: str
    target_devices: List[str]
    config_type: ConfigType
    priority: str = "normal"
    requester: str = "system"
    timestamp: str = ""

@dataclass
class ValidationRule:
    """Configuration validation rule"""
    rule_id: str
    name: str
    description: str
    pattern: str
    severity: ValidationSeverity
    config_types: List[ConfigType]
    recommendation: str = ""

@dataclass
class ValidationIssue:
    """Configuration validation issue"""
    rule_id: str
    severity: ValidationSeverity
    line_number: int
    description: str
    recommendation: str
    original_config: str
    suggested_fix: str = ""

@dataclass
class BestPracticeCheck:
    """Best practice check result"""
    check_id: str
    name: str
    passed: bool
    severity: ValidationSeverity
    description: str
    recommendation: str
    affected_lines: List[int] = None

@dataclass
class RiskAssessment:
    """Configuration change risk assessment"""
    overall_risk: RiskLevel
    risk_factors: List[str]
    mitigation_steps: List[str]
    rollback_plan: str
    impact_analysis: str
    deployment_windows: List[str] = None

@dataclass
class DeploymentPlan:
    """Configuration deployment plan"""
    plan_id: str
    deployment_order: List[str]
    pre_checks: List[str]
    post_checks: List[str]
    estimated_duration: str
    maintenance_window: str = ""
    contact_information: str = ""

@dataclass
class GeneratedConfiguration:
    """Generated network configuration"""
    config_id: str
    request: ConfigurationRequest
    generated_config: Dict[str, str]  # device_name -> config_text
    validation_issues: List[ValidationIssue]
    best_practice_checks: List[BestPracticeCheck]
    risk_assessment: RiskAssessment
    deployment_plan: DeploymentPlan
    confidence_score: float  # 0.0 to 1.0
    timestamp: str

class ConfigurationParser:
    """Natural language configuration request parser"""
    
    def __init__(self):
        self.intent_patterns = self._initialize_intent_patterns()
        self.device_patterns = self._initialize_device_patterns()
        
    def _initialize_intent_patterns(self) -> Dict[ConfigType, List[str]]:
        """Initialize patterns for configuration intent recognition"""
        return {
            ConfigType.INTERFACE: [
                r"configure interface|setup interface|add interface|create interface",
                r"set ip address|assign ip|configure ip",
                r"enable interface|bring up interface|no shutdown",
                r"disable interface|shutdown interface|take down",
                r"interface description|interface name"
            ],
            ConfigType.ROUTING: [
                r"configure routing|setup routing|add route|create route",
                r"ospf|bgp|eigrp|rip|static route",
                r"default route|default gateway",
                r"routing protocol|routing configuration",
                r"neighbor|peer|adjacency"
            ],
            ConfigType.VLAN: [
                r"configure vlan|setup vlan|add vlan|create vlan",
                r"vlan.*\d+|vlan configuration",
                r"trunk|access|switchport",
                r"vlan name|vlan description"
            ],
            ConfigType.SECURITY: [
                r"configure security|setup security|add security",
                r"access-list|acl|access control",
                r"firewall|security policy",
                r"authentication|authorization|accounting",
                r"ssh|ssl|tls|encryption"
            ],
            ConfigType.QOS: [
                r"configure qos|setup qos|quality of service",
                r"traffic shaping|rate limiting|bandwidth",
                r"priority|dscp|cos|marking",
                r"policy-map|class-map|service-policy"
            ],
            ConfigType.MONITORING: [
                r"configure monitoring|setup monitoring|add monitoring",
                r"snmp|logging|syslog",
                r"netflow|sflow|monitoring",
                r"debug|troubleshooting|diagnostics"
            ]
        }
    
    def _initialize_device_patterns(self) -> List[str]:
        """Initialize patterns for device recognition"""
        return [
            r"on device (\w+)|device (\w+)|(\w+) device",
            r"on switch (\w+)|switch (\w+)|(\w+) switch",
            r"on router (\w+)|router (\w+)|(\w+) router",
            r"on (\w+)|(\w+) only",
            r"all devices|every device|all switches|all routers"
        ]
    
    def parse_request(self, description: str) -> ConfigurationRequest:
        """Parse natural language configuration request"""
        request_id = f"CR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Detect configuration type
        config_type = self._detect_config_type(description)
        
        # Extract target devices
        target_devices = self._extract_target_devices(description)
        
        # Detect priority
        priority = self._detect_priority(description)
        
        return ConfigurationRequest(
            request_id=request_id,
            description=description,
            target_devices=target_devices,
            config_type=config_type,
            priority=priority,
            timestamp=datetime.now().isoformat()
        )
    
    def _detect_config_type(self, description: str) -> ConfigType:
        """Detect configuration type from description"""
        description_lower = description.lower()
        
        for config_type, patterns in self.intent_patterns.items():
            for pattern in patterns:
                if re.search(pattern, description_lower):
                    return config_type
        
        return ConfigType.GENERAL
    
    def _extract_target_devices(self, description: str) -> List[str]:
        """Extract target devices from description"""
        devices = []
        description_lower = description.lower()
        
        # Check for specific device names
        topology_info = get_network_topology()
        if 'devices' in topology_info:
            for device in topology_info['devices']:
                device_name = device['name'].lower()
                if device_name in description_lower:
                    devices.append(device['name'])
        
        # Check for device type patterns
        if re.search(r"all devices|every device", description_lower):
            if 'devices' in topology_info:
                devices = [device['name'] for device in topology_info['devices']]
        elif re.search(r"all switches|spine|leaf", description_lower):
            if 'devices' in topology_info:
                devices = [device['name'] for device in topology_info['devices'] 
                          if device.get('role') in ['spine', 'leaf']]
        
        # If no devices specified, return empty list (will prompt user)
        return devices if devices else []
    
    def _detect_priority(self, description: str) -> str:
        """Detect priority from description"""
        description_lower = description.lower()
        
        if re.search(r"urgent|critical|emergency|asap", description_lower):
            return "high"
        elif re.search(r"low priority|when convenient|non-urgent", description_lower):
            return "low"
        else:
            return "normal"

class ConfigurationValidator:
    """Configuration validation and best practices checker"""
    
    def __init__(self):
        self.validation_rules = self._load_validation_rules()
        self.best_practice_rules = self._initialize_best_practice_rules()
        
    def _load_validation_rules(self) -> List[ValidationRule]:
        """Load validation rules from configuration"""
        rules = []
        try:
            if os.path.exists(CONFIG_VALIDATION_RULES):
                with open(CONFIG_VALIDATION_RULES, 'r') as f:
                    rules_config = yaml.safe_load(f)
                    for rule_data in rules_config.get('validation_rules', []):
                        rule = ValidationRule(
                            rule_id=rule_data['rule_id'],
                            name=rule_data['name'],
                            description=rule_data['description'],
                            pattern=rule_data['pattern'],
                            severity=ValidationSeverity(rule_data['severity']),
                            config_types=[ConfigType(ct) for ct in rule_data['config_types']],
                            recommendation=rule_data.get('recommendation', '')
                        )
                        rules.append(rule)
            else:
                # Create default validation rules
                rules = self._create_default_validation_rules()
                self._save_validation_rules(rules)
        except Exception as e:
            logger.error(f"Failed to load validation rules: {e}")
            rules = self._create_default_validation_rules()
        
        return rules
    
    def _create_default_validation_rules(self) -> List[ValidationRule]:
        """Create default validation rules"""
        return [
            ValidationRule(
                rule_id="NO_SHUTDOWN_CHECK",
                name="Interface Shutdown Check",
                description="Ensure interfaces are properly enabled with 'no shutdown'",
                pattern=r"interface\s+\w+.*?(?=interface|\Z)",
                severity=ValidationSeverity.WARNING,
                config_types=[ConfigType.INTERFACE],
                recommendation="Add 'no shutdown' command to enable the interface"
            ),
            ValidationRule(
                rule_id="IP_ADDRESS_FORMAT",
                name="IP Address Format Validation",
                description="Validate IP address format and subnet mask",
                pattern=r"ip address (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                severity=ValidationSeverity.ERROR,
                config_types=[ConfigType.INTERFACE],
                recommendation="Use valid IP address and subnet mask format"
            ),
            ValidationRule(
                rule_id="VLAN_RANGE_CHECK",
                name="VLAN Range Validation",
                description="Ensure VLAN IDs are within valid range (1-4094)",
                pattern=r"vlan (\d+)",
                severity=ValidationSeverity.ERROR,
                config_types=[ConfigType.VLAN],
                recommendation="Use VLAN IDs between 1 and 4094"
            ),
            ValidationRule(
                rule_id="OSPF_AREA_FORMAT",
                name="OSPF Area Format Check",
                description="Validate OSPF area format",
                pattern=r"network .* area (\d+|\d+\.\d+\.\d+\.\d+)",
                severity=ValidationSeverity.WARNING,
                config_types=[ConfigType.ROUTING],
                recommendation="Use standard OSPF area format (0 or dotted decimal)"
            ),
            ValidationRule(
                rule_id="BGP_AS_RANGE",
                name="BGP AS Number Validation",
                description="Validate BGP AS number range",
                pattern=r"router bgp (\d+)",
                severity=ValidationSeverity.ERROR,
                config_types=[ConfigType.ROUTING],
                recommendation="Use valid BGP AS number (1-65535 for 2-byte, 1-4294967295 for 4-byte)"
            )
        ]
    
    def _save_validation_rules(self, rules: List[ValidationRule]):
        """Save validation rules to configuration file"""
        try:
            os.makedirs(os.path.dirname(CONFIG_VALIDATION_RULES), exist_ok=True)
            rules_config = {
                'validation_rules': []
            }
            
            for rule in rules:
                rule_data = {
                    'rule_id': rule.rule_id,
                    'name': rule.name,
                    'description': rule.description,
                    'pattern': rule.pattern,
                    'severity': rule.severity.value,
                    'config_types': [ct.value for ct in rule.config_types],
                    'recommendation': rule.recommendation
                }
                rules_config['validation_rules'].append(rule_data)
            
            with open(CONFIG_VALIDATION_RULES, 'w') as f:
                yaml.dump(rules_config, f, default_flow_style=False)
                
        except Exception as e:
            logger.error(f"Failed to save validation rules: {e}")
    
    def _initialize_best_practice_rules(self) -> List[Dict[str, Any]]:
        """Initialize best practice checking rules"""
        return [
            {
                'check_id': 'INTERFACE_DESCRIPTION',
                'name': 'Interface Description',
                'pattern': r'interface\s+(\S+)(?:\n(?!interface).*)*',
                'requirement': r'description\s+\S+',
                'severity': ValidationSeverity.INFO,
                'description': 'All interfaces should have meaningful descriptions',
                'recommendation': 'Add description to interface for documentation purposes'
            },
            {
                'check_id': 'OSPF_AUTHENTICATION',
                'name': 'OSPF Authentication',
                'pattern': r'router ospf\s+\d+(?:\n(?!router).*)*',
                'requirement': r'area\s+\d+\s+authentication',
                'severity': ValidationSeverity.WARNING,
                'description': 'OSPF areas should use authentication for security',
                'recommendation': 'Configure OSPF authentication for improved security'
            },
            {
                'check_id': 'BGP_PASSWORD',
                'name': 'BGP Neighbor Password',
                'pattern': r'neighbor\s+\S+\s+remote-as\s+\d+',
                'requirement': r'neighbor\s+\S+\s+password',
                'severity': ValidationSeverity.WARNING,
                'description': 'BGP neighbors should use MD5 authentication',
                'recommendation': 'Configure BGP neighbor password for security'
            },
            {
                'check_id': 'BANNER_MOTD',
                'name': 'Banner MOTD',
                'pattern': r'banner motd',
                'requirement': r'banner motd',
                'severity': ValidationSeverity.INFO,
                'description': 'Device should have a message of the day banner',
                'recommendation': 'Configure banner motd for security and legal notices'
            },
            {
                'check_id': 'NTP_CONFIGURATION',
                'name': 'NTP Configuration',
                'pattern': r'ntp server',
                'requirement': r'ntp server',
                'severity': ValidationSeverity.WARNING,
                'description': 'Device should be configured with NTP for time synchronization',
                'recommendation': 'Configure NTP server for accurate time synchronization'
            }
        ]
    
    def validate_configuration(self, config_text: str, config_type: ConfigType) -> List[ValidationIssue]:
        """Validate configuration against rules"""
        issues = []
        lines = config_text.split('\n')
        
        # Apply validation rules
        for rule in self.validation_rules:
            if config_type in rule.config_types or ConfigType.GENERAL in rule.config_types:
                matches = re.finditer(rule.pattern, config_text, re.MULTILINE | re.DOTALL)
                
                for match in matches:
                    line_num = config_text[:match.start()].count('\n') + 1
                    
                    # Specific validation logic based on rule
                    issue = self._validate_specific_rule(rule, match, line_num, lines)
                    if issue:
                        issues.append(issue)
        
        return issues
    
    def _validate_specific_rule(self, rule: ValidationRule, match: re.Match, 
                               line_num: int, lines: List[str]) -> Optional[ValidationIssue]:
        """Validate specific rule match"""
        
        if rule.rule_id == "NO_SHUTDOWN_CHECK":
            # Check if interface has 'no shutdown'
            interface_config = match.group(0)
            if 'no shutdown' not in interface_config and 'shutdown' in interface_config:
                return ValidationIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line_number=line_num,
                    description="Interface is administratively shut down",
                    recommendation=rule.recommendation,
                    original_config=lines[line_num-1] if line_num <= len(lines) else "",
                    suggested_fix="Add 'no shutdown' command"
                )
        
        elif rule.rule_id == "IP_ADDRESS_FORMAT":
            # Validate IP address format
            ip_addr = match.group(1)
            subnet_mask = match.group(2)
            
            if not self._is_valid_ip(ip_addr) or not self._is_valid_subnet_mask(subnet_mask):
                return ValidationIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line_number=line_num,
                    description="Invalid IP address or subnet mask format",
                    recommendation=rule.recommendation,
                    original_config=lines[line_num-1] if line_num <= len(lines) else "",
                    suggested_fix="Use valid IP address format (e.g., 192.168.1.1 255.255.255.0)"
                )
        
        elif rule.rule_id == "VLAN_RANGE_CHECK":
            # Check VLAN range
            vlan_id = int(match.group(1))
            if vlan_id < 1 or vlan_id > 4094:
                return ValidationIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line_number=line_num,
                    description=f"VLAN ID {vlan_id} is out of valid range",
                    recommendation=rule.recommendation,
                    original_config=lines[line_num-1] if line_num <= len(lines) else "",
                    suggested_fix=f"Use VLAN ID between 1 and 4094"
                )
        
        elif rule.rule_id == "BGP_AS_RANGE":
            # Check BGP AS number
            as_number = int(match.group(1))
            if as_number < 1 or as_number > 4294967295:
                return ValidationIssue(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    line_number=line_num,
                    description=f"BGP AS number {as_number} is out of valid range",
                    recommendation=rule.recommendation,
                    original_config=lines[line_num-1] if line_num <= len(lines) else "",
                    suggested_fix="Use valid BGP AS number"
                )
        
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def _is_valid_subnet_mask(self, mask: str) -> bool:
        """Validate subnet mask format"""
        try:
            parts = mask.split('.')
            if len(parts) != 4:
                return False
            
            # Convert to binary and check for contiguous 1s
            binary = ''
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
                binary += format(int(part), '08b')
            
            # Check for contiguous 1s followed by 0s
            ones_ended = False
            for bit in binary:
                if bit == '0':
                    ones_ended = True
                elif bit == '1' and ones_ended:
                    return False
            
            return True
        except:
            return False
    
    def check_best_practices(self, config_text: str) -> List[BestPracticeCheck]:
        """Check configuration against best practices"""
        checks = []
        
        for rule in self.best_practice_rules:
            # Find all occurrences of the pattern
            pattern_matches = list(re.finditer(rule['pattern'], config_text, re.MULTILINE | re.DOTALL))
            
            if pattern_matches:
                # Check if requirement is met for each match
                for match in pattern_matches:
                    config_section = match.group(0)
                    requirement_met = bool(re.search(rule['requirement'], config_section))
                    
                    if not requirement_met:
                        line_num = config_text[:match.start()].count('\n') + 1
                        checks.append(BestPracticeCheck(
                            check_id=rule['check_id'],
                            name=rule['name'],
                            passed=False,
                            severity=rule['severity'],
                            description=rule['description'],
                            recommendation=rule['recommendation'],
                            affected_lines=[line_num]
                        ))
                    else:
                        checks.append(BestPracticeCheck(
                            check_id=rule['check_id'],
                            name=rule['name'],
                            passed=True,
                            severity=ValidationSeverity.INFO,
                            description=f"{rule['name']} check passed",
                            recommendation="Best practice is being followed"
                        ))
            else:
                # Pattern not found - might be missing entirely
                if rule['check_id'] in ['BANNER_MOTD', 'NTP_CONFIGURATION']:
                    checks.append(BestPracticeCheck(
                        check_id=rule['check_id'],
                        name=rule['name'],
                        passed=False,
                        severity=rule['severity'],
                        description=f"{rule['name']} configuration is missing",
                        recommendation=rule['recommendation']
                    ))
        
        return checks

class RiskAnalyzer:
    """Configuration change risk analysis"""
    
    def __init__(self):
        self.risk_factors = self._initialize_risk_factors()
        
    def _initialize_risk_factors(self) -> Dict[str, Dict[str, Any]]:
        """Initialize risk assessment factors"""
        return {
            'protocol_changes': {
                'risk_level': RiskLevel.HIGH,
                'patterns': [r'router\s+(ospf|bgp|eigrp)', r'redistribute', r'default-information'],
                'description': 'Changes to routing protocols can affect network convergence'
            },
            'interface_changes': {
                'risk_level': RiskLevel.MEDIUM,
                'patterns': [r'interface\s+', r'ip address', r'shutdown', r'no shutdown'],
                'description': 'Interface changes can affect connectivity'
            },
            'security_changes': {
                'risk_level': RiskLevel.HIGH,
                'patterns': [r'access-list', r'ip access-group', r'authentication', r'password'],
                'description': 'Security changes can affect device access and authentication'
            },
            'vlan_changes': {
                'risk_level': RiskLevel.MEDIUM,
                'patterns': [r'vlan\s+\d+', r'switchport', r'trunk'],
                'description': 'VLAN changes can affect Layer 2 connectivity'
            },
            'critical_services': {
                'risk_level': RiskLevel.CRITICAL,
                'patterns': [r'no\s+(cdp|lldp|spanning-tree)', r'errdisable'],
                'description': 'Changes to critical services can cause network outages'
            }
        }
    
    def assess_risk(self, config_text: str, target_devices: List[str]) -> RiskAssessment:
        """Assess risk of configuration changes"""
        risk_factors = []
        overall_risk = RiskLevel.LOW
        
        # Analyze configuration for risk factors
        for factor_name, factor_info in self.risk_factors.items():
            for pattern in factor_info['patterns']:
                if re.search(pattern, config_text, re.IGNORECASE):
                    risk_factors.append(f"{factor_name}: {factor_info['description']}")
                    if factor_info['risk_level'].value in ['high', 'critical']:
                        overall_risk = factor_info['risk_level']
                    elif overall_risk == RiskLevel.LOW and factor_info['risk_level'] == RiskLevel.MEDIUM:
                        overall_risk = RiskLevel.MEDIUM
        
        # Additional risk factors based on device count and type
        if len(target_devices) > 3:
            risk_factors.append("Multiple device deployment increases complexity")
            if overall_risk == RiskLevel.LOW:
                overall_risk = RiskLevel.MEDIUM
        
        # Check for spine devices (higher risk)
        spine_devices = [d for d in target_devices if 'SPINE' in d.upper()]
        if spine_devices:
            risk_factors.append("Changes to spine devices affect entire network")
            if overall_risk in [RiskLevel.LOW, RiskLevel.MEDIUM]:
                overall_risk = RiskLevel.HIGH
        
        # Generate mitigation steps
        mitigation_steps = self._generate_mitigation_steps(risk_factors, overall_risk)
        
        # Generate rollback plan
        rollback_plan = self._generate_rollback_plan(config_text, target_devices)
        
        # Impact analysis
        impact_analysis = self._generate_impact_analysis(risk_factors, target_devices)
        
        # Deployment windows
        deployment_windows = self._suggest_deployment_windows(overall_risk)
        
        return RiskAssessment(
            overall_risk=overall_risk,
            risk_factors=risk_factors,
            mitigation_steps=mitigation_steps,
            rollback_plan=rollback_plan,
            impact_analysis=impact_analysis,
            deployment_windows=deployment_windows
        )
    
    def _generate_mitigation_steps(self, risk_factors: List[str], risk_level: RiskLevel) -> List[str]:
        """Generate risk mitigation steps"""
        steps = [
            "Perform pre-deployment validation and testing",
            "Take configuration backup before changes",
            "Deploy during maintenance window",
            "Monitor network metrics during deployment"
        ]
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            steps.extend([
                "Notify network operations center (NOC)",
                "Have rollback plan ready for immediate execution",
                "Deploy to single device first as pilot",
                "Keep experienced engineer on standby"
            ])
        
        if risk_level == RiskLevel.CRITICAL:
            steps.extend([
                "Coordinate with business stakeholders",
                "Prepare emergency response procedures",
                "Consider phased deployment approach"
            ])
        
        return steps
    
    def _generate_rollback_plan(self, config_text: str, target_devices: List[str]) -> str:
        """Generate rollback plan"""
        return f"""
ROLLBACK PLAN:
1. Immediately restore previous configuration from backup
2. Verify device connectivity and basic functionality
3. Check routing protocol convergence
4. Validate critical services are operational
5. Notify stakeholders of rollback completion

ROLLBACK COMMANDS:
- configure replace startup-config force
- copy backup-config running-config
- reload in 10 (with saved configuration)

ESTIMATED ROLLBACK TIME: 5-15 minutes per device
DEVICES AFFECTED: {', '.join(target_devices)}
"""
    
    def _generate_impact_analysis(self, risk_factors: List[str], target_devices: List[str]) -> str:
        """Generate impact analysis"""
        impact = f"IMPACT ANALYSIS:\n"
        impact += f"Devices Affected: {len(target_devices)} ({', '.join(target_devices)})\n"
        
        if any('spine' in factor.lower() for factor in risk_factors):
            impact += "HIGH IMPACT: Spine device changes affect entire network fabric\n"
        elif len(target_devices) > 2:
            impact += "MEDIUM-HIGH IMPACT: Multiple device changes\n"
        else:
            impact += "LOW-MEDIUM IMPACT: Limited device scope\n"
        
        impact += f"\nRisk Factors Identified: {len(risk_factors)}\n"
        for factor in risk_factors:
            impact += f"- {factor}\n"
        
        return impact
    
    def _suggest_deployment_windows(self, risk_level: RiskLevel) -> List[str]:
        """Suggest appropriate deployment windows"""
        if risk_level == RiskLevel.CRITICAL:
            return [
                "Emergency maintenance window only",
                "Coordinate with all stakeholders",
                "Business approval required"
            ]
        elif risk_level == RiskLevel.HIGH:
            return [
                "Scheduled maintenance window",
                "Low traffic periods (2 AM - 6 AM)",
                "Weekend deployment preferred"
            ]
        elif risk_level == RiskLevel.MEDIUM:
            return [
                "Maintenance window recommended",
                "Off-peak hours acceptable",
                "Weekday evening (after business hours)"
            ]
        else:
            return [
                "Any time acceptable",
                "Business hours deployment okay for low-risk changes",
                "Consider user impact minimal"
            ]

class ConfigurationGenerator:
    """Main configuration generation engine"""
    
    def __init__(self):
        self.parser = ConfigurationParser()
        self.validator = ConfigurationValidator()
        self.risk_analyzer = RiskAnalyzer()
        self.template_generators = self._initialize_template_generators()
        
    def _initialize_template_generators(self) -> Dict[ConfigType, callable]:
        """Initialize configuration template generators"""
        return {
            ConfigType.INTERFACE: self._generate_interface_config,
            ConfigType.ROUTING: self._generate_routing_config,
            ConfigType.VLAN: self._generate_vlan_config,
            ConfigType.SECURITY: self._generate_security_config,
            ConfigType.QOS: self._generate_qos_config,
            ConfigType.MONITORING: self._generate_monitoring_config,
            ConfigType.GENERAL: self._generate_general_config
        }
    
    def generate_configuration(self, description: str, target_devices: List[str] = None) -> GeneratedConfiguration:
        """
        Generate network configuration from natural language description
        
        Args:
            description: Natural language description of desired configuration
            target_devices: Optional list of target devices
            
        Returns:
            GeneratedConfiguration: Complete configuration with validation and risk assessment
        """
        logger.info(f"Generating configuration: {description}")
        
        try:
            # Parse the request
            request = self.parser.parse_request(description)
            
            # Override target devices if provided
            if target_devices:
                request.target_devices = target_devices
            
            # If no devices specified, get from topology
            if not request.target_devices:
                topology = get_network_topology()
                if 'devices' in topology:
                    request.target_devices = [d['name'] for d in topology['devices']]
            
            # Generate configuration for each device
            generated_configs = {}
            all_validation_issues = []
            all_best_practice_checks = []
            
            for device_name in request.target_devices:
                # Generate device-specific configuration
                device_config = self._generate_device_config(request, device_name)
                generated_configs[device_name] = device_config
                
                # Validate configuration
                validation_issues = self.validator.validate_configuration(device_config, request.config_type)
                all_validation_issues.extend(validation_issues)
                
                # Check best practices
                best_practice_checks = self.validator.check_best_practices(device_config)
                all_best_practice_checks.extend(best_practice_checks)
            
            # Assess risk
            combined_config = '\n'.join(generated_configs.values())
            risk_assessment = self.risk_analyzer.assess_risk(combined_config, request.target_devices)
            
            # Create deployment plan
            deployment_plan = self._create_deployment_plan(request, risk_assessment)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                all_validation_issues, all_best_practice_checks, risk_assessment
            )
            
            # Create result
            result = GeneratedConfiguration(
                config_id=f"GC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                request=request,
                generated_config=generated_configs,
                validation_issues=all_validation_issues,
                best_practice_checks=all_best_practice_checks,
                risk_assessment=risk_assessment,
                deployment_plan=deployment_plan,
                confidence_score=confidence_score,
                timestamp=datetime.now().isoformat()
            )
            
            logger.info(f"Configuration generation completed: {len(generated_configs)} devices")
            return result
            
        except Exception as e:
            logger.error(f"Configuration generation failed: {e}")
            # Return error result
            return GeneratedConfiguration(
                config_id=f"GC-ERROR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                request=ConfigurationRequest(
                    request_id="ERROR",
                    description=description,
                    target_devices=target_devices or [],
                    config_type=ConfigType.GENERAL,
                    timestamp=datetime.now().isoformat()
                ),
                generated_config={},
                validation_issues=[],
                best_practice_checks=[],
                risk_assessment=RiskAssessment(
                    overall_risk=RiskLevel.CRITICAL,
                    risk_factors=[f"Configuration generation error: {str(e)}"],
                    mitigation_steps=["Fix configuration generation system"],
                    rollback_plan="No configuration was generated",
                    impact_analysis="Unable to generate configuration"
                ),
                deployment_plan=DeploymentPlan(
                    plan_id="ERROR",
                    deployment_order=[],
                    pre_checks=["Fix generation system"],
                    post_checks=[],
                    estimated_duration="N/A"
                ),
                confidence_score=0.0,
                timestamp=datetime.now().isoformat()
            )
    
    def _generate_device_config(self, request: ConfigurationRequest, device_name: str) -> str:
        """Generate configuration for specific device"""
        
        # Get device details
        device_details = get_device_details(device_name)
        
        # Get appropriate generator
        generator = self.template_generators.get(request.config_type, self._generate_general_config)
        
        # Generate configuration
        config = generator(request, device_name, device_details)
        
        return config
    
    def _generate_interface_config(self, request: ConfigurationRequest, device_name: str, device_details: Dict) -> str:
        """Generate interface configuration"""
        config_lines = [
            f"! Interface configuration for {device_name}",
            f"! Generated from: {request.description}",
            "!"
        ]
        
        # Parse interface requirements from description
        description = request.description.lower()
        
        if "loopback" in description:
            # Extract loopback number and IP
            loopback_match = re.search(r"loopback\s*(\d+)", description)
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)", description)
            
            loopback_num = loopback_match.group(1) if loopback_match else "0"
            ip_addr = ip_match.group(1) if ip_match else "10.0.0.1/32"
            
            if "/" in ip_addr:
                ip, prefix = ip_addr.split("/")
                mask = self._prefix_to_mask(int(prefix))
            else:
                ip, mask = ip_addr, "255.255.255.255"
            
            config_lines.extend([
                f"interface loopback{loopback_num}",
                f" description {request.description}",
                f" ip address {ip} {mask}",
                " no shutdown",
                "!"
            ])
        
        elif any(keyword in description for keyword in ["ethernet", "gigabit", "interface"]):
            # Extract interface name and configuration
            intf_match = re.search(r"(ethernet|gigabitethernet|ge|eth)[\s]*(\d+/\d+|\d+)", description)
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)", description)
            
            if intf_match:
                intf_type = "GigabitEthernet" if "gigabit" in intf_match.group(1).lower() else "Ethernet"
                intf_num = intf_match.group(2)
                interface_name = f"{intf_type}{intf_num}"
                
                config_lines.extend([
                    f"interface {interface_name}",
                    f" description {request.description}"
                ])
                
                if ip_match:
                    ip_addr = ip_match.group(1)
                    if "/" in ip_addr:
                        ip, prefix = ip_addr.split("/")
                        mask = self._prefix_to_mask(int(prefix))
                    else:
                        ip, mask = ip_addr, "255.255.255.0"
                    
                    config_lines.extend([
                        " no switchport",
                        f" ip address {ip} {mask}"
                    ])
                
                if "shutdown" not in description or "no shutdown" in description:
                    config_lines.append(" no shutdown")
                
                config_lines.append("!")
        
        return '\n'.join(config_lines)
    
    def _generate_routing_config(self, request: ConfigurationRequest, device_name: str, device_details: Dict) -> str:
        """Generate routing protocol configuration"""
        config_lines = [
            f"! Routing configuration for {device_name}",
            f"! Generated from: {request.description}",
            "!"
        ]
        
        description = request.description.lower()
        
        if "ospf" in description:
            # Extract OSPF process ID and networks
            process_match = re.search(r"ospf\s*(\d+)", description)
            process_id = process_match.group(1) if process_match else "1"
            
            config_lines.extend([
                f"router ospf {process_id}",
                f" router-id {self._get_device_router_id(device_name)}"
            ])
            
            # Add network statements based on description
            if "network" in description:
                network_matches = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)", description)
                for network in network_matches:
                    if "/" in network:
                        net, prefix = network.split("/")
                        wildcard = self._prefix_to_wildcard(int(prefix))
                    else:
                        net, wildcard = network, "0.0.0.255"
                    
                    area = "0"  # Default area
                    config_lines.append(f" network {net} {wildcard} area {area}")
            
            config_lines.append("!")
        
        elif "bgp" in description:
            # Extract BGP AS number
            as_match = re.search(r"as\s*(\d+)|bgp\s*(\d+)", description)
            as_number = as_match.group(1) or as_match.group(2) if as_match else "65000"
            
            config_lines.extend([
                f"router bgp {as_number}",
                f" bgp router-id {self._get_device_router_id(device_name)}",
                " bgp log-neighbor-changes"
            ])
            
            # Add neighbor configuration if specified
            if "neighbor" in description:
                neighbor_matches = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", description)
                for neighbor in neighbor_matches:
                    config_lines.extend([
                        f" neighbor {neighbor} remote-as {as_number}",
                        f" neighbor {neighbor} update-source loopback0"
                    ])
            
            config_lines.append("!")
        
        elif "static" in description or "route" in description:
            # Extract static route information
            route_matches = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)", description)
            if len(route_matches) >= 2:
                network = route_matches[0]
                next_hop = route_matches[1]
                
                if "/" in network:
                    net, prefix = network.split("/")
                    mask = self._prefix_to_mask(int(prefix))
                else:
                    net, mask = network, "255.255.255.0"
                
                config_lines.extend([
                    f"ip route {net} {mask} {next_hop}",
                    "!"
                ])
        
        return '\n'.join(config_lines)
    
    def _generate_vlan_config(self, request: ConfigurationRequest, device_name: str, device_details: Dict) -> str:
        """Generate VLAN configuration"""
        config_lines = [
            f"! VLAN configuration for {device_name}",
            f"! Generated from: {request.description}",
            "!"
        ]
        
        description = request.description.lower()
        
        # Extract VLAN ID and name
        vlan_match = re.search(r"vlan\s*(\d+)", description)
        name_match = re.search(r"name\s+(\w+)|(\w+)\s+vlan", description)
        
        if vlan_match:
            vlan_id = vlan_match.group(1)
            vlan_name = name_match.group(1) or name_match.group(2) if name_match else f"VLAN{vlan_id}"
            
            config_lines.extend([
                f"vlan {vlan_id}",
                f" name {vlan_name}",
                "!"
            ])
            
            # Add interface configuration if specified
            if any(keyword in description for keyword in ["access", "trunk", "switchport"]):
                intf_match = re.search(r"(ethernet|gigabitethernet|ge|eth)[\s]*(\d+/\d+|\d+)", description)
                if intf_match:
                    intf_type = "GigabitEthernet" if "gigabit" in intf_match.group(1).lower() else "Ethernet"
                    intf_num = intf_match.group(2)
                    interface_name = f"{intf_type}{intf_num}"
                    
                    config_lines.extend([
                        f"interface {interface_name}",
                        f" description {request.description}",
                        " switchport"
                    ])
                    
                    if "access" in description:
                        config_lines.append(f" switchport access vlan {vlan_id}")
                    elif "trunk" in description:
                        config_lines.extend([
                            " switchport mode trunk",
                            f" switchport trunk allowed vlan {vlan_id}"
                        ])
                    
                    config_lines.extend([
                        " no shutdown",
                        "!"
                    ])
        
        return '\n'.join(config_lines)
    
    def _generate_security_config(self, request: ConfigurationRequest, device_name: str, device_details: Dict) -> str:
        """Generate security configuration"""
        config_lines = [
            f"! Security configuration for {device_name}",
            f"! Generated from: {request.description}",
            "!"
        ]
        
        description = request.description.lower()
        
        if "access-list" in description or "acl" in description:
            # Extract ACL information
            acl_match = re.search(r"access-list\s*(\d+)|acl\s*(\d+)", description)
            acl_num = acl_match.group(1) or acl_match.group(2) if acl_match else "100"
            
            config_lines.extend([
                f"access-list {acl_num} remark {request.description}",
                f"access-list {acl_num} permit ip any any",
                "!"
            ])
        
        elif "ssh" in description:
            config_lines.extend([
                "ip domain-name example.com",
                "crypto key generate rsa modulus 1024",
                "ip ssh version 2",
                "username admin privilege 15 secret cisco123",
                "line vty 0 15",
                " transport input ssh",
                " login local",
                "!"
            ])
        
        return '\n'.join(config_lines)
    
    def _generate_qos_config(self, request: ConfigurationRequest, device_name: str, device_details: Dict) -> str:
        """Generate QoS configuration"""
        config_lines = [
            f"! QoS configuration for {device_name}",
            f"! Generated from: {request.description}",
            "!"
        ]
        
        # Basic QoS template
        config_lines.extend([
            "class-map match-all VOICE",
            " match dscp ef",
            "!",
            "policy-map QOS-POLICY",
            " class VOICE",
            "  priority percent 20",
            " class class-default",
            "  fair-queue",
            "!"
        ])
        
        return '\n'.join(config_lines)
    
    def _generate_monitoring_config(self, request: ConfigurationRequest, device_name: str, device_details: Dict) -> str:
        """Generate monitoring configuration"""
        config_lines = [
            f"! Monitoring configuration for {device_name}",
            f"! Generated from: {request.description}",
            "!"
        ]
        
        description = request.description.lower()
        
        if "snmp" in description:
            config_lines.extend([
                "snmp-server community public RO",
                "snmp-server community private RW",
                "snmp-server location Network Lab",
                "snmp-server contact admin@example.com",
                "!"
            ])
        
        if "logging" in description or "syslog" in description:
            config_lines.extend([
                "logging buffered 4096",
                "logging console warnings",
                "logging monitor informational",
                "!"
            ])
        
        return '\n'.join(config_lines)
    
    def _generate_general_config(self, request: ConfigurationRequest, device_name: str, device_details: Dict) -> str:
        """Generate general configuration"""
        config_lines = [
            f"! General configuration for {device_name}",
            f"! Generated from: {request.description}",
            "!",
            f"hostname {device_name}",
            "!"
        ]
        
        return '\n'.join(config_lines)
    
    def _get_device_router_id(self, device_name: str) -> str:
        """Get router ID for device"""
        # Simple router ID assignment based on device name
        device_map = {
            'SPINE1': '1.1.1.1',
            'SPINE2': '2.2.2.2',
            'LEAF1': '11.11.11.11',
            'LEAF2': '12.12.12.12',
            'LEAF3': '13.13.13.13',
            'LEAF4': '14.14.14.14'
        }
        return device_map.get(device_name, '10.0.0.1')
    
    def _prefix_to_mask(self, prefix: int) -> str:
        """Convert prefix length to subnet mask"""
        mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return f"{(mask_int >> 24) & 0xFF}.{(mask_int >> 16) & 0xFF}.{(mask_int >> 8) & 0xFF}.{mask_int & 0xFF}"
    
    def _prefix_to_wildcard(self, prefix: int) -> str:
        """Convert prefix length to wildcard mask"""
        wildcard_int = 0xFFFFFFFF >> prefix
        return f"{(wildcard_int >> 24) & 0xFF}.{(wildcard_int >> 16) & 0xFF}.{(wildcard_int >> 8) & 0xFF}.{wildcard_int & 0xFF}"
    
    def _create_deployment_plan(self, request: ConfigurationRequest, risk_assessment: RiskAssessment) -> DeploymentPlan:
        """Create deployment plan"""
        
        # Determine deployment order (spine devices last for high-risk changes)
        deployment_order = request.target_devices.copy()
        if risk_assessment.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            # Deploy to leaf devices first, then spine devices
            leaf_devices = [d for d in deployment_order if 'LEAF' in d.upper()]
            spine_devices = [d for d in deployment_order if 'SPINE' in d.upper()]
            deployment_order = leaf_devices + spine_devices
        
        # Define pre-checks and post-checks
        pre_checks = [
            "Verify device connectivity and SSH access",
            "Take configuration backup",
            "Check current network status and routing tables",
            "Verify no ongoing maintenance or issues"
        ]
        
        post_checks = [
            "Verify configuration applied successfully",
            "Check device connectivity and basic functionality",
            "Validate routing protocol convergence",
            "Confirm no new alarms or errors",
            "Test end-to-end connectivity"
        ]
        
        # Estimate duration based on complexity and device count
        base_time = 5  # minutes per device
        complexity_multiplier = {
            ConfigType.ROUTING: 2.0,
            ConfigType.SECURITY: 1.5,
            ConfigType.INTERFACE: 1.2,
            ConfigType.VLAN: 1.0,
            ConfigType.QOS: 1.3,
            ConfigType.MONITORING: 1.1,
            ConfigType.GENERAL: 1.0
        }
        
        estimated_minutes = base_time * len(deployment_order) * complexity_multiplier.get(request.config_type, 1.0)
        if risk_assessment.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            estimated_minutes *= 1.5  # Additional time for high-risk deployments
        
        estimated_duration = f"{int(estimated_minutes)} minutes"
        
        return DeploymentPlan(
            plan_id=f"DP-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            deployment_order=deployment_order,
            pre_checks=pre_checks,
            post_checks=post_checks,
            estimated_duration=estimated_duration,
            maintenance_window="TBD - coordinate with operations team",
            contact_information="Network Operations: ext-1234"
        )
    
    def _calculate_confidence_score(self, validation_issues: List[ValidationIssue], 
                                  best_practice_checks: List[BestPracticeCheck], 
                                  risk_assessment: RiskAssessment) -> float:
        """Calculate confidence score for generated configuration"""
        
        base_score = 1.0
        
        # Reduce score for validation issues
        error_count = len([i for i in validation_issues if i.severity == ValidationSeverity.ERROR])
        warning_count = len([i for i in validation_issues if i.severity == ValidationSeverity.WARNING])
        
        base_score -= (error_count * 0.2)  # -20% per error
        base_score -= (warning_count * 0.1)  # -10% per warning
        
        # Reduce score for failed best practice checks
        failed_checks = len([c for c in best_practice_checks if not c.passed])
        base_score -= (failed_checks * 0.05)  # -5% per failed check
        
        # Adjust for risk level
        risk_penalty = {
            RiskLevel.LOW: 0.0,
            RiskLevel.MEDIUM: 0.1,
            RiskLevel.HIGH: 0.2,
            RiskLevel.CRITICAL: 0.3
        }
        base_score -= risk_penalty.get(risk_assessment.overall_risk, 0.0)
        
        # Ensure score stays within bounds
        return max(0.0, min(1.0, base_score))

# MCP Tool Functions
def generate_configuration(description: str, target_devices: str = "") -> Dict[str, Any]:
    """
    AI-powered configuration generation tool for MCP integration
    
    Args:
        description: Natural language description of desired configuration
        target_devices: Comma-separated list of target devices (optional)
        
    Returns:
        Dict containing generated configuration and analysis
    """
    try:
        # Parse target devices
        device_list = []
        if target_devices:
            device_list = [device.strip() for device in target_devices.split(',')]
        
        # Create generator and generate configuration
        generator = ConfigurationGenerator()
        result = generator.generate_configuration(description, device_list)
        
        # Convert to dictionary for MCP response
        result_dict = asdict(result)
        
        # Convert enums to strings for JSON serialization
        def convert_enums(obj):
            if isinstance(obj, dict):
                return {k: convert_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums(item) for item in obj]
            elif isinstance(obj, (ConfigType, RiskLevel, ValidationSeverity)):
                return obj.value
            else:
                return obj
        
        result_dict = convert_enums(result_dict)
        
        return {
            'success': True,
            'configuration': result_dict,
            'message': f"Configuration generated for {len(result.generated_config)} devices"
        }
        
    except Exception as e:
        logger.error(f"MCP generate_configuration failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': f"Configuration generation failed: {str(e)}"
        }

if __name__ == "__main__":
    # Test the configuration generator
    generator = ConfigurationGenerator()
    
    # Test interface configuration
    result = generator.generate_configuration(
        "Configure loopback0 interface with IP address 10.1.1.1/32 on LEAF1"
    )
    
    print("Generated Configuration:")
    print(json.dumps(asdict(result), indent=2))
