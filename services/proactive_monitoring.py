#!/usr/bin/env python3
"""
Proactive Network Monitoring and Alerting Service

Implements continuous network monitoring with intelligent alerting,
threshold-based and anomaly-based alert generation, and alert prioritization
with escalation logic for network automation.
"""

import os
import sys
import json
import yaml
import logging
import asyncio
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
import threading
from pathlib import Path
from collections import defaultdict, deque
try:
    import smtplib
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import network services
from services.network_context_engine import NetworkContextEngine, NetworkAlert, AlertSeverity, DeviceState
from services.network_status_tool import get_network_status
from services.device_details_tool import get_device_details

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# File paths
MONITORING_CONFIG_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/config/monitoring_config.yaml'
ALERT_HISTORY_DB = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/alert_history.db'
ESCALATION_LOG = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/escalation.log'


class AlertPriority(Enum):
    """Alert priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class AlertStatus(Enum):
    """Alert status tracking"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    SUPPRESSED = "suppressed"


class NotificationType(Enum):
    """Notification delivery methods"""
    EMAIL = "email"
    WEBHOOK = "webhook"
    SMS = "sms"
    SLACK = "slack"
    TEAMS = "teams"


@dataclass
class AlertRule:
    """Alert rule configuration"""
    rule_id: str
    name: str
    description: str
    metric_type: str  # cpu, memory, interface, protocol, connectivity
    threshold_type: str  # static, dynamic, anomaly
    threshold_value: float
    comparison: str  # gt, lt, eq, ne
    duration: int  # seconds the condition must persist
    priority: AlertPriority
    enabled: bool = True
    device_filter: Optional[str] = None  # regex pattern for device names
    interface_filter: Optional[str] = None  # regex pattern for interfaces
    suppress_duration: int = 300  # seconds to suppress duplicate alerts


@dataclass
class EscalationRule:
    """Alert escalation configuration"""
    rule_id: str
    alert_priority: AlertPriority
    escalation_delay: int  # seconds before escalation
    escalation_levels: List[Dict[str, Any]]  # notification configs per level
    max_escalations: int = 3
    auto_resolve: bool = False
    resolve_timeout: int = 3600  # auto-resolve timeout in seconds


@dataclass
class ProactiveAlert:
    """Enhanced alert with prioritization and escalation tracking"""
    alert_id: str
    severity: AlertSeverity
    priority: AlertPriority
    status: AlertStatus
    alert_type: str
    device_name: str
    metric_name: str
    current_value: float
    threshold_value: float
    message: str
    timestamp: datetime
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    escalation_level: int = 0
    escalated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    suppressed_until: Optional[datetime] = None
    correlation_id: Optional[str] = None  # For grouping related alerts
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'alert_id': self.alert_id,
            'severity': self.severity.value if isinstance(self.severity, AlertSeverity) else self.severity,
            'priority': self.priority.value if isinstance(self.priority, AlertPriority) else self.priority,
            'status': self.status.value if isinstance(self.status, AlertStatus) else self.status,
            'alert_type': self.alert_type,
            'device_name': self.device_name,
            'metric_name': self.metric_name,
            'current_value': self.current_value,
            'threshold_value': self.threshold_value,
            'message': self.message,
            'timestamp': self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            'acknowledged_by': self.acknowledged_by,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'escalation_level': self.escalation_level,
            'escalated_at': self.escalated_at.isoformat() if self.escalated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'suppressed_until': self.suppressed_until.isoformat() if self.suppressed_until else None,
            'correlation_id': self.correlation_id
        }


class ProactiveMonitoringService:
    """Proactive network monitoring service with intelligent alerting"""
    
    def __init__(self):
        self.context_engine = NetworkContextEngine()
        self.running = False
        self.monitoring_thread = None
        self.escalation_thread = None
        
        # Alert tracking
        self.active_alerts: Dict[str, ProactiveAlert] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.escalation_rules: Dict[AlertPriority, EscalationRule] = {}
        
        # Suppression tracking
        self.suppression_cache: Dict[str, datetime] = {}
        
        # Configuration
        self.config = self._load_configuration()
        
        # Initialize database
        self._init_database()
        
        # Load rules
        self._load_alert_rules()
        self._load_escalation_rules()
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load monitoring configuration"""
        default_config = {
            'monitoring_interval': 60,
            'escalation_check_interval': 300,
            'alert_correlation_window': 300,
            'max_alerts_per_device': 10,
            'notification_settings': {
                'email': {
                    'enabled': False,
                    'smtp_server': 'localhost',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'from_address': 'network-monitoring@company.com',
                    'default_recipients': []
                },
                'webhook': {
                    'enabled': False,
                    'url': '',
                    'headers': {},
                    'timeout': 30
                }
            }
        }
        
        try:
            if os.path.exists(MONITORING_CONFIG_FILE):
                with open(MONITORING_CONFIG_FILE, 'r') as f:
                    config = yaml.safe_load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                return config
            else:
                # Create default config file
                os.makedirs(os.path.dirname(MONITORING_CONFIG_FILE), exist_ok=True)
                with open(MONITORING_CONFIG_FILE, 'w') as f:
                    yaml.dump(default_config, f, default_flow_style=False)
                return default_config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return default_config
    
    def _init_database(self):
        """Initialize alert history database"""
        try:
            os.makedirs(os.path.dirname(ALERT_HISTORY_DB), exist_ok=True)
            
            with sqlite3.connect(ALERT_HISTORY_DB) as conn:
                cursor = conn.cursor()
                
                # Create alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alert_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_id TEXT UNIQUE,
                        severity TEXT,
                        priority INTEGER,
                        status TEXT,
                        alert_type TEXT,
                        device_name TEXT,
                        metric_name TEXT,
                        current_value REAL,
                        threshold_value REAL,
                        message TEXT,
                        timestamp TEXT,
                        acknowledged_by TEXT,
                        acknowledged_at TEXT,
                        escalation_level INTEGER,
                        escalated_at TEXT,
                        resolved_at TEXT,
                        correlation_id TEXT
                    )
                ''')
                
                # Create escalation log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS escalation_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_id TEXT,
                        escalation_level INTEGER,
                        escalated_at TEXT,
                        notification_type TEXT,
                        notification_target TEXT,
                        success BOOLEAN,
                        error_message TEXT
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alert_history(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_device ON alert_history(device_name)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_status ON alert_history(status)')
                
                conn.commit()
                logger.info("Alert history database initialized")
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
    
    def _load_alert_rules(self):
        """Load alert rules from configuration"""
        default_rules = [
            AlertRule(
                rule_id="cpu_high",
                name="High CPU Usage",
                description="CPU usage exceeds threshold",
                metric_type="cpu",
                threshold_type="static",
                threshold_value=80.0,
                comparison="gt",
                duration=300,
                priority=AlertPriority.HIGH,
                suppress_duration=600
            ),
            AlertRule(
                rule_id="cpu_critical",
                name="Critical CPU Usage",
                description="CPU usage critically high",
                metric_type="cpu",
                threshold_type="static",
                threshold_value=95.0,
                comparison="gt",
                duration=60,
                priority=AlertPriority.CRITICAL,
                suppress_duration=300
            ),
            AlertRule(
                rule_id="memory_high",
                name="High Memory Usage",
                description="Memory usage exceeds threshold",
                metric_type="memory",
                threshold_type="static",
                threshold_value=85.0,
                comparison="gt",
                duration=300,
                priority=AlertPriority.HIGH,
                suppress_duration=600
            ),
            AlertRule(
                rule_id="memory_critical",
                name="Critical Memory Usage",
                description="Memory usage critically high",
                metric_type="memory",
                threshold_type="static",
                threshold_value=95.0,
                comparison="gt",
                duration=60,
                priority=AlertPriority.CRITICAL,
                suppress_duration=300
            ),
            AlertRule(
                rule_id="device_unreachable",
                name="Device Unreachable",
                description="Device is not responding",
                metric_type="connectivity",
                threshold_type="static",
                threshold_value=0,
                comparison="eq",
                duration=120,
                priority=AlertPriority.CRITICAL,
                suppress_duration=300
            ),
            AlertRule(
                rule_id="interface_down",
                name="Interface Down",
                description="Critical interface is down",
                metric_type="interface",
                threshold_type="static",
                threshold_value=0,
                comparison="eq",
                duration=60,
                priority=AlertPriority.HIGH,
                suppress_duration=300,
                interface_filter="Ethernet|GigabitEthernet|TenGigabitEthernet"
            )
        ]
        
        # Store rules
        for rule in default_rules:
            self.alert_rules[rule.rule_id] = rule
        
        logger.info(f"Loaded {len(self.alert_rules)} alert rules")
    
    def _load_escalation_rules(self):
        """Load escalation rules from configuration"""
        default_escalations = [
            EscalationRule(
                rule_id="critical_escalation",
                alert_priority=AlertPriority.CRITICAL,
                escalation_delay=300,  # 5 minutes
                escalation_levels=[
                    {
                        'level': 1,
                        'notifications': [
                            {'type': NotificationType.EMAIL, 'targets': ['admin@company.com']},
                            {'type': NotificationType.WEBHOOK, 'targets': ['http://monitoring.company.com/webhook']}
                        ]
                    },
                    {
                        'level': 2,
                        'notifications': [
                            {'type': NotificationType.EMAIL, 'targets': ['manager@company.com', 'oncall@company.com']},
                        ]
                    },
                    {
                        'level': 3,
                        'notifications': [
                            {'type': NotificationType.EMAIL, 'targets': ['director@company.com']},
                        ]
                    }
                ],
                max_escalations=3,
                auto_resolve=False
            ),
            EscalationRule(
                rule_id="high_escalation",
                alert_priority=AlertPriority.HIGH,
                escalation_delay=900,  # 15 minutes
                escalation_levels=[
                    {
                        'level': 1,
                        'notifications': [
                            {'type': NotificationType.EMAIL, 'targets': ['admin@company.com']}
                        ]
                    },
                    {
                        'level': 2,
                        'notifications': [
                            {'type': NotificationType.EMAIL, 'targets': ['manager@company.com']}
                        ]
                    }
                ],
                max_escalations=2,
                auto_resolve=True,
                resolve_timeout=3600
            ),
            EscalationRule(
                rule_id="medium_escalation",
                alert_priority=AlertPriority.MEDIUM,
                escalation_delay=1800,  # 30 minutes
                escalation_levels=[
                    {
                        'level': 1,
                        'notifications': [
                            {'type': NotificationType.EMAIL, 'targets': ['admin@company.com']}
                        ]
                    }
                ],
                max_escalations=1,
                auto_resolve=True,
                resolve_timeout=7200
            )
        ]
        
        # Store rules
        for rule in default_escalations:
            self.escalation_rules[rule.alert_priority] = rule
        
        logger.info(f"Loaded {len(self.escalation_rules)} escalation rules")
    
    def start_monitoring(self):
        """Start proactive monitoring service"""
        if self.running:
            return {"success": False, "message": "Monitoring already running"}
        
        self.running = True
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        # Start escalation thread
        self.escalation_thread = threading.Thread(target=self._escalation_loop, daemon=True)
        self.escalation_thread.start()
        
        # Start network context monitoring
        self.context_engine.start_monitoring()
        
        logger.info("Proactive monitoring service started")
        return {
            "success": True,
            "message": "Proactive monitoring service started",
            "monitoring_interval": self.config.get('monitoring_interval', 60),
            "escalation_interval": self.config.get('escalation_check_interval', 300),
            "active_rules": len(self.alert_rules)
        }
    
    def stop_monitoring(self):
        """Stop proactive monitoring service"""
        self.running = False
        
        # Stop context engine
        self.context_engine.stop_monitoring()
        
        # Wait for threads to finish
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10)
        
        if self.escalation_thread:
            self.escalation_thread.join(timeout=10)
        
        logger.info("Proactive monitoring service stopped")
        return {"success": True, "message": "Proactive monitoring service stopped"}
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                start_time = time.time()
                
                # Collect current network state
                network_status = get_network_status()
                
                if network_status.get('success'):
                    # Evaluate alert rules
                    new_alerts = self._evaluate_alert_rules(network_status['network_status'])
                    
                    # Process new alerts
                    for alert in new_alerts:
                        self._process_alert(alert)
                    
                    # Check for resolved alerts
                    self._check_resolved_alerts(network_status['network_status'])
                    
                    # Correlate alerts
                    self._correlate_alerts()
                
                # Calculate sleep time to maintain interval
                elapsed = time.time() - start_time
                sleep_time = max(0, self.config.get('monitoring_interval', 60) - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(30)
    
    def _escalation_loop(self):
        """Escalation checking loop"""
        while self.running:
            try:
                self._check_escalations()
                time.sleep(self.config.get('escalation_check_interval', 300))
                
            except Exception as e:
                logger.error(f"Error in escalation loop: {e}")
                time.sleep(60)
    
    def _evaluate_alert_rules(self, network_status: Dict[str, Any]) -> List[ProactiveAlert]:
        """Evaluate alert rules against current network status"""
        new_alerts = []
        current_time = datetime.now()
        
        # Get device status data
        device_status = network_status.get('device_status', {})
        
        for device_name, status in device_status.items():
            if status.get('reachable', False):
                # Check CPU rules
                cpu_usage = status.get('cpu_usage', 0)
                for rule_id, rule in self.alert_rules.items():
                    if rule.metric_type == 'cpu' and rule.enabled:
                        if self._evaluate_threshold(cpu_usage, rule):
                            alert_id = f"{rule_id}_{device_name}_{int(current_time.timestamp())}"
                            if not self._is_suppressed(rule_id, device_name, 'cpu'):
                                alert = ProactiveAlert(
                                    alert_id=alert_id,
                                    severity=self._priority_to_severity(rule.priority),
                                    priority=rule.priority,
                                    status=AlertStatus.NEW,
                                    alert_type=rule.alert_type if hasattr(rule, 'alert_type') else 'cpu_threshold',
                                    device_name=device_name,
                                    metric_name='cpu_usage',
                                    current_value=cpu_usage,
                                    threshold_value=rule.threshold_value,
                                    message=f"{rule.name}: CPU usage {cpu_usage}% exceeds threshold {rule.threshold_value}% on {device_name}",
                                    timestamp=current_time
                                )
                                new_alerts.append(alert)
                                self._set_suppression(rule_id, device_name, 'cpu', rule.suppress_duration)
                
                # Check Memory rules
                memory_usage = status.get('memory_usage', 0)
                for rule_id, rule in self.alert_rules.items():
                    if rule.metric_type == 'memory' and rule.enabled:
                        if self._evaluate_threshold(memory_usage, rule):
                            alert_id = f"{rule_id}_{device_name}_{int(current_time.timestamp())}"
                            if not self._is_suppressed(rule_id, device_name, 'memory'):
                                alert = ProactiveAlert(
                                    alert_id=alert_id,
                                    severity=self._priority_to_severity(rule.priority),
                                    priority=rule.priority,
                                    status=AlertStatus.NEW,
                                    alert_type=rule.alert_type if hasattr(rule, 'alert_type') else 'memory_threshold',
                                    device_name=device_name,
                                    metric_name='memory_usage',
                                    current_value=memory_usage,
                                    threshold_value=rule.threshold_value,
                                    message=f"{rule.name}: Memory usage {memory_usage}% exceeds threshold {rule.threshold_value}% on {device_name}",
                                    timestamp=current_time
                                )
                                new_alerts.append(alert)
                                self._set_suppression(rule_id, device_name, 'memory', rule.suppress_duration)
            
            else:
                # Device unreachable
                for rule_id, rule in self.alert_rules.items():
                    if rule.metric_type == 'connectivity' and rule.enabled:
                        alert_id = f"{rule_id}_{device_name}_{int(current_time.timestamp())}"
                        if not self._is_suppressed(rule_id, device_name, 'connectivity'):
                            alert = ProactiveAlert(
                                alert_id=alert_id,
                                severity=self._priority_to_severity(rule.priority),
                                priority=rule.priority,
                                status=AlertStatus.NEW,
                                alert_type=rule.alert_type if hasattr(rule, 'alert_type') else 'connectivity',
                                device_name=device_name,
                                metric_name='reachability',
                                current_value=0,
                                threshold_value=1,
                                message=f"{rule.name}: Device {device_name} is unreachable",
                                timestamp=current_time
                            )
                            new_alerts.append(alert)
                            self._set_suppression(rule_id, device_name, 'connectivity', rule.suppress_duration)
        
        return new_alerts
    
    def _evaluate_threshold(self, value: float, rule: AlertRule) -> bool:
        """Evaluate if a value triggers an alert rule"""
        if rule.comparison == 'gt':
            return value > rule.threshold_value
        elif rule.comparison == 'lt':
            return value < rule.threshold_value
        elif rule.comparison == 'eq':
            return value == rule.threshold_value
        elif rule.comparison == 'ne':
            return value != rule.threshold_value
        else:
            return False
    
    def _priority_to_severity(self, priority: AlertPriority) -> AlertSeverity:
        """Map alert priority to severity"""
        if priority in [AlertPriority.CRITICAL, AlertPriority.EMERGENCY]:
            return AlertSeverity.CRITICAL
        elif priority == AlertPriority.HIGH:
            return AlertSeverity.HIGH
        elif priority == AlertPriority.MEDIUM:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def _is_suppressed(self, rule_id: str, device_name: str, metric_type: str) -> bool:
        """Check if an alert is currently suppressed"""
        key = f"{rule_id}_{device_name}_{metric_type}"
        if key in self.suppression_cache:
            return datetime.now() < self.suppression_cache[key]
        return False
    
    def _set_suppression(self, rule_id: str, device_name: str, metric_type: str, duration: int):
        """Set suppression for an alert"""
        key = f"{rule_id}_{device_name}_{metric_type}"
        self.suppression_cache[key] = datetime.now() + timedelta(seconds=duration)
    
    def _process_alert(self, alert: ProactiveAlert):
        """Process a new alert"""
        try:
            # Add to active alerts
            self.active_alerts[alert.alert_id] = alert
            
            # Store in database
            self._store_alert_history(alert)
            
            # Send initial notification
            self._send_notification(alert, escalation_level=0)
            
            logger.info(f"New alert processed: {alert.alert_id} - {alert.message}")
            
        except Exception as e:
            logger.error(f"Failed to process alert {alert.alert_id}: {e}")
    
    def _check_resolved_alerts(self, network_status: Dict[str, Any]):
        """Check if any active alerts have been resolved"""
        resolved_alerts = []
        
        for alert_id, alert in self.active_alerts.items():
            if alert.status in [AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS]:
                if self._is_alert_resolved(alert, network_status):
                    alert.status = AlertStatus.RESOLVED
                    alert.resolved_at = datetime.now()
                    resolved_alerts.append(alert)
        
        # Remove resolved alerts from active list
        for alert in resolved_alerts:
            if alert.alert_id in self.active_alerts:
                del self.active_alerts[alert.alert_id]
                self._update_alert_history(alert)
                logger.info(f"Alert resolved: {alert.alert_id}")
    
    def _is_alert_resolved(self, alert: ProactiveAlert, network_status: Dict[str, Any]) -> bool:
        """Check if an alert condition has been resolved"""
        device_status = network_status.get('device_status', {}).get(alert.device_name, {})
        
        if alert.metric_name == 'cpu_usage':
            current_cpu = device_status.get('cpu_usage', 0)
            return current_cpu < alert.threshold_value
        elif alert.metric_name == 'memory_usage':
            current_memory = device_status.get('memory_usage', 0)
            return current_memory < alert.threshold_value
        elif alert.metric_name == 'reachability':
            return device_status.get('reachable', False)
        
        return False
    
    def _correlate_alerts(self):
        """Correlate related alerts to reduce noise"""
        correlation_window = self.config.get('alert_correlation_window', 300)
        current_time = datetime.now()
        
        # Group alerts by time window and device
        correlation_groups = defaultdict(list)
        
        for alert in self.active_alerts.values():
            if alert.correlation_id is None:
                window_start = alert.timestamp.replace(second=0, microsecond=0)
                key = f"{alert.device_name}_{window_start}"
                correlation_groups[key].append(alert)
        
        # Assign correlation IDs to related alerts
        for group_alerts in correlation_groups.values():
            if len(group_alerts) > 1:
                correlation_id = f"corr_{int(current_time.timestamp())}"
                for alert in group_alerts:
                    alert.correlation_id = correlation_id
    
    def _check_escalations(self):
        """Check and process alert escalations"""
        current_time = datetime.now()
        
        for alert in list(self.active_alerts.values()):
            if alert.status == AlertStatus.RESOLVED:
                continue
            
            escalation_rule = self.escalation_rules.get(alert.priority)
            if not escalation_rule:
                continue
            
            # Check if escalation is needed
            time_since_alert = (current_time - alert.timestamp).total_seconds()
            time_since_escalation = 0
            
            if alert.escalated_at:
                time_since_escalation = (current_time - alert.escalated_at).total_seconds()
            
            should_escalate = False
            
            if alert.escalation_level == 0:
                # First escalation
                should_escalate = time_since_alert >= escalation_rule.escalation_delay
            elif alert.escalation_level < escalation_rule.max_escalations:
                # Subsequent escalations
                should_escalate = time_since_escalation >= escalation_rule.escalation_delay
            
            if should_escalate:
                self._escalate_alert(alert, escalation_rule)
            
            # Check auto-resolve
            if (escalation_rule.auto_resolve and 
                time_since_alert >= escalation_rule.resolve_timeout and
                alert.status != AlertStatus.RESOLVED):
                alert.status = AlertStatus.RESOLVED
                alert.resolved_at = current_time
                self._update_alert_history(alert)
                if alert.alert_id in self.active_alerts:
                    del self.active_alerts[alert.alert_id]
                logger.info(f"Alert auto-resolved: {alert.alert_id}")
    
    def _escalate_alert(self, alert: ProactiveAlert, escalation_rule: EscalationRule):
        """Escalate an alert to the next level"""
        alert.escalation_level += 1
        alert.escalated_at = datetime.now()
        alert.status = AlertStatus.ESCALATED
        
        # Send escalation notifications
        self._send_notification(alert, escalation_level=alert.escalation_level)
        
        # Log escalation
        self._log_escalation(alert, escalation_rule)
        
        # Update database
        self._update_alert_history(alert)
        
        logger.warning(f"Alert escalated to level {alert.escalation_level}: {alert.alert_id}")
    
    def _send_notification(self, alert: ProactiveAlert, escalation_level: int = 0):
        """Send alert notification"""
        try:
            escalation_rule = self.escalation_rules.get(alert.priority)
            if not escalation_rule:
                return
            
            # Find notification config for this escalation level
            notification_config = None
            for level_config in escalation_rule.escalation_levels:
                if level_config['level'] == escalation_level + 1:
                    notification_config = level_config
                    break
            
            if not notification_config:
                return
            
            # Send notifications
            for notification in notification_config.get('notifications', []):
                notification_type = notification['type']
                targets = notification['targets']
                
                if isinstance(notification_type, str):
                    notification_type = NotificationType(notification_type)
                
                for target in targets:
                    try:
                        if notification_type == NotificationType.EMAIL:
                            self._send_email_notification(alert, target, escalation_level)
                        elif notification_type == NotificationType.WEBHOOK:
                            self._send_webhook_notification(alert, target, escalation_level)
                        
                        # Log successful notification
                        self._log_notification(alert, notification_type, target, True, None)
                        
                    except Exception as e:
                        logger.error(f"Failed to send {notification_type.value} notification to {target}: {e}")
                        self._log_notification(alert, notification_type, target, False, str(e))
                        
        except Exception as e:
            logger.error(f"Failed to send notification for alert {alert.alert_id}: {e}")
    
    def _send_email_notification(self, alert: ProactiveAlert, recipient: str, escalation_level: int):
        """Send email notification"""
        if not EMAIL_AVAILABLE:
            logger.warning("Email functionality not available - skipping email notification")
            return
            
        email_config = self.config.get('notification_settings', {}).get('email', {})
        
        if not email_config.get('enabled', False):
            logger.warning("Email notifications are disabled")
            return
        
        # Create message
        msg = MimeMultipart()
        msg['From'] = email_config.get('from_address', 'network-monitoring@company.com')
        msg['To'] = recipient
        
        subject_prefix = f"[ESCALATION L{escalation_level + 1}] " if escalation_level > 0 else ""
        msg['Subject'] = f"{subject_prefix}Network Alert: {alert.alert_type} - {alert.device_name}"
        
        # Create HTML body
        body = f"""
        <html>
        <body>
        <h2>Network Monitoring Alert</h2>
        <table border="1" cellpadding="5">
            <tr><td><b>Alert ID:</b></td><td>{alert.alert_id}</td></tr>
            <tr><td><b>Severity:</b></td><td>{alert.severity.value}</td></tr>
            <tr><td><b>Priority:</b></td><td>{alert.priority.name}</td></tr>
            <tr><td><b>Device:</b></td><td>{alert.device_name}</td></tr>
            <tr><td><b>Metric:</b></td><td>{alert.metric_name}</td></tr>
            <tr><td><b>Current Value:</b></td><td>{alert.current_value}</td></tr>
            <tr><td><b>Threshold:</b></td><td>{alert.threshold_value}</td></tr>
            <tr><td><b>Timestamp:</b></td><td>{alert.timestamp}</td></tr>
            <tr><td><b>Message:</b></td><td>{alert.message}</td></tr>
        </table>
        
        {f'<p><b>Escalation Level:</b> {escalation_level + 1}</p>' if escalation_level > 0 else ''}
        
        <p>Please investigate and take appropriate action.</p>
        </body>
        </html>
        """
        
        msg.attach(MimeText(body, 'html'))
        
        # Send email
        smtp_server = email_config.get('smtp_server', 'localhost')
        smtp_port = email_config.get('smtp_port', 587)
        username = email_config.get('username', '')
        password = email_config.get('password', '')
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if username and password:
                server.starttls()
                server.login(username, password)
            server.send_message(msg)
        
        logger.info(f"Email notification sent to {recipient} for alert {alert.alert_id}")
    
    def _send_webhook_notification(self, alert: ProactiveAlert, webhook_url: str, escalation_level: int):
        """Send webhook notification"""
        if not REQUESTS_AVAILABLE:
            logger.warning("Requests library not available - skipping webhook notification")
            return
            
        webhook_config = self.config.get('notification_settings', {}).get('webhook', {})
        
        if not webhook_config.get('enabled', False):
            logger.warning("Webhook notifications are disabled")
            return
        
        # Prepare payload
        payload = {
            'alert': alert.to_dict(),
            'escalation_level': escalation_level,
            'timestamp': datetime.now().isoformat()
        }
        
        # Send webhook
        headers = webhook_config.get('headers', {})
        headers['Content-Type'] = 'application/json'
        
        timeout = webhook_config.get('timeout', 30)
        
        response = requests.post(
            webhook_url,
            json=payload,
            headers=headers,
            timeout=timeout
        )
        
        response.raise_for_status()
        
        logger.info(f"Webhook notification sent to {webhook_url} for alert {alert.alert_id}")
    
    def _store_alert_history(self, alert: ProactiveAlert):
        """Store alert in history database"""
        try:
            with sqlite3.connect(ALERT_HISTORY_DB) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO alert_history (
                        alert_id, severity, priority, status, alert_type, device_name,
                        metric_name, current_value, threshold_value, message, timestamp,
                        acknowledged_by, acknowledged_at, escalation_level, escalated_at,
                        resolved_at, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.alert_id,
                    alert.severity.value if isinstance(alert.severity, AlertSeverity) else alert.severity,
                    alert.priority.value if isinstance(alert.priority, AlertPriority) else alert.priority,
                    alert.status.value if isinstance(alert.status, AlertStatus) else alert.status,
                    alert.alert_type,
                    alert.device_name,
                    alert.metric_name,
                    alert.current_value,
                    alert.threshold_value,
                    alert.message,
                    alert.timestamp.isoformat() if isinstance(alert.timestamp, datetime) else alert.timestamp,
                    alert.acknowledged_by,
                    alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                    alert.escalation_level,
                    alert.escalated_at.isoformat() if alert.escalated_at else None,
                    alert.resolved_at.isoformat() if alert.resolved_at else None,
                    alert.correlation_id
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to store alert history: {e}")
    
    def _update_alert_history(self, alert: ProactiveAlert):
        """Update existing alert in history database"""
        self._store_alert_history(alert)  # INSERT OR REPLACE handles updates
    
    def _log_escalation(self, alert: ProactiveAlert, escalation_rule: EscalationRule):
        """Log escalation event"""
        try:
            with open(ESCALATION_LOG, 'a') as f:
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'alert_id': alert.alert_id,
                    'escalation_level': alert.escalation_level,
                    'escalation_rule': escalation_rule.rule_id,
                    'priority': alert.priority.name if isinstance(alert.priority, AlertPriority) else alert.priority,
                    'device_name': alert.device_name
                }
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Failed to log escalation: {e}")
    
    def _log_notification(self, alert: ProactiveAlert, notification_type: NotificationType, 
                         target: str, success: bool, error_message: Optional[str]):
        """Log notification attempt"""
        try:
            with sqlite3.connect(ALERT_HISTORY_DB) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO escalation_log (
                        alert_id, escalation_level, escalated_at, notification_type,
                        notification_target, success, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.alert_id,
                    alert.escalation_level,
                    datetime.now().isoformat(),
                    notification_type.value if isinstance(notification_type, NotificationType) else notification_type,
                    target,
                    success,
                    error_message
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to log notification: {e}")
    
    def get_active_alerts(self, priority_filter: Optional[AlertPriority] = None, 
                         device_filter: Optional[str] = None) -> Dict[str, Any]:
        """Get current active alerts"""
        try:
            filtered_alerts = []
            
            for alert in self.active_alerts.values():
                # Apply filters
                if priority_filter and alert.priority != priority_filter:
                    continue
                
                if device_filter and device_filter.lower() not in alert.device_name.lower():
                    continue
                
                filtered_alerts.append(alert.to_dict())
            
            # Sort by priority and timestamp
            filtered_alerts.sort(key=lambda x: (
                -AlertPriority[x['priority']].value if isinstance(x['priority'], str) else -x['priority'],
                x['timestamp']
            ))
            
            return {
                'success': True,
                'active_alerts': filtered_alerts,
                'total_count': len(filtered_alerts),
                'by_priority': self._count_by_priority(filtered_alerts),
                'by_status': self._count_by_status(filtered_alerts)
            }
            
        except Exception as e:
            logger.error(f"Failed to get active alerts: {e}")
            return {
                'success': False,
                'error': str(e),
                'active_alerts': []
            }
    
    def _count_by_priority(self, alerts: List[Dict]) -> Dict[str, int]:
        """Count alerts by priority"""
        counts = defaultdict(int)
        for alert in alerts:
            priority = alert.get('priority', 'unknown')
            if isinstance(priority, int):
                priority = AlertPriority(priority).name
            counts[priority] += 1
        return dict(counts)
    
    def _count_by_status(self, alerts: List[Dict]) -> Dict[str, int]:
        """Count alerts by status"""
        counts = defaultdict(int)
        for alert in alerts:
            status = alert.get('status', 'unknown')
            counts[status] += 1
        return dict(counts)
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> Dict[str, Any]:
        """Acknowledge an alert"""
        try:
            if alert_id not in self.active_alerts:
                return {
                    'success': False,
                    'error': f'Alert {alert_id} not found in active alerts'
                }
            
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = acknowledged_by
            alert.acknowledged_at = datetime.now()
            
            # Update database
            self._update_alert_history(alert)
            
            logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
            
            return {
                'success': True,
                'message': f'Alert {alert_id} acknowledged',
                'acknowledged_by': acknowledged_by,
                'acknowledged_at': alert.acknowledged_at.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get monitoring service status"""
        return {
            'success': True,
            'monitoring_status': {
                'running': self.running,
                'monitoring_interval': self.config.get('monitoring_interval', 60),
                'escalation_check_interval': self.config.get('escalation_check_interval', 300),
                'active_alerts_count': len(self.active_alerts),
                'alert_rules_count': len(self.alert_rules),
                'escalation_rules_count': len(self.escalation_rules),
                'suppression_cache_size': len(self.suppression_cache),
                'last_check': datetime.now().isoformat()
            }
        }


# Global monitoring service instance
_monitoring_service = None


def get_monitoring_service() -> ProactiveMonitoringService:
    """Get global monitoring service instance"""
    global _monitoring_service
    if _monitoring_service is None:
        _monitoring_service = ProactiveMonitoringService()
    return _monitoring_service


# MCP Tool Functions
def start_proactive_monitoring() -> Dict[str, Any]:
    """
    Start proactive network monitoring with intelligent alerting
    
    Returns:
        Dict containing monitoring service status and configuration
    """
    try:
        service = get_monitoring_service()
        result = service.start_monitoring()
        
        logger.info("Proactive monitoring started via MCP tool")
        return result
        
    except Exception as e:
        logger.error(f"Failed to start proactive monitoring: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': 'Failed to start proactive monitoring service'
        }


def stop_proactive_monitoring() -> Dict[str, Any]:
    """
    Stop proactive network monitoring service
    
    Returns:
        Dict containing operation status
    """
    try:
        service = get_monitoring_service()
        result = service.stop_monitoring()
        
        logger.info("Proactive monitoring stopped via MCP tool")
        return result
        
    except Exception as e:
        logger.error(f"Failed to stop proactive monitoring: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': 'Failed to stop proactive monitoring service'
        }


def get_active_alerts(priority_filter: Optional[str] = None, 
                     device_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    Get current active network alerts with optional filtering
    
    Args:
        priority_filter: Optional priority filter (LOW, MEDIUM, HIGH, CRITICAL, EMERGENCY)
        device_filter: Optional device name filter (partial match)
    
    Returns:
        Dict containing active alerts and summary statistics
    """
    try:
        service = get_monitoring_service()
        
        # Convert priority filter
        priority = None
        if priority_filter:
            try:
                priority = AlertPriority[priority_filter.upper()]
            except KeyError:
                return {
                    'success': False,
                    'error': f'Invalid priority filter: {priority_filter}. Valid values: LOW, MEDIUM, HIGH, CRITICAL, EMERGENCY'
                }
        
        result = service.get_active_alerts(priority_filter=priority, device_filter=device_filter)
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to get active alerts: {e}")
        return {
            'success': False,
            'error': str(e),
            'active_alerts': []
        }


def acknowledge_alert(alert_id: str, acknowledged_by: str) -> Dict[str, Any]:
    """
    Acknowledge a network alert
    
    Args:
        alert_id: ID of the alert to acknowledge
        acknowledged_by: Username or identifier of person acknowledging
    
    Returns:
        Dict containing acknowledgment status
    """
    try:
        service = get_monitoring_service()
        result = service.acknowledge_alert(alert_id, acknowledged_by)
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def get_proactive_monitoring_status() -> Dict[str, Any]:
    """
    Get proactive monitoring service status and configuration
    
    Returns:
        Dict containing monitoring service status information
    """
    try:
        service = get_monitoring_service()
        result = service.get_monitoring_status()
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to get monitoring status: {e}")
        return {
            'success': False,
            'error': str(e)
        }


if __name__ == "__main__":
    # Command-line interface for testing
    import argparse
    
    parser = argparse.ArgumentParser(description='Proactive Network Monitoring Service')
    parser.add_argument('--start', action='store_true', help='Start monitoring service')
    parser.add_argument('--stop', action='store_true', help='Stop monitoring service')
    parser.add_argument('--status', action='store_true', help='Get monitoring status')
    parser.add_argument('--alerts', action='store_true', help='Get active alerts')
    
    args = parser.parse_args()
    
    if args.start:
        result = start_proactive_monitoring()
        print(json.dumps(result, indent=2))
    
    elif args.stop:
        result = stop_proactive_monitoring()
        print(json.dumps(result, indent=2))
    
    elif args.status:
        result = get_proactive_monitoring_status()
        print(json.dumps(result, indent=2))
    
    elif args.alerts:
        result = get_active_alerts()
        print(json.dumps(result, indent=2))
    
    else:
        parser.print_help()
