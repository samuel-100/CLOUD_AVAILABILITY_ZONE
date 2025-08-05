#!/usr/bin/env python3
"""
Test Proactive Monitoring and Alerting System

Tests for the comprehensive proactive monitoring service including
alert generation, prioritization, escalation, and notification systems.
"""

import os
import sys
import unittest
import json
import time
import tempfile
import sqlite3
from datetime import datetime, timedelta
from unittest.mock import patch, Mock, MagicMock

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from services.proactive_monitoring import (
    ProactiveMonitoringService,
    AlertPriority,
    AlertStatus,
    NotificationType,
    AlertRule,
    EscalationRule,
    ProactiveAlert,
    start_proactive_monitoring,
    stop_proactive_monitoring,
    get_active_alerts,
    acknowledge_alert,
    get_proactive_monitoring_status
)


class TestProactiveMonitoring(unittest.TestCase):
    """Test cases for proactive monitoring system"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock file paths
        self.original_monitoring_config = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/config/monitoring_config.yaml'
        self.original_alert_db = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/alert_history.db'
        
        # Create test config
        self.test_config = {
            'monitoring_interval': 10,
            'escalation_check_interval': 30,
            'alert_correlation_window': 60,
            'max_alerts_per_device': 5,
            'notification_settings': {
                'email': {'enabled': False},
                'webhook': {'enabled': False}
            }
        }
        
        # Patch file paths
        with patch('services.proactive_monitoring.MONITORING_CONFIG_FILE', 
                  os.path.join(self.temp_dir, 'monitoring_config.yaml')):
            with patch('services.proactive_monitoring.ALERT_HISTORY_DB',
                      os.path.join(self.temp_dir, 'alert_history.db')):
                self.service = ProactiveMonitoringService()
    
    def tearDown(self):
        """Clean up test environment"""
        if hasattr(self, 'service') and self.service.running:
            self.service.stop_monitoring()
    
    def test_service_initialization(self):
        """Test service initialization"""
        self.assertIsNotNone(self.service)
        self.assertFalse(self.service.running)
        self.assertIsInstance(self.service.alert_rules, dict)
        self.assertIsInstance(self.service.escalation_rules, dict)
        self.assertGreater(len(self.service.alert_rules), 0)
        self.assertGreater(len(self.service.escalation_rules), 0)
    
    def test_alert_rule_creation(self):
        """Test alert rule creation and validation"""
        rule = AlertRule(
            rule_id="test_cpu",
            name="Test CPU Rule",
            description="Test CPU monitoring",
            metric_type="cpu",
            threshold_type="static",
            threshold_value=80.0,
            comparison="gt",
            duration=300,
            priority=AlertPriority.HIGH
        )
        
        self.assertEqual(rule.rule_id, "test_cpu")
        self.assertEqual(rule.priority, AlertPriority.HIGH)
        self.assertEqual(rule.threshold_value, 80.0)
    
    def test_escalation_rule_creation(self):
        """Test escalation rule creation"""
        escalation = EscalationRule(
            rule_id="test_escalation",
            alert_priority=AlertPriority.CRITICAL,
            escalation_delay=300,
            escalation_levels=[
                {
                    'level': 1,
                    'notifications': [
                        {'type': NotificationType.EMAIL, 'targets': ['admin@test.com']}
                    ]
                }
            ]
        )
        
        self.assertEqual(escalation.alert_priority, AlertPriority.CRITICAL)
        self.assertEqual(escalation.escalation_delay, 300)
        self.assertEqual(len(escalation.escalation_levels), 1)
    
    def test_proactive_alert_creation(self):
        """Test proactive alert creation and serialization"""
        alert = ProactiveAlert(
            alert_id="test_alert_001",
            severity="HIGH",
            priority=AlertPriority.HIGH,
            status=AlertStatus.NEW,
            alert_type="cpu_threshold",
            device_name="SPINE1",
            metric_name="cpu_usage",
            current_value=85.0,
            threshold_value=80.0,
            message="CPU usage high",
            timestamp=datetime.now()
        )
        
        # Test serialization
        alert_dict = alert.to_dict()
        self.assertIsInstance(alert_dict, dict)
        self.assertEqual(alert_dict['alert_id'], "test_alert_001")
        self.assertEqual(alert_dict['device_name'], "SPINE1")
        self.assertEqual(alert_dict['current_value'], 85.0)
    
    @patch('services.proactive_monitoring.get_network_status')
    def test_start_stop_monitoring(self, mock_network_status):
        """Test starting and stopping monitoring service"""
        # Mock network status
        mock_network_status.return_value = {
            'success': True,
            'network_status': {
                'device_status': {
                    'SPINE1': {
                        'reachable': True,
                        'cpu_usage': 70.0,
                        'memory_usage': 60.0
                    }
                }
            }
        }
        
        # Test start monitoring
        result = self.service.start_monitoring()
        self.assertTrue(result['success'])
        self.assertTrue(self.service.running)
        
        # Let it run briefly
        time.sleep(0.1)
        
        # Test stop monitoring
        result = self.service.stop_monitoring()
        self.assertTrue(result['success'])
        self.assertFalse(self.service.running)
    
    def test_threshold_evaluation(self):
        """Test threshold evaluation logic"""
        rule = AlertRule(
            rule_id="test_rule",
            name="Test Rule",
            description="Test",
            metric_type="cpu",
            threshold_type="static",
            threshold_value=80.0,
            comparison="gt",
            duration=300,
            priority=AlertPriority.HIGH
        )
        
        # Test greater than
        self.assertTrue(self.service._evaluate_threshold(85.0, rule))
        self.assertFalse(self.service._evaluate_threshold(75.0, rule))
        
        # Test less than
        rule.comparison = "lt"
        self.assertFalse(self.service._evaluate_threshold(85.0, rule))
        self.assertTrue(self.service._evaluate_threshold(75.0, rule))
        
        # Test equal
        rule.comparison = "eq"
        rule.threshold_value = 80.0
        self.assertTrue(self.service._evaluate_threshold(80.0, rule))
        self.assertFalse(self.service._evaluate_threshold(85.0, rule))
    
    def test_priority_to_severity_mapping(self):
        """Test alert priority to severity mapping"""
        self.assertEqual(
            self.service._priority_to_severity(AlertPriority.LOW).value, 
            "low"
        )
        self.assertEqual(
            self.service._priority_to_severity(AlertPriority.CRITICAL).value,
            "critical"
        )
    
    def test_alert_suppression(self):
        """Test alert suppression mechanism"""
        rule_id = "test_rule"
        device_name = "SPINE1"
        metric_type = "cpu"
        
        # Initially not suppressed
        self.assertFalse(self.service._is_suppressed(rule_id, device_name, metric_type))
        
        # Set suppression
        self.service._set_suppression(rule_id, device_name, metric_type, 300)
        
        # Should be suppressed now
        self.assertTrue(self.service._is_suppressed(rule_id, device_name, metric_type))
    
    @patch('services.proactive_monitoring.get_network_status')
    def test_alert_evaluation(self, mock_network_status):
        """Test alert rule evaluation against network status"""
        # Mock network status with high CPU
        mock_network_status.return_value = {
            'success': True,
            'network_status': {
                'device_status': {
                    'SPINE1': {
                        'reachable': True,
                        'cpu_usage': 90.0,
                        'memory_usage': 85.0
                    },
                    'SPINE2': {
                        'reachable': False,
                        'cpu_usage': 0,
                        'memory_usage': 0
                    }
                }
            }
        }
        
        network_status = mock_network_status()['network_status']
        alerts = self.service._evaluate_alert_rules(network_status)
        
        # Should generate alerts for high CPU and unreachable device
        self.assertGreater(len(alerts), 0)
        
        # Check alert properties
        cpu_alerts = [a for a in alerts if a.metric_name == 'cpu_usage']
        self.assertGreater(len(cpu_alerts), 0)
        
        connectivity_alerts = [a for a in alerts if a.metric_name == 'reachability']
        self.assertGreater(len(connectivity_alerts), 0)
    
    def test_alert_correlation(self):
        """Test alert correlation functionality"""
        # Create multiple alerts for the same device
        current_time = datetime.now()
        
        alert1 = ProactiveAlert(
            alert_id="alert_001",
            severity="HIGH",
            priority=AlertPriority.HIGH,
            status=AlertStatus.NEW,
            alert_type="cpu_threshold",
            device_name="SPINE1",
            metric_name="cpu_usage",
            current_value=90.0,
            threshold_value=80.0,
            message="High CPU",
            timestamp=current_time
        )
        
        alert2 = ProactiveAlert(
            alert_id="alert_002",
            severity="HIGH",
            priority=AlertPriority.HIGH,
            status=AlertStatus.NEW,
            alert_type="memory_threshold",
            device_name="SPINE1",
            metric_name="memory_usage",
            current_value=95.0,
            threshold_value=85.0,
            message="High Memory",
            timestamp=current_time + timedelta(seconds=30)
        )
        
        self.service.active_alerts[alert1.alert_id] = alert1
        self.service.active_alerts[alert2.alert_id] = alert2
        
        # Run correlation
        self.service._correlate_alerts()
        
        # Both alerts should have the same correlation ID
        self.assertIsNotNone(alert1.correlation_id)
        self.assertIsNotNone(alert2.correlation_id)
        self.assertEqual(alert1.correlation_id, alert2.correlation_id)
    
    @patch('services.proactive_monitoring.get_network_status')
    def test_alert_resolution(self, mock_network_status):
        """Test alert resolution detection"""
        # Create an active CPU alert
        alert = ProactiveAlert(
            alert_id="cpu_alert_001",
            severity="HIGH",
            priority=AlertPriority.HIGH,
            status=AlertStatus.NEW,
            alert_type="cpu_threshold",
            device_name="SPINE1",
            metric_name="cpu_usage",
            current_value=90.0,
            threshold_value=80.0,
            message="High CPU",
            timestamp=datetime.now()
        )
        
        self.service.active_alerts[alert.alert_id] = alert
        
        # Mock network status showing resolved condition
        mock_network_status.return_value = {
            'success': True,
            'network_status': {
                'device_status': {
                    'SPINE1': {
                        'reachable': True,
                        'cpu_usage': 70.0,
                        'memory_usage': 60.0
                    }
                }
            }
        }
        
        network_status = mock_network_status()['network_status']
        
        # Check resolution
        self.service._check_resolved_alerts(network_status)
        
        # Alert should be removed from active alerts
        self.assertNotIn(alert.alert_id, self.service.active_alerts)
        self.assertEqual(alert.status, AlertStatus.RESOLVED)
        self.assertIsNotNone(alert.resolved_at)
    
    def test_escalation_logic(self):
        """Test alert escalation logic"""
        # Create alert that should escalate
        past_time = datetime.now() - timedelta(minutes=10)
        
        alert = ProactiveAlert(
            alert_id="escalation_test",
            severity="CRITICAL",
            priority=AlertPriority.CRITICAL,
            status=AlertStatus.NEW,
            alert_type="cpu_threshold",
            device_name="SPINE1",
            metric_name="cpu_usage",
            current_value=98.0,
            threshold_value=95.0,
            message="Critical CPU",
            timestamp=past_time
        )
        
        self.service.active_alerts[alert.alert_id] = alert
        
        # Mock notification sending
        with patch.object(self.service, '_send_notification'):
            # Check escalations
            self.service._check_escalations()
        
        # Alert should be escalated
        self.assertEqual(alert.status, AlertStatus.ESCALATED)
        self.assertEqual(alert.escalation_level, 1)
        self.assertIsNotNone(alert.escalated_at)
    
    @patch('smtplib.SMTP')
    def test_email_notification(self, mock_smtp):
        """Test email notification sending"""
        # Configure email in service
        self.service.config['notification_settings']['email']['enabled'] = True
        
        alert = ProactiveAlert(
            alert_id="email_test",
            severity="HIGH",
            priority=AlertPriority.HIGH,
            status=AlertStatus.NEW,
            alert_type="cpu_threshold",
            device_name="SPINE1",
            metric_name="cpu_usage",
            current_value=85.0,
            threshold_value=80.0,
            message="High CPU",
            timestamp=datetime.now()
        )
        
        # Mock SMTP server
        mock_server = Mock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        
        # Send notification
        self.service._send_email_notification(alert, "admin@test.com", 0)
        
        # Verify SMTP was called
        mock_smtp.assert_called_once()
        mock_server.send_message.assert_called_once()
    
    @patch('requests.post')
    def test_webhook_notification(self, mock_requests):
        """Test webhook notification sending"""
        # Configure webhook in service
        self.service.config['notification_settings']['webhook']['enabled'] = True
        
        alert = ProactiveAlert(
            alert_id="webhook_test",
            severity="HIGH",
            priority=AlertPriority.HIGH,
            status=AlertStatus.NEW,
            alert_type="cpu_threshold",
            device_name="SPINE1",
            metric_name="cpu_usage",
            current_value=85.0,
            threshold_value=80.0,
            message="High CPU",
            timestamp=datetime.now()
        )
        
        # Mock successful webhook response
        mock_requests.return_value.status_code = 200
        
        # Send notification
        self.service._send_webhook_notification(alert, "http://test.com/webhook", 0)
        
        # Verify webhook was called
        mock_requests.assert_called_once()
        args, kwargs = mock_requests.call_args
        self.assertEqual(args[0], "http://test.com/webhook")
        self.assertIn('json', kwargs)
    
    def test_database_operations(self):
        """Test database operations for alert history"""
        alert = ProactiveAlert(
            alert_id="db_test",
            severity="HIGH",
            priority=AlertPriority.HIGH,
            status=AlertStatus.NEW,
            alert_type="cpu_threshold",
            device_name="SPINE1",
            metric_name="cpu_usage",
            current_value=85.0,
            threshold_value=80.0,
            message="High CPU",
            timestamp=datetime.now()
        )
        
        # Store alert
        self.service._store_alert_history(alert)
        
        # Verify it was stored
        with sqlite3.connect(os.path.join(self.temp_dir, 'alert_history.db')) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM alert_history WHERE alert_id = ?', (alert.alert_id,))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
    
    def test_get_active_alerts(self):
        """Test getting active alerts with filtering"""
        # Add test alerts
        alerts = [
            ProactiveAlert(
                alert_id="test_001",
                severity="HIGH",
                priority=AlertPriority.HIGH,
                status=AlertStatus.NEW,
                alert_type="cpu_threshold",
                device_name="SPINE1",
                metric_name="cpu_usage",
                current_value=85.0,
                threshold_value=80.0,
                message="High CPU",
                timestamp=datetime.now()
            ),
            ProactiveAlert(
                alert_id="test_002",
                severity="CRITICAL",
                priority=AlertPriority.CRITICAL,
                status=AlertStatus.NEW,
                alert_type="memory_threshold",
                device_name="SPINE2",
                metric_name="memory_usage",
                current_value=95.0,
                threshold_value=90.0,
                message="Critical Memory",
                timestamp=datetime.now()
            )
        ]
        
        for alert in alerts:
            self.service.active_alerts[alert.alert_id] = alert
        
        # Test get all alerts
        result = self.service.get_active_alerts()
        self.assertTrue(result['success'])
        self.assertEqual(len(result['active_alerts']), 2)
        
        # Test priority filter
        result = self.service.get_active_alerts(priority_filter=AlertPriority.CRITICAL)
        self.assertTrue(result['success'])
        self.assertEqual(len(result['active_alerts']), 1)
        self.assertEqual(result['active_alerts'][0]['priority'], AlertPriority.CRITICAL.value)
        
        # Test device filter
        result = self.service.get_active_alerts(device_filter="SPINE1")
        self.assertTrue(result['success'])
        self.assertEqual(len(result['active_alerts']), 1)
        self.assertEqual(result['active_alerts'][0]['device_name'], "SPINE1")
    
    def test_acknowledge_alert(self):
        """Test alert acknowledgment"""
        alert = ProactiveAlert(
            alert_id="ack_test",
            severity="HIGH",
            priority=AlertPriority.HIGH,
            status=AlertStatus.NEW,
            alert_type="cpu_threshold",
            device_name="SPINE1",
            metric_name="cpu_usage",
            current_value=85.0,
            threshold_value=80.0,
            message="High CPU",
            timestamp=datetime.now()
        )
        
        self.service.active_alerts[alert.alert_id] = alert
        
        # Acknowledge alert
        result = self.service.acknowledge_alert("ack_test", "admin")
        
        self.assertTrue(result['success'])
        self.assertEqual(alert.status, AlertStatus.ACKNOWLEDGED)
        self.assertEqual(alert.acknowledged_by, "admin")
        self.assertIsNotNone(alert.acknowledged_at)
    
    def test_monitoring_status(self):
        """Test monitoring status reporting"""
        result = self.service.get_monitoring_status()
        
        self.assertTrue(result['success'])
        self.assertIn('monitoring_status', result)
        self.assertIn('running', result['monitoring_status'])
        self.assertIn('active_alerts_count', result['monitoring_status'])
        self.assertIn('alert_rules_count', result['monitoring_status'])


class TestMCPIntegration(unittest.TestCase):
    """Test MCP tool integration"""
    
    @patch('services.proactive_monitoring.ProactiveMonitoringService')
    def test_start_proactive_monitoring_tool(self, mock_service_class):
        """Test start_proactive_monitoring MCP tool"""
        mock_service = Mock()
        mock_service.start_monitoring.return_value = {
            'success': True,
            'message': 'Monitoring started'
        }
        mock_service_class.return_value = mock_service
        
        result = start_proactive_monitoring()
        
        self.assertTrue(result['success'])
        mock_service.start_monitoring.assert_called_once()
    
    @patch('services.proactive_monitoring.ProactiveMonitoringService')
    def test_stop_proactive_monitoring_tool(self, mock_service_class):
        """Test stop_proactive_monitoring MCP tool"""
        mock_service = Mock()
        mock_service.stop_monitoring.return_value = {
            'success': True,
            'message': 'Monitoring stopped'
        }
        mock_service_class.return_value = mock_service
        
        result = stop_proactive_monitoring()
        
        self.assertTrue(result['success'])
        mock_service.stop_monitoring.assert_called_once()
    
    @patch('services.proactive_monitoring.ProactiveMonitoringService')
    def test_get_active_alerts_tool(self, mock_service_class):
        """Test get_active_alerts MCP tool"""
        mock_service = Mock()
        mock_service.get_active_alerts.return_value = {
            'success': True,
            'active_alerts': [],
            'total_count': 0
        }
        mock_service_class.return_value = mock_service
        
        result = get_active_alerts()
        
        self.assertTrue(result['success'])
        mock_service.get_active_alerts.assert_called_once()
    
    @patch('services.proactive_monitoring.ProactiveMonitoringService')
    def test_acknowledge_alert_tool(self, mock_service_class):
        """Test acknowledge_alert MCP tool"""
        mock_service = Mock()
        mock_service.acknowledge_alert.return_value = {
            'success': True,
            'message': 'Alert acknowledged'
        }
        mock_service_class.return_value = mock_service
        
        result = acknowledge_alert("test_alert", "admin")
        
        self.assertTrue(result['success'])
        mock_service.acknowledge_alert.assert_called_once_with("test_alert", "admin")
    
    @patch('services.proactive_monitoring.ProactiveMonitoringService')
    def test_get_monitoring_status_tool(self, mock_service_class):
        """Test get_proactive_monitoring_status MCP tool"""
        mock_service = Mock()
        mock_service.get_monitoring_status.return_value = {
            'success': True,
            'monitoring_status': {
                'running': False,
                'active_alerts_count': 0
            }
        }
        mock_service_class.return_value = mock_service
        
        result = get_proactive_monitoring_status()
        
        self.assertTrue(result['success'])
        mock_service.get_monitoring_status.assert_called_once()


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestProactiveMonitoring))
    test_suite.addTest(unittest.makeSuite(TestMCPIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with error code if tests failed
    if not result.wasSuccessful():
        exit(1)
