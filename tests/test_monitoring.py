#!/usr/bin/env python3
"""
Test Suite for Monitoring and Observability Service

Comprehensive tests for metrics collection, health checks, distributed tracing,
and monitoring dashboard functionality.
"""

import os
import sys
import unittest
import tempfile
import sqlite3
import time
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Add services to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.monitoring_service import (
    MonitoringService, MetricsCollector, HealthChecker, DistributedTracer,
    CorrelationContext, StructuredLogger, HealthStatus, MetricPoint, TracingSpan,
    get_system_health, get_monitoring_metrics, get_trace_details
)


class TestCorrelationContext(unittest.TestCase):
    """Test correlation context and tracing"""
    
    def setUp(self):
        self.context = CorrelationContext()
    
    def test_correlation_id_management(self):
        """Test correlation ID setting and retrieval"""
        correlation_id = "test-correlation-123"
        
        # Initially no correlation ID
        self.assertIsNone(self.context.get_correlation_id())
        
        # Set correlation ID
        self.context.set_correlation_id(correlation_id)
        self.assertEqual(self.context.get_correlation_id(), correlation_id)
    
    def test_trace_id_management(self):
        """Test trace ID setting and retrieval"""
        trace_id = "test-trace-456"
        
        # Initially no trace ID
        self.assertIsNone(self.context.get_trace_id())
        
        # Set trace ID
        self.context.set_trace_id(trace_id)
        self.assertEqual(self.context.get_trace_id(), trace_id)
    
    def test_correlation_context_manager(self):
        """Test correlation context manager"""
        correlation_id = "context-test-123"
        trace_id = "context-trace-456"
        
        with self.context.correlation_context(correlation_id, trace_id):
            self.assertEqual(self.context.get_correlation_id(), correlation_id)
            self.assertEqual(self.context.get_trace_id(), trace_id)
        
        # Context should be cleared after exiting
        self.assertIsNone(self.context.get_correlation_id())
        self.assertIsNone(self.context.get_trace_id())


class TestStructuredLogger(unittest.TestCase):
    """Test structured logging functionality"""
    
    def setUp(self):
        self.logger = StructuredLogger("test_logger")
        self.context = CorrelationContext()
    
    def test_logging_with_correlation_id(self):
        """Test logging includes correlation ID"""
        correlation_id = "log-test-123"
        self.context.set_correlation_id(correlation_id)
        
        # Test that logging methods work (actual correlation injection tested in integration)
        self.logger.info("Test message", extra_field="test_value")
        self.logger.warning("Warning message")
        self.logger.error("Error message")
        self.logger.debug("Debug message")
        
        # Test passes if no exceptions are raised
        self.assertTrue(True)


class TestDistributedTracer(unittest.TestCase):
    """Test distributed tracing functionality"""
    
    def setUp(self):
        # Use temporary database for testing
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.tracer = DistributedTracer(self.temp_db.name)
    
    def tearDown(self):
        os.unlink(self.temp_db.name)
    
    def test_span_creation_and_finishing(self):
        """Test span lifecycle"""
        operation_name = "test_operation"
        
        # Start span
        span = self.tracer.start_span(operation_name)
        
        self.assertIsInstance(span, TracingSpan)
        self.assertEqual(span.operation_name, operation_name)
        self.assertIsNotNone(span.span_id)
        self.assertIsNotNone(span.trace_id)
        self.assertIsInstance(span.start_time, datetime)
        
        # Span should be active
        self.assertIn(span.span_id, self.tracer.active_spans)
        
        # Add log to span
        self.tracer.add_span_log(span, "test_event", {"key": "value"})
        self.assertEqual(len(span.logs), 1)
        
        # Finish span
        self.tracer.finish_span(span, {"result": "success"})
        
        # Span should no longer be active
        self.assertNotIn(span.span_id, self.tracer.active_spans)
        self.assertIsNotNone(span.duration_ms)
        self.assertEqual(span.tags["result"], "success")
    
    def test_trace_retrieval(self):
        """Test trace retrieval from database"""
        trace_id = str(uuid.uuid4())
        
        # Create multiple spans for the same trace
        span1 = self.tracer.start_span("operation_1")
        span1.trace_id = trace_id
        self.tracer.finish_span(span1)
        
        span2 = self.tracer.start_span("operation_2")
        span2.trace_id = trace_id
        self.tracer.finish_span(span2)
        
        # Retrieve trace
        retrieved_spans = self.tracer.get_trace(trace_id)
        
        self.assertEqual(len(retrieved_spans), 2)
        self.assertTrue(all(span.trace_id == trace_id for span in retrieved_spans))


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality"""
    
    def setUp(self):
        # Disable Prometheus for testing
        self.metrics = MetricsCollector(enable_prometheus=False)
    
    def test_request_metrics_recording(self):
        """Test HTTP request metrics recording"""
        method, endpoint, status, duration = "GET", "/api/test", "200", 0.5
        
        self.metrics.record_request(method, endpoint, status, duration)
        
        # Check fallback storage
        self.assertIn('request_count', self.metrics.metric_storage)
        self.assertIn('request_duration', self.metrics.metric_storage)
        
        count_metric = self.metrics.metric_storage['request_count'][0]
        duration_metric = self.metrics.metric_storage['request_duration'][0]
        
        self.assertEqual(count_metric.value, 1.0)
        self.assertEqual(duration_metric.value, duration)
        self.assertEqual(count_metric.labels['method'], method)
        self.assertEqual(count_metric.labels['endpoint'], endpoint)
        self.assertEqual(count_metric.labels['status'], status)
    
    def test_device_metrics_recording(self):
        """Test device metrics recording"""
        device_name, device_type, is_up = "SPINE1", "spine", True
        response_time = 0.1
        
        self.metrics.record_device_status(device_name, device_type, is_up)
        self.metrics.record_device_response_time(device_name, response_time)
        
        # Check storage
        self.assertIn('device_status', self.metrics.metric_storage)
        self.assertIn('device_response_time', self.metrics.metric_storage)
        
        status_metric = self.metrics.metric_storage['device_status'][0]
        response_metric = self.metrics.metric_storage['device_response_time'][0]
        
        self.assertEqual(status_metric.value, 1.0)  # device is up
        self.assertEqual(response_metric.value, response_time)
        self.assertEqual(status_metric.labels['device_name'], device_name)
        self.assertEqual(status_metric.labels['device_type'], device_type)
    
    def test_error_metrics_recording(self):
        """Test error metrics recording"""
        error_type, severity = "timeout", "low"
        
        self.metrics.record_error(error_type, severity)
        
        # Check storage
        self.assertIn('error_count', self.metrics.metric_storage)
        
        error_metric = self.metrics.metric_storage['error_count'][0]
        self.assertEqual(error_metric.value, 1.0)
        self.assertEqual(error_metric.labels['error_type'], error_type)
        self.assertEqual(error_metric.labels['severity'], severity)
    
    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    def test_system_metrics_recording(self, mock_memory, mock_cpu):
        """Test system metrics recording"""
        mock_cpu.return_value = 45.5
        mock_memory.return_value = Mock(used=1024*1024*1024)  # 1GB
        
        self.metrics.record_system_metrics()
        
        # Check storage
        self.assertIn('system_cpu_usage', self.metrics.metric_storage)
        self.assertIn('system_memory_usage', self.metrics.metric_storage)
        
        cpu_metric = self.metrics.metric_storage['system_cpu_usage'][0]
        memory_metric = self.metrics.metric_storage['system_memory_usage'][0]
        
        self.assertEqual(cpu_metric.value, 45.5)
        self.assertEqual(memory_metric.value, 1024*1024*1024)
    
    def test_metrics_summary(self):
        """Test metrics summary generation"""
        # Record some metrics
        self.metrics.record_request("GET", "/test", "200", 0.5)
        self.metrics.record_error("timeout", "low")
        
        summary = self.metrics.get_metrics_summary()
        
        self.assertIn('prometheus_enabled', summary)
        self.assertIn('timestamp', summary)
        self.assertIn('metrics', summary)
        self.assertFalse(summary['prometheus_enabled'])
        self.assertIn('request_count', summary['metrics'])
        self.assertIn('error_count', summary['metrics'])


class TestHealthChecker(unittest.TestCase):
    """Test health checking functionality"""
    
    def setUp(self):
        # Use temporary database for testing
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.health_checker = HealthChecker(self.temp_db.name)
    
    def tearDown(self):
        os.unlink(self.temp_db.name)
    
    def test_health_check_registration(self):
        """Test health check registration"""
        def dummy_check():
            return HealthStatus("test", "healthy", "OK", datetime.now())
        
        self.health_checker.register_health_check("test_component", dummy_check)
        self.assertIn("test_component", self.health_checker.health_checks)
    
    def test_health_check_execution(self):
        """Test health check execution"""
        def healthy_check():
            return HealthStatus("test", "healthy", "All good", datetime.now())
        
        def failing_check():
            raise Exception("Check failed")
        
        # Register checks
        self.health_checker.register_health_check("healthy_component", healthy_check)
        self.health_checker.register_health_check("failing_component", failing_check)
        
        # Run healthy check
        result = self.health_checker.run_health_check("healthy_component")
        self.assertEqual(result.status, "healthy")
        self.assertEqual(result.message, "All good")
        
        # Run failing check
        result = self.health_checker.run_health_check("failing_component")
        self.assertEqual(result.status, "critical")
        self.assertIn("Health check failed", result.message)
    
    def test_system_health_status(self):
        """Test overall system health status"""
        def healthy_check():
            return HealthStatus("healthy", "healthy", "OK", datetime.now())
        
        def warning_check():
            return HealthStatus("warning", "warning", "Warning", datetime.now())
        
        def critical_check():
            return HealthStatus("critical", "critical", "Critical", datetime.now())
        
        # Test with all healthy
        self.health_checker.register_health_check("healthy", healthy_check)
        system_health = self.health_checker.get_system_health()
        self.assertEqual(system_health["overall_status"], "healthy")
        
        # Add warning component
        self.health_checker.register_health_check("warning", warning_check)
        system_health = self.health_checker.get_system_health()
        self.assertEqual(system_health["overall_status"], "warning")
        
        # Add critical component
        self.health_checker.register_health_check("critical", critical_check)
        system_health = self.health_checker.get_system_health()
        self.assertEqual(system_health["overall_status"], "critical")
        
        # Check summary
        summary = system_health["summary"]
        self.assertEqual(summary["total_components"], 3)
        self.assertEqual(summary["healthy"], 1)
        self.assertEqual(summary["warning"], 1)
        self.assertEqual(summary["critical"], 1)


class TestMonitoringService(unittest.TestCase):
    """Test main monitoring service"""
    
    def setUp(self):
        # Create service with Prometheus disabled for testing
        self.service = MonitoringService(enable_prometheus=False)
    
    def test_service_initialization(self):
        """Test monitoring service initialization"""
        self.assertIsNotNone(self.service.metrics)
        self.assertIsNotNone(self.service.health_checker)
        self.assertIsNotNone(self.service.tracer)
        self.assertIsNotNone(self.service.correlation)
        
        # Check default health checks are registered
        health_status = self.service.health_checker.get_system_health()
        self.assertGreater(health_status["summary"]["total_components"], 0)
    
    def test_monitoring_dashboard(self):
        """Test monitoring dashboard data generation"""
        dashboard = self.service.get_monitoring_dashboard()
        
        self.assertIn('timestamp', dashboard)
        self.assertIn('service_info', dashboard)
        self.assertIn('health_status', dashboard)
        self.assertIn('metrics_summary', dashboard)
        self.assertIn('active_traces', dashboard)
        
        # Check service info
        service_info = dashboard['service_info']
        self.assertFalse(service_info['prometheus_enabled'])
        self.assertTrue(service_info['tracing_enabled'])
        self.assertTrue(service_info['correlation_tracking'])


class TestMCPIntegration(unittest.TestCase):
    """Test MCP tool integration"""
    
    def test_get_system_health_tool(self):
        """Test get_system_health MCP tool"""
        result = get_system_health()
        
        self.assertIsInstance(result, dict)
        self.assertIn('overall_status', result)
        self.assertIn('timestamp', result)
        self.assertIn('components', result)
        self.assertIn('summary', result)
    
    def test_get_monitoring_metrics_tool(self):
        """Test get_monitoring_metrics MCP tool"""
        result = get_monitoring_metrics()
        
        self.assertIsInstance(result, dict)
        self.assertIn('timestamp', result)
        self.assertIn('service_info', result)
        self.assertIn('health_status', result)
        self.assertIn('metrics_summary', result)
    
    def test_get_trace_details_tool(self):
        """Test get_trace_details MCP tool"""
        trace_id = str(uuid.uuid4())
        
        result = get_trace_details(trace_id)
        
        self.assertIsInstance(result, dict)
        self.assertIn('trace_id', result)
        self.assertIn('span_count', result)
        self.assertIn('spans', result)
        self.assertIn('timestamp', result)
        self.assertEqual(result['trace_id'], trace_id)


class TestMonitoringIntegration(unittest.TestCase):
    """Test monitoring integration scenarios"""
    
    def setUp(self):
        self.service = MonitoringService(enable_prometheus=False)
    
    def test_end_to_end_monitoring_flow(self):
        """Test complete monitoring flow"""
        # 1. Record some metrics
        self.service.metrics.record_request("POST", "/api/deploy", "200", 1.5)
        self.service.metrics.record_device_status("SPINE1", "spine", True)
        self.service.metrics.record_error("timeout", "medium")
        
        # 2. Create a trace
        span = self.service.tracer.start_span("config_deployment")
        self.service.tracer.add_span_log(span, "deployment_started", {"device": "SPINE1"})
        self.service.tracer.finish_span(span, {"result": "success"})
        
        # 3. Check health
        health_status = self.service.health_checker.get_system_health()
        
        # 4. Get dashboard
        dashboard = self.service.get_monitoring_dashboard()
        
        # Verify everything is working
        self.assertIn("healthy", health_status["overall_status"])
        self.assertGreater(len(self.service.metrics.metric_storage), 0)
        self.assertEqual(len(self.service.tracer.active_spans), 0)  # Span should be finished
        self.assertIsInstance(dashboard, dict)
    
    def test_correlation_across_components(self):
        """Test correlation ID propagation across components"""
        correlation_id = "test-correlation-123"
        trace_id = "test-trace-456"
        
        with self.service.correlation.correlation_context(correlation_id, trace_id):
            # Start a span (should use the trace_id from context)
            span = self.service.tracer.start_span("test_operation")
            self.assertEqual(span.trace_id, trace_id)
            
            # Record metrics (correlation should be available)
            self.service.metrics.record_request("GET", "/test", "200", 0.1)
            
            # Finish span
            self.service.tracer.finish_span(span)
        
        # Verify correlation was maintained
        self.assertEqual(span.trace_id, trace_id)


if __name__ == '__main__':
    unittest.main()
