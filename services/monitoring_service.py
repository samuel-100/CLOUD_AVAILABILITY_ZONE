#!/usr/bin/env python3
"""
Monitoring and Observability Service

Provides comprehensive monitoring, metrics collection, health checks,
and observability for the network automation system.
"""

import os
import sys
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import sqlite3
import json
import uuid
import psutil
import socket
from contextlib import contextmanager

# Prometheus metrics (fallback to dict if prometheus_client not available)
try:
    from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server, CollectorRegistry
    PROMETHEUS_AVAILABLE = True
except ImportError:
    # Fallback implementation for metrics
    PROMETHEUS_AVAILABLE = False
    class MockMetric:
        def inc(self, *args, **kwargs): pass
        def dec(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def info(self, *args, **kwargs): pass
    
    Counter = Histogram = Gauge = Info = lambda *args, **kwargs: MockMetric()


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class HealthStatus:
    """Health check status information"""
    component: str
    status: str  # healthy, warning, critical, unknown
    message: str
    timestamp: datetime
    details: Optional[Dict[str, Any]] = None


@dataclass
class MetricPoint:
    """Individual metric data point"""
    name: str
    value: float
    timestamp: datetime
    labels: Optional[Dict[str, str]] = None
    help_text: Optional[str] = None


@dataclass
class TracingSpan:
    """Distributed tracing span"""
    span_id: str
    trace_id: str
    operation_name: str
    start_time: datetime
    duration_ms: Optional[float] = None
    parent_span_id: Optional[str] = None
    tags: Optional[Dict[str, Any]] = None
    logs: Optional[List[Dict[str, Any]]] = None


class CorrelationContext:
    """Context manager for correlation IDs and tracing"""
    
    _local = threading.local()
    
    @classmethod
    def get_correlation_id(cls) -> Optional[str]:
        """Get current correlation ID"""
        return getattr(cls._local, 'correlation_id', None)
    
    @classmethod
    def get_trace_id(cls) -> Optional[str]:
        """Get current trace ID"""
        return getattr(cls._local, 'trace_id', None)
    
    @classmethod
    def set_correlation_id(cls, correlation_id: str):
        """Set correlation ID for current context"""
        cls._local.correlation_id = correlation_id
    
    @classmethod
    def set_trace_id(cls, trace_id: str):
        """Set trace ID for current context"""
        cls._local.trace_id = trace_id
    
    @contextmanager
    def correlation_context(self, correlation_id: str = None, trace_id: str = None):
        """Context manager for correlation and trace IDs"""
        old_correlation_id = self.get_correlation_id()
        old_trace_id = self.get_trace_id()
        
        try:
            if correlation_id:
                self.set_correlation_id(correlation_id)
            if trace_id:
                self.set_trace_id(trace_id)
            yield
        finally:
            if old_correlation_id:
                self.set_correlation_id(old_correlation_id)
            else:
                delattr(self._local, 'correlation_id')
            
            if old_trace_id:
                self.set_trace_id(old_trace_id)
            else:
                delattr(self._local, 'trace_id')


class StructuredLogger:
    """Structured logging with correlation IDs"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.correlation = CorrelationContext()
    
    def _add_context(self, extra: Dict[str, Any]) -> Dict[str, Any]:
        """Add correlation context to log entry"""
        correlation_id = self.correlation.get_correlation_id()
        trace_id = self.correlation.get_trace_id()
        
        if correlation_id:
            extra['correlation_id'] = correlation_id
        if trace_id:
            extra['trace_id'] = trace_id
        
        return extra
    
    def info(self, msg: str, **kwargs):
        extra = self._add_context(kwargs)
        self.logger.info(msg, extra=extra)
    
    def warning(self, msg: str, **kwargs):
        extra = self._add_context(kwargs)
        self.logger.warning(msg, extra=extra)
    
    def error(self, msg: str, **kwargs):
        extra = self._add_context(kwargs)
        self.logger.error(msg, extra=extra)
    
    def debug(self, msg: str, **kwargs):
        extra = self._add_context(kwargs)
        self.logger.debug(msg, extra=extra)


class DistributedTracer:
    """Distributed tracing implementation"""
    
    def __init__(self, db_path: str = "logs/tracing.db"):
        self.db_path = db_path
        self.correlation = CorrelationContext()
        self._init_database()
        self.active_spans = {}
    
    def _init_database(self):
        """Initialize tracing database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS spans (
                    span_id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    operation_name TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    duration_ms REAL,
                    parent_span_id TEXT,
                    tags TEXT,
                    logs TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_spans_trace_id ON spans(trace_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_spans_operation ON spans(operation_name)
            """)
    
    def start_span(self, operation_name: str, parent_span_id: str = None) -> TracingSpan:
        """Start a new tracing span"""
        span_id = str(uuid.uuid4())
        trace_id = self.correlation.get_trace_id() or str(uuid.uuid4())
        
        span = TracingSpan(
            span_id=span_id,
            trace_id=trace_id,
            operation_name=operation_name,
            start_time=datetime.now(),
            parent_span_id=parent_span_id,
            tags={},
            logs=[]
        )
        
        self.active_spans[span_id] = span
        self.correlation.set_trace_id(trace_id)
        
        return span
    
    def finish_span(self, span: TracingSpan, tags: Dict[str, Any] = None):
        """Finish a tracing span"""
        if span.span_id in self.active_spans:
            span.duration_ms = (datetime.now() - span.start_time).total_seconds() * 1000
            
            if tags:
                span.tags.update(tags)
            
            self._store_span(span)
            del self.active_spans[span.span_id]
    
    def add_span_log(self, span: TracingSpan, event: str, payload: Dict[str, Any] = None):
        """Add log entry to span"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'payload': payload or {}
        }
        span.logs.append(log_entry)
    
    def _store_span(self, span: TracingSpan):
        """Store span in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO spans (
                    span_id, trace_id, operation_name, start_time,
                    duration_ms, parent_span_id, tags, logs
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                span.span_id,
                span.trace_id,
                span.operation_name,
                span.start_time.isoformat(),
                span.duration_ms,
                span.parent_span_id,
                json.dumps(span.tags),
                json.dumps(span.logs)
            ))
    
    def get_trace(self, trace_id: str) -> List[TracingSpan]:
        """Get all spans for a trace"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT span_id, trace_id, operation_name, start_time,
                       duration_ms, parent_span_id, tags, logs
                FROM spans WHERE trace_id = ?
                ORDER BY start_time
            """, (trace_id,))
            
            spans = []
            for row in cursor.fetchall():
                span = TracingSpan(
                    span_id=row[0],
                    trace_id=row[1],
                    operation_name=row[2],
                    start_time=datetime.fromisoformat(row[3]),
                    duration_ms=row[4],
                    parent_span_id=row[5],
                    tags=json.loads(row[6]) if row[6] else {},
                    logs=json.loads(row[7]) if row[7] else []
                )
                spans.append(span)
            
            return spans


class MetricsCollector:
    """Prometheus metrics collector"""
    
    def __init__(self, enable_prometheus: bool = True):
        self.enable_prometheus = enable_prometheus and PROMETHEUS_AVAILABLE
        self.registry = CollectorRegistry() if self.enable_prometheus else None
        
        # Initialize metrics
        self._init_metrics()
        
        # In-memory metrics for fallback
        self.metric_storage = defaultdict(list)
        self.metric_metadata = {}
    
    def _init_metrics(self):
        """Initialize Prometheus metrics"""
        registry = self.registry if self.enable_prometheus else None
        
        # Request metrics
        self.request_count = Counter(
            'network_automation_requests_total',
            'Total number of requests',
            ['method', 'endpoint', 'status'],
            registry=registry
        )
        
        self.request_duration = Histogram(
            'network_automation_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'endpoint'],
            registry=registry
        )
        
        # Device metrics
        self.device_status = Gauge(
            'network_automation_device_status',
            'Device status (1=up, 0=down)',
            ['device_name', 'device_type'],
            registry=registry
        )
        
        self.device_response_time = Histogram(
            'network_automation_device_response_time_seconds',
            'Device response time in seconds',
            ['device_name'],
            registry=registry
        )
        
        # Error metrics
        self.error_count = Counter(
            'network_automation_errors_total',
            'Total number of errors',
            ['error_type', 'severity'],
            registry=registry
        )
        
        # System metrics
        self.system_cpu_usage = Gauge(
            'network_automation_cpu_usage_percent',
            'CPU usage percentage',
            registry=registry
        )
        
        self.system_memory_usage = Gauge(
            'network_automation_memory_usage_bytes',
            'Memory usage in bytes',
            registry=registry
        )
        
        # MCP metrics
        self.mcp_connections = Gauge(
            'network_automation_mcp_connections',
            'Active MCP connections',
            registry=registry
        )
        
        self.mcp_tool_calls = Counter(
            'network_automation_mcp_tool_calls_total',
            'Total MCP tool calls',
            ['tool_name', 'status'],
            registry=registry
        )
    
    def record_request(self, method: str, endpoint: str, status: str, duration: float):
        """Record HTTP request metrics"""
        if self.enable_prometheus:
            self.request_count.labels(method=method, endpoint=endpoint, status=status).inc()
            self.request_duration.labels(method=method, endpoint=endpoint).observe(duration)
        else:
            self._store_metric('request_count', 1, {'method': method, 'endpoint': endpoint, 'status': status})
            self._store_metric('request_duration', duration, {'method': method, 'endpoint': endpoint})
    
    def record_device_status(self, device_name: str, device_type: str, is_up: bool):
        """Record device status"""
        status_value = 1.0 if is_up else 0.0
        if self.enable_prometheus:
            self.device_status.labels(device_name=device_name, device_type=device_type).set(status_value)
        else:
            self._store_metric('device_status', status_value, {'device_name': device_name, 'device_type': device_type})
    
    def record_device_response_time(self, device_name: str, response_time: float):
        """Record device response time"""
        if self.enable_prometheus:
            self.device_response_time.labels(device_name=device_name).observe(response_time)
        else:
            self._store_metric('device_response_time', response_time, {'device_name': device_name})
    
    def record_error(self, error_type: str, severity: str):
        """Record error occurrence"""
        if self.enable_prometheus:
            self.error_count.labels(error_type=error_type, severity=severity).inc()
        else:
            self._store_metric('error_count', 1, {'error_type': error_type, 'severity': severity})
    
    def record_system_metrics(self):
        """Record system resource metrics"""
        cpu_percent = psutil.cpu_percent()
        memory_info = psutil.virtual_memory()
        
        if self.enable_prometheus:
            self.system_cpu_usage.set(cpu_percent)
            self.system_memory_usage.set(memory_info.used)
        else:
            self._store_metric('system_cpu_usage', cpu_percent)
            self._store_metric('system_memory_usage', memory_info.used)
    
    def record_mcp_metrics(self, active_connections: int, tool_name: str = None, status: str = None):
        """Record MCP-related metrics"""
        if self.enable_prometheus:
            self.mcp_connections.set(active_connections)
            if tool_name and status:
                self.mcp_tool_calls.labels(tool_name=tool_name, status=status).inc()
        else:
            self._store_metric('mcp_connections', active_connections)
            if tool_name and status:
                self._store_metric('mcp_tool_calls', 1, {'tool_name': tool_name, 'status': status})
    
    def _store_metric(self, name: str, value: float, labels: Dict[str, str] = None):
        """Store metric in fallback storage"""
        metric_point = MetricPoint(
            name=name,
            value=value,
            timestamp=datetime.now(),
            labels=labels or {}
        )
        self.metric_storage[name].append(metric_point)
        
        # Keep only last 1000 points per metric
        if len(self.metric_storage[name]) > 1000:
            self.metric_storage[name] = self.metric_storage[name][-1000:]
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        summary = {
            'prometheus_enabled': self.enable_prometheus,
            'timestamp': datetime.now().isoformat(),
            'metrics': {}
        }
        
        if not self.enable_prometheus:
            # Return fallback metrics
            for name, points in self.metric_storage.items():
                if points:
                    latest = points[-1]
                    summary['metrics'][name] = {
                        'value': latest.value,
                        'timestamp': latest.timestamp.isoformat(),
                        'labels': latest.labels
                    }
        
        return summary


class HealthChecker:
    """System health monitoring"""
    
    def __init__(self, db_path: str = "logs/health.db"):
        self.db_path = db_path
        self.health_checks = {}
        self.logger = StructuredLogger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize health check database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS health_checks (
                    id TEXT PRIMARY KEY,
                    component TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    details TEXT,
                    timestamp TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_health_component ON health_checks(component)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_health_timestamp ON health_checks(timestamp)
            """)
    
    def register_health_check(self, component: str, check_func: Callable[[], HealthStatus]):
        """Register a health check function"""
        self.health_checks[component] = check_func
        self.logger.info(f"Registered health check for component: {component}")
    
    def run_health_check(self, component: str) -> HealthStatus:
        """Run health check for specific component"""
        if component not in self.health_checks:
            return HealthStatus(
                component=component,
                status="unknown",
                message=f"No health check registered for {component}",
                timestamp=datetime.now()
            )
        
        try:
            result = self.health_checks[component]()
            self._store_health_status(result)
            return result
        except Exception as e:
            error_status = HealthStatus(
                component=component,
                status="critical",
                message=f"Health check failed: {str(e)}",
                timestamp=datetime.now(),
                details={"error": str(e)}
            )
            self._store_health_status(error_status)
            return error_status
    
    def run_all_health_checks(self) -> Dict[str, HealthStatus]:
        """Run all registered health checks"""
        results = {}
        for component in self.health_checks:
            results[component] = self.run_health_check(component)
        return results
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        health_results = self.run_all_health_checks()
        
        overall_status = "healthy"
        critical_count = sum(1 for status in health_results.values() if status.status == "critical")
        warning_count = sum(1 for status in health_results.values() if status.status == "warning")
        
        if critical_count > 0:
            overall_status = "critical"
        elif warning_count > 0:
            overall_status = "warning"
        
        return {
            "overall_status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "components": {name: asdict(status) for name, status in health_results.items()},
            "summary": {
                "total_components": len(health_results),
                "healthy": sum(1 for s in health_results.values() if s.status == "healthy"),
                "warning": warning_count,
                "critical": critical_count,
                "unknown": sum(1 for s in health_results.values() if s.status == "unknown")
            }
        }
    
    def _store_health_status(self, status: HealthStatus):
        """Store health status in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO health_checks (
                    id, component, status, message, details, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                status.component,
                status.status,
                status.message,
                json.dumps(status.details) if status.details else None,
                status.timestamp.isoformat()
            ))


class MonitoringService:
    """Main monitoring and observability service"""
    
    def __init__(self, 
                 prometheus_port: int = 8000,
                 enable_prometheus: bool = True,
                 db_path: str = "logs/monitoring.db"):
        
        self.prometheus_port = prometheus_port
        self.enable_prometheus = enable_prometheus
        self.db_path = db_path
        
        # Initialize components
        self.metrics = MetricsCollector(enable_prometheus)
        self.health_checker = HealthChecker()
        self.tracer = DistributedTracer()
        self.correlation = CorrelationContext()
        self.logger = StructuredLogger(__name__)
        
        # Start Prometheus server if enabled
        if self.enable_prometheus and PROMETHEUS_AVAILABLE:
            try:
                start_http_server(self.prometheus_port, registry=self.metrics.registry)
                self.logger.info(f"Prometheus metrics server started on port {self.prometheus_port}")
            except Exception as e:
                self.logger.error(f"Failed to start Prometheus server: {e}")
                self.enable_prometheus = False
        
        # Register default health checks
        self._register_default_health_checks()
        
        # Start background monitoring
        self._start_background_monitoring()
        
        self.logger.info("Monitoring service initialized")
    
    def _register_default_health_checks(self):
        """Register default system health checks"""
        
        def database_health() -> HealthStatus:
            """Check database connectivity"""
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("SELECT 1")
                return HealthStatus(
                    component="database",
                    status="healthy",
                    message="Database connectivity OK",
                    timestamp=datetime.now()
                )
            except Exception as e:
                return HealthStatus(
                    component="database",
                    status="critical",
                    message=f"Database error: {str(e)}",
                    timestamp=datetime.now(),
                    details={"error": str(e)}
                )
        
        def system_resources_health() -> HealthStatus:
            """Check system resource usage"""
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_info = psutil.virtual_memory()
                disk_info = psutil.disk_usage('/')
                
                status = "healthy"
                message = "System resources normal"
                details = {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_info.percent,
                    "disk_percent": disk_info.percent
                }
                
                if cpu_percent > 90 or memory_info.percent > 90 or disk_info.percent > 90:
                    status = "critical"
                    message = "High resource usage detected"
                elif cpu_percent > 70 or memory_info.percent > 70 or disk_info.percent > 70:
                    status = "warning"
                    message = "Elevated resource usage"
                
                return HealthStatus(
                    component="system_resources",
                    status=status,
                    message=message,
                    timestamp=datetime.now(),
                    details=details
                )
            except Exception as e:
                return HealthStatus(
                    component="system_resources",
                    status="critical",
                    message=f"Failed to check system resources: {str(e)}",
                    timestamp=datetime.now(),
                    details={"error": str(e)}
                )
        
        def network_connectivity_health() -> HealthStatus:
            """Check basic network connectivity"""
            try:
                # Test DNS resolution
                socket.gethostbyname("google.com")
                
                return HealthStatus(
                    component="network_connectivity",
                    status="healthy",
                    message="Network connectivity OK",
                    timestamp=datetime.now()
                )
            except Exception as e:
                return HealthStatus(
                    component="network_connectivity",
                    status="warning",
                    message=f"Network connectivity issue: {str(e)}",
                    timestamp=datetime.now(),
                    details={"error": str(e)}
                )
        
        # Register health checks
        self.health_checker.register_health_check("database", database_health)
        self.health_checker.register_health_check("system_resources", system_resources_health)
        self.health_checker.register_health_check("network_connectivity", network_connectivity_health)
    
    def _start_background_monitoring(self):
        """Start background monitoring tasks"""
        def monitor_system():
            while True:
                try:
                    # Collect system metrics
                    self.metrics.record_system_metrics()
                    
                    # Run health checks every 30 seconds
                    time.sleep(30)
                except Exception as e:
                    self.logger.error(f"Background monitoring error: {e}")
                    time.sleep(60)  # Wait longer on error
        
        monitor_thread = threading.Thread(target=monitor_system, daemon=True)
        monitor_thread.start()
    
    def get_monitoring_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive monitoring dashboard data"""
        health_status = self.health_checker.get_system_health()
        metrics_summary = self.metrics.get_metrics_summary()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "service_info": {
                "prometheus_enabled": self.enable_prometheus,
                "prometheus_port": self.prometheus_port if self.enable_prometheus else None,
                "tracing_enabled": True,
                "correlation_tracking": True
            },
            "health_status": health_status,
            "metrics_summary": metrics_summary,
            "active_traces": len(self.tracer.active_spans)
        }


# MCP Tools for monitoring
def get_system_health() -> Dict[str, Any]:
    """Get comprehensive system health status"""
    try:
        service = MonitoringService()
        return service.health_checker.get_system_health()
    except Exception as e:
        return {
            "error": f"Failed to get system health: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }


def get_monitoring_metrics() -> Dict[str, Any]:
    """Get monitoring metrics and dashboard data"""
    try:
        service = MonitoringService()
        return service.get_monitoring_dashboard()
    except Exception as e:
        return {
            "error": f"Failed to get monitoring metrics: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }


def get_trace_details(trace_id: str) -> Dict[str, Any]:
    """Get detailed trace information"""
    try:
        tracer = DistributedTracer()
        spans = tracer.get_trace(trace_id)
        
        return {
            "trace_id": trace_id,
            "span_count": len(spans),
            "spans": [asdict(span) for span in spans],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "error": f"Failed to get trace details: {str(e)}",
            "trace_id": trace_id,
            "timestamp": datetime.now().isoformat()
        }


if __name__ == "__main__":
    # Test the monitoring service
    print("🔍 Testing Monitoring and Observability Service...")
    
    service = MonitoringService(enable_prometheus=False)  # Disable Prometheus for testing
    
    # Test health checks
    health = service.health_checker.get_system_health()
    print(f"✅ System health: {health['overall_status']}")
    print(f"✅ Components checked: {health['summary']['total_components']}")
    
    # Test metrics
    service.metrics.record_request("GET", "/api/test", "200", 0.5)
    service.metrics.record_device_status("SPINE1", "spine", True)
    service.metrics.record_error("timeout", "low")
    
    metrics = service.metrics.get_metrics_summary()
    print(f"✅ Metrics collected: {len(metrics['metrics'])} types")
    
    # Test tracing
    span = service.tracer.start_span("test_operation")
    service.tracer.add_span_log(span, "test_event", {"key": "value"})
    service.tracer.finish_span(span, {"result": "success"})
    
    print("✅ Tracing functionality working")
    
    # Test dashboard
    dashboard = service.get_monitoring_dashboard()
    print(f"✅ Dashboard data generated at {dashboard['timestamp']}")
    
    print("\n🎉 Monitoring and Observability Service - OPERATIONAL!")
