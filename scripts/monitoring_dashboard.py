#!/usr/bin/env python3
"""
Network Automation Monitoring Dashboard

A simple terminal-based monitoring dashboard that displays real-time
system health, metrics, and observability data.
"""

import os
import sys
import time
import json
from datetime import datetime
from typing import Dict, Any

# Add services to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.monitoring_service import MonitoringService, get_system_health, get_monitoring_metrics


class MonitoringDashboard:
    """Terminal-based monitoring dashboard"""
    
    def __init__(self, refresh_interval: int = 30):
        self.refresh_interval = refresh_interval
        self.service = MonitoringService(enable_prometheus=False)  # Use fallback metrics for demo
        
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def format_health_status(self, status: str) -> str:
        """Format health status with colors"""
        colors = {
            'healthy': '\033[92m',      # Green
            'warning': '\033[93m',      # Yellow
            'critical': '\033[91m',     # Red
            'unknown': '\033[94m'       # Blue
        }
        reset = '\033[0m'
        
        return f"{colors.get(status, '')}{status.upper()}{reset}"
    
    def format_metric_value(self, value: float, unit: str = "") -> str:
        """Format metric value with appropriate precision"""
        if isinstance(value, float):
            if value < 1:
                return f"{value:.3f}{unit}"
            elif value < 100:
                return f"{value:.2f}{unit}"
            else:
                return f"{value:.1f}{unit}"
        return f"{value}{unit}"
    
    def render_header(self):
        """Render dashboard header"""
        print("=" * 80)
        print("📊 NETWORK AUTOMATION MONITORING DASHBOARD")
        print("=" * 80)
        print(f"🕒 Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🔄 Refresh Interval: {self.refresh_interval}s")
        print("-" * 80)
    
    def render_system_health(self, health_data: Dict[str, Any]):
        """Render system health section"""
        print("\n🏥 SYSTEM HEALTH")
        print("-" * 40)
        
        overall_status = health_data.get('overall_status', 'unknown')
        print(f"Overall Status: {self.format_health_status(overall_status)}")
        
        summary = health_data.get('summary', {})
        print(f"Components: {summary.get('total_components', 0)} total")
        print(f"  ✅ Healthy: {summary.get('healthy', 0)}")
        print(f"  ⚠️  Warning: {summary.get('warning', 0)}")
        print(f"  🚨 Critical: {summary.get('critical', 0)}")
        print(f"  ❓ Unknown: {summary.get('unknown', 0)}")
        
        # Show component details
        components = health_data.get('components', {})
        if components:
            print("\nComponent Details:")
            for name, component in components.items():
                status = component.get('status', 'unknown')
                message = component.get('message', 'No message')
                print(f"  {name}: {self.format_health_status(status)} - {message}")
    
    def render_metrics_summary(self, metrics_data: Dict[str, Any]):
        """Render metrics summary section"""
        print("\n📈 METRICS SUMMARY")
        print("-" * 40)
        
        metrics = metrics_data.get('metrics', {})
        if not metrics:
            print("No metrics available")
            return
        
        # Group metrics by category
        request_metrics = {}
        device_metrics = {}
        system_metrics = {}
        error_metrics = {}
        mcp_metrics = {}
        
        for name, data in metrics.items():
            if 'request' in name:
                request_metrics[name] = data
            elif 'device' in name:
                device_metrics[name] = data
            elif 'system' in name:
                system_metrics[name] = data
            elif 'error' in name:
                error_metrics[name] = data
            elif 'mcp' in name:
                mcp_metrics[name] = data
        
        # Display system metrics
        if system_metrics:
            print("System Resources:")
            for name, data in system_metrics.items():
                value = data.get('value', 0)
                if 'cpu' in name:
                    print(f"  CPU Usage: {self.format_metric_value(value, '%')}")
                elif 'memory' in name:
                    # Convert bytes to MB
                    mb_value = value / (1024 * 1024)
                    print(f"  Memory Usage: {self.format_metric_value(mb_value, ' MB')}")
        
        # Display request metrics
        if request_metrics:
            print("Request Metrics:")
            for name, data in request_metrics.items():
                value = data.get('value', 0)
                labels = data.get('labels', {})
                if 'count' in name:
                    print(f"  Requests: {int(value)} ({labels.get('status', 'N/A')})")
                elif 'duration' in name:
                    print(f"  Response Time: {self.format_metric_value(value, 's')}")
        
        # Display device metrics
        if device_metrics:
            print("Device Metrics:")
            for name, data in device_metrics.items():
                value = data.get('value', 0)
                labels = data.get('labels', {})
                device_name = labels.get('device_name', 'Unknown')
                if 'status' in name:
                    status = "UP" if value == 1.0 else "DOWN"
                    print(f"  {device_name}: {status}")
                elif 'response_time' in name:
                    print(f"  {device_name} Response: {self.format_metric_value(value, 's')}")
        
        # Display error metrics
        if error_metrics:
            print("Error Metrics:")
            for name, data in error_metrics.items():
                value = data.get('value', 0)
                labels = data.get('labels', {})
                error_type = labels.get('error_type', 'Unknown')
                severity = labels.get('severity', 'Unknown')
                print(f"  {error_type} ({severity}): {int(value)}")
        
        # Display MCP metrics
        if mcp_metrics:
            print("MCP Metrics:")
            for name, data in mcp_metrics.items():
                value = data.get('value', 0)
                if 'connections' in name:
                    print(f"  Active Connections: {int(value)}")
                elif 'tool_calls' in name:
                    labels = data.get('labels', {})
                    tool_name = labels.get('tool_name', 'Unknown')
                    status = labels.get('status', 'Unknown')
                    print(f"  Tool Calls ({tool_name}): {int(value)} ({status})")
    
    def render_service_info(self, service_data: Dict[str, Any]):
        """Render service information section"""
        print("\n⚙️  SERVICE INFORMATION")
        print("-" * 40)
        
        service_info = service_data.get('service_info', {})
        print(f"Prometheus: {'✅ Enabled' if service_info.get('prometheus_enabled') else '❌ Disabled'}")
        
        if service_info.get('prometheus_port'):
            print(f"Metrics Port: {service_info['prometheus_port']}")
        
        print(f"Tracing: {'✅ Enabled' if service_info.get('tracing_enabled') else '❌ Disabled'}")
        print(f"Correlation Tracking: {'✅ Enabled' if service_info.get('correlation_tracking') else '❌ Disabled'}")
        
        active_traces = service_data.get('active_traces', 0)
        print(f"Active Traces: {active_traces}")
    
    def render_footer(self):
        """Render dashboard footer"""
        print("\n" + "-" * 80)
        print("💡 Commands: Press Ctrl+C to exit, wait for auto-refresh")
        print("📚 Monitoring Data: Health checks, metrics, tracing, and observability")
        print("=" * 80)
    
    def run_dashboard(self):
        """Run the monitoring dashboard"""
        print("🚀 Starting Network Automation Monitoring Dashboard...")
        print(f"📊 Dashboard will refresh every {self.refresh_interval} seconds")
        print("🛑 Press Ctrl+C to stop\n")
        
        try:
            while True:
                # Clear screen and render dashboard
                self.clear_screen()
                
                try:
                    # Get monitoring data
                    health_data = get_system_health()
                    monitoring_data = get_monitoring_metrics()
                    
                    # Render dashboard sections
                    self.render_header()
                    self.render_system_health(health_data)
                    self.render_metrics_summary(monitoring_data.get('metrics_summary', {}))
                    self.render_service_info(monitoring_data)
                    self.render_footer()
                    
                except Exception as e:
                    print(f"❌ Error retrieving monitoring data: {e}")
                    print("🔄 Will retry on next refresh...")
                
                # Wait for next refresh
                time.sleep(self.refresh_interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Dashboard stopped by user")
            print("👋 Goodbye!")


class MonitoringCLI:
    """Command-line interface for monitoring operations"""
    
    def __init__(self):
        self.service = MonitoringService(enable_prometheus=False)
    
    def show_health(self):
        """Show system health status"""
        print("🏥 System Health Status")
        print("=" * 50)
        
        health_data = get_system_health()
        overall_status = health_data.get('overall_status', 'unknown')
        
        print(f"Overall Status: {overall_status.upper()}")
        print(f"Timestamp: {health_data.get('timestamp', 'N/A')}")
        
        print("\nComponent Details:")
        components = health_data.get('components', {})
        for name, component in components.items():
            status = component.get('status', 'unknown')
            message = component.get('message', 'No message')
            print(f"  {name}: {status} - {message}")
        
        summary = health_data.get('summary', {})
        print(f"\nSummary:")
        print(f"  Total: {summary.get('total_components', 0)}")
        print(f"  Healthy: {summary.get('healthy', 0)}")
        print(f"  Warning: {summary.get('warning', 0)}")
        print(f"  Critical: {summary.get('critical', 0)}")
        print(f"  Unknown: {summary.get('unknown', 0)}")
    
    def show_metrics(self):
        """Show metrics summary"""
        print("📈 Metrics Summary")
        print("=" * 50)
        
        monitoring_data = get_monitoring_metrics()
        metrics = monitoring_data.get('metrics_summary', {}).get('metrics', {})
        
        if not metrics:
            print("No metrics available")
            return
        
        for name, data in metrics.items():
            value = data.get('value', 0)
            labels = data.get('labels', {})
            timestamp = data.get('timestamp', 'N/A')
            
            print(f"\n{name}:")
            print(f"  Value: {value}")
            print(f"  Labels: {labels}")
            print(f"  Timestamp: {timestamp}")
    
    def show_traces(self, trace_id: str = None):
        """Show trace information"""
        if trace_id:
            print(f"📊 Trace Details: {trace_id}")
            print("=" * 50)
            
            trace_data = get_trace_details(trace_id)
            
            if 'error' in trace_data:
                print(f"Error: {trace_data['error']}")
                return
            
            spans = trace_data.get('spans', [])
            print(f"Trace ID: {trace_id}")
            print(f"Span Count: {len(spans)}")
            
            for span in spans:
                print(f"\nSpan: {span.get('operation_name', 'Unknown')}")
                print(f"  Span ID: {span.get('span_id', 'N/A')}")
                print(f"  Duration: {span.get('duration_ms', 'N/A')} ms")
                print(f"  Tags: {span.get('tags', {})}")
        else:
            print("📊 Active Traces")
            print("=" * 50)
            
            monitoring_data = get_monitoring_metrics()
            active_traces = monitoring_data.get('active_traces', 0)
            print(f"Active Traces: {active_traces}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Automation Monitoring Dashboard")
    parser.add_argument('--mode', choices=['dashboard', 'health', 'metrics', 'traces'], 
                       default='dashboard', help='Display mode')
    parser.add_argument('--trace-id', help='Specific trace ID to show details')
    parser.add_argument('--refresh', type=int, default=30, 
                       help='Dashboard refresh interval in seconds')
    
    args = parser.parse_args()
    
    if args.mode == 'dashboard':
        dashboard = MonitoringDashboard(refresh_interval=args.refresh)
        dashboard.run_dashboard()
    else:
        cli = MonitoringCLI()
        
        if args.mode == 'health':
            cli.show_health()
        elif args.mode == 'metrics':
            cli.show_metrics()
        elif args.mode == 'traces':
            cli.show_traces(args.trace_id)


if __name__ == "__main__":
    main()
