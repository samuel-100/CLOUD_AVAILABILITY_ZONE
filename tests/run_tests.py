#!/usr/bin/env python3
"""
Test Runner for Network Automation System

Comprehensive test execution with reporting, coverage analysis, and performance metrics.
"""

import os
import sys
import time
import unittest
import argparse
import subprocess
import json
from datetime import datetime
from typing import Dict, List, Any
import logging

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import test modules
from tests.test_framework import run_test_suite
from tests.test_integration import run_integration_tests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TestRunner:
    """Comprehensive test runner with reporting and analysis"""
    
    def __init__(self, output_dir: str = "tests/results"):
        self.output_dir = output_dir
        self.start_time = None
        self.results = {
            "timestamp": None,
            "duration": 0,
            "test_suites": {},
            "summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "errors": 0,
                "skipped": 0
            },
            "coverage": {},
            "performance": {}
        }
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
    
    def run_all_tests(self, test_types: List[str] = None) -> Dict[str, Any]:
        """Run all specified test types"""
        self.start_time = time.time()
        self.results["timestamp"] = datetime.now().isoformat()
        
        if test_types is None:
            test_types = ["unit", "integration", "performance"]
        
        print("🧪 Network Automation Test Suite Runner")
        print("=" * 60)
        print(f"Test Types: {', '.join(test_types)}")
        print(f"Output Directory: {self.output_dir}")
        print()
        
        # Run each test type
        for test_type in test_types:
            print(f"Running {test_type} tests...")
            
            if test_type == "unit":
                self._run_unit_tests()
            elif test_type == "integration":
                self._run_integration_tests()
            elif test_type == "performance":
                self._run_performance_tests()
            elif test_type == "coverage":
                self._run_coverage_analysis()
            else:
                print(f"❌ Unknown test type: {test_type}")
        
        # Calculate totals
        self._calculate_summary()
        
        # Generate reports
        self._generate_reports()
        
        self.results["duration"] = time.time() - self.start_time
        
        return self.results
    
    def _run_unit_tests(self):
        """Run unit tests"""
        print("🔬 Running Unit Tests...")
        
        try:
            # Run pytest for better reporting
            result = subprocess.run([
                sys.executable, "-m", "pytest",
                "tests/test_framework.py",
                "tests/test_deployment.py", 
                "tests/test_monitoring.py",
                "-v",
                "--tb=short",
                "--junitxml=" + os.path.join(self.output_dir, "unit_tests.xml"),
                "--html=" + os.path.join(self.output_dir, "unit_tests.html"),
                "--self-contained-html"
            ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
            self.results["test_suites"]["unit"] = {
                "status": "passed" if result.returncode == 0 else "failed",
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "duration": 0  # TODO: Parse from output
            }
            
            print(f"   {'✅ PASSED' if result.returncode == 0 else '❌ FAILED'}")
            
        except Exception as e:
            print(f"   ❌ ERROR: {str(e)}")
            self.results["test_suites"]["unit"] = {
                "status": "error",
                "error": str(e)
            }
    
    def _run_integration_tests(self):
        """Run integration tests"""
        print("🔗 Running Integration Tests...")
        
        try:
            # Import and run integration tests
            success = run_integration_tests()
            
            self.results["test_suites"]["integration"] = {
                "status": "passed" if success else "failed",
                "success": success
            }
            
            print(f"   {'✅ PASSED' if success else '❌ FAILED'}")
            
        except Exception as e:
            print(f"   ❌ ERROR: {str(e)}")
            self.results["test_suites"]["integration"] = {
                "status": "error",
                "error": str(e)
            }
    
    def _run_performance_tests(self):
        """Run performance tests"""
        print("⚡ Running Performance Tests...")
        
        try:
            # Run performance-specific tests
            perf_results = self._execute_performance_benchmarks()
            
            self.results["test_suites"]["performance"] = perf_results
            self.results["performance"] = perf_results.get("benchmarks", {})
            
            print(f"   ✅ COMPLETED")
            
        except Exception as e:
            print(f"   ❌ ERROR: {str(e)}")
            self.results["test_suites"]["performance"] = {
                "status": "error",
                "error": str(e)
            }
    
    def _execute_performance_benchmarks(self) -> Dict[str, Any]:
        """Execute performance benchmarks"""
        benchmarks = {}
        
        # Configuration loading benchmark
        start_time = time.time()
        try:
            from services.deployment_service import ConfigurationManager
            config_manager = ConfigurationManager("testing")
            
            # Benchmark configuration access
            for _ in range(1000):
                config_manager.get_config("api.host", "default")
            
            config_benchmark = time.time() - start_time
            benchmarks["config_access_1000_ops"] = {
                "duration": config_benchmark,
                "operations_per_second": 1000 / config_benchmark
            }
            
        except Exception as e:
            benchmarks["config_access_1000_ops"] = {"error": str(e)}
        
        # Health check benchmark
        start_time = time.time()
        try:
            from services.monitoring_service import MonitoringService
            monitoring_service = MonitoringService(enable_prometheus=False)
            
            # Register test health checks
            def test_health():
                from services.monitoring_service import HealthStatus
                return HealthStatus("test", "healthy", "Test", datetime.now())
            
            for i in range(10):
                monitoring_service.health_checker.register_health_check(f"test_{i}", test_health)
            
            # Benchmark health check execution
            for _ in range(100):
                monitoring_service.health_checker.run_all_health_checks()
            
            health_benchmark = time.time() - start_time
            benchmarks["health_checks_100_runs"] = {
                "duration": health_benchmark,
                "runs_per_second": 100 / health_benchmark
            }
            
        except Exception as e:
            benchmarks["health_checks_100_runs"] = {"error": str(e)}
        
        # Metrics collection benchmark
        start_time = time.time()
        try:
            from services.monitoring_service import MetricsCollector
            metrics_collector = MetricsCollector(enable_server=False)
            
            # Benchmark metrics collection
            for i in range(1000):
                metrics_collector.increment_counter("test_counter", {"iteration": str(i % 10)})
                metrics_collector.set_gauge("test_gauge", float(i), {"batch": str(i // 100)})
            
            metrics_benchmark = time.time() - start_time
            benchmarks["metrics_collection_1000_ops"] = {
                "duration": metrics_benchmark,
                "operations_per_second": 1000 / metrics_benchmark
            }
            
        except Exception as e:
            benchmarks["metrics_collection_1000_ops"] = {"error": str(e)}
        
        return {
            "status": "completed",
            "benchmarks": benchmarks,
            "timestamp": datetime.now().isoformat()
        }
    
    def _run_coverage_analysis(self):
        """Run coverage analysis"""
        print("📊 Running Coverage Analysis...")
        
        try:
            # Run tests with coverage
            result = subprocess.run([
                sys.executable, "-m", "pytest",
                "tests/",
                "--cov=services",
                "--cov=mcp",
                "--cov-report=html:" + os.path.join(self.output_dir, "coverage_html"),
                "--cov-report=xml:" + os.path.join(self.output_dir, "coverage.xml"),
                "--cov-report=json:" + os.path.join(self.output_dir, "coverage.json"),
                "--cov-report=term"
            ], capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
            # Parse coverage results
            coverage_file = os.path.join(self.output_dir, "coverage.json")
            if os.path.exists(coverage_file):
                with open(coverage_file, 'r') as f:
                    coverage_data = json.load(f)
                    self.results["coverage"] = coverage_data.get("totals", {})
            
            self.results["test_suites"]["coverage"] = {
                "status": "completed",
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            print(f"   ✅ COMPLETED")
            
        except Exception as e:
            print(f"   ❌ ERROR: {str(e)}")
            self.results["test_suites"]["coverage"] = {
                "status": "error",
                "error": str(e)
            }
    
    def _calculate_summary(self):
        """Calculate test summary statistics"""
        summary = self.results["summary"]
        
        for suite_name, suite_results in self.results["test_suites"].items():
            if suite_results.get("status") == "passed":
                summary["passed"] += 1
            elif suite_results.get("status") == "failed":
                summary["failed"] += 1
            elif suite_results.get("status") == "error":
                summary["errors"] += 1
            
            summary["total_tests"] += 1
    
    def _generate_reports(self):
        """Generate test reports"""
        # Generate JSON report
        json_report_path = os.path.join(self.output_dir, "test_results.json")
        with open(json_report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate HTML report
        html_report_path = os.path.join(self.output_dir, "test_report.html")
        self._generate_html_report(html_report_path)
        
        # Generate text summary
        summary_path = os.path.join(self.output_dir, "test_summary.txt")
        self._generate_text_summary(summary_path)
        
        print(f"\n📋 Reports generated:")
        print(f"   📄 JSON Report: {json_report_path}")
        print(f"   🌐 HTML Report: {html_report_path}")
        print(f"   📝 Text Summary: {summary_path}")
    
    def _generate_html_report(self, filepath: str):
        """Generate HTML test report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Automation Test Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .test-suite {{ margin: 10px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .passed {{ background-color: #d4edda; }}
        .failed {{ background-color: #f8d7da; }}
        .error {{ background-color: #fff3cd; }}
        .performance {{ margin: 10px 0; }}
        .benchmark {{ margin: 5px 0; padding: 10px; background-color: #e9ecef; }}
        pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🧪 Network Automation Test Results</h1>
        <p><strong>Timestamp:</strong> {self.results['timestamp']}</p>
        <p><strong>Duration:</strong> {self.results['duration']:.2f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Test Suites:</strong> {self.results['summary']['total_tests']}</p>
        <p><strong>✅ Passed:</strong> {self.results['summary']['passed']}</p>
        <p><strong>❌ Failed:</strong> {self.results['summary']['failed']}</p>
        <p><strong>💥 Errors:</strong> {self.results['summary']['errors']}</p>
    </div>
"""
        
        # Add test suite results
        html_content += "<h2>🔍 Test Suite Results</h2>"
        for suite_name, suite_results in self.results["test_suites"].items():
            status_class = suite_results.get("status", "unknown")
            html_content += f"""
    <div class="test-suite {status_class}">
        <h3>{suite_name.title()} Tests</h3>
        <p><strong>Status:</strong> {suite_results.get('status', 'unknown').upper()}</p>
"""
            
            if suite_results.get("error"):
                html_content += f"<p><strong>Error:</strong> {suite_results['error']}</p>"
            
            if suite_results.get("stdout"):
                html_content += f"<details><summary>Output</summary><pre>{suite_results['stdout']}</pre></details>"
            
            html_content += "</div>"
        
        # Add performance results
        if self.results.get("performance"):
            html_content += "<h2>⚡ Performance Benchmarks</h2>"
            for benchmark_name, benchmark_data in self.results["performance"].items():
                html_content += f"""
    <div class="benchmark">
        <h4>{benchmark_name.replace('_', ' ').title()}</h4>
"""
                if "error" in benchmark_data:
                    html_content += f"<p><strong>Error:</strong> {benchmark_data['error']}</p>"
                else:
                    html_content += f"<p><strong>Duration:</strong> {benchmark_data.get('duration', 0):.4f} seconds</p>"
                    if "operations_per_second" in benchmark_data:
                        html_content += f"<p><strong>Ops/sec:</strong> {benchmark_data['operations_per_second']:.2f}</p>"
                    if "runs_per_second" in benchmark_data:
                        html_content += f"<p><strong>Runs/sec:</strong> {benchmark_data['runs_per_second']:.2f}</p>"
                
                html_content += "</div>"
        
        # Add coverage results
        if self.results.get("coverage"):
            html_content += "<h2>📊 Coverage Results</h2>"
            coverage = self.results["coverage"]
            html_content += f"""
    <div class="test-suite">
        <p><strong>Coverage Percentage:</strong> {coverage.get('percent_covered', 0):.1f}%</p>
        <p><strong>Lines Covered:</strong> {coverage.get('covered_lines', 0)}</p>
        <p><strong>Total Lines:</strong> {coverage.get('num_statements', 0)}</p>
        <p><strong>Missing Lines:</strong> {coverage.get('missing_lines', 0)}</p>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html_content)
    
    def _generate_text_summary(self, filepath: str):
        """Generate text summary report"""
        summary_content = f"""
Network Automation Test Results Summary
=====================================

Timestamp: {self.results['timestamp']}
Duration: {self.results['duration']:.2f} seconds

Test Suite Summary:
- Total Test Suites: {self.results['summary']['total_tests']}
- ✅ Passed: {self.results['summary']['passed']}
- ❌ Failed: {self.results['summary']['failed']}
- 💥 Errors: {self.results['summary']['errors']}

Test Suite Details:
"""
        
        for suite_name, suite_results in self.results["test_suites"].items():
            status = suite_results.get("status", "unknown").upper()
            summary_content += f"- {suite_name.title()}: {status}\n"
            
            if suite_results.get("error"):
                summary_content += f"  Error: {suite_results['error']}\n"
        
        if self.results.get("performance"):
            summary_content += "\nPerformance Benchmarks:\n"
            for benchmark_name, benchmark_data in self.results["performance"].items():
                summary_content += f"- {benchmark_name.replace('_', ' ').title()}:\n"
                if "error" in benchmark_data:
                    summary_content += f"  Error: {benchmark_data['error']}\n"
                else:
                    summary_content += f"  Duration: {benchmark_data.get('duration', 0):.4f}s\n"
                    if "operations_per_second" in benchmark_data:
                        summary_content += f"  Ops/sec: {benchmark_data['operations_per_second']:.2f}\n"
        
        if self.results.get("coverage"):
            coverage = self.results["coverage"]
            summary_content += f"\nCoverage Results:\n"
            summary_content += f"- Coverage: {coverage.get('percent_covered', 0):.1f}%\n"
            summary_content += f"- Lines Covered: {coverage.get('covered_lines', 0)}\n"
            summary_content += f"- Total Lines: {coverage.get('num_statements', 0)}\n"
        
        with open(filepath, 'w') as f:
            f.write(summary_content)


def main():
    """Main test runner function"""
    parser = argparse.ArgumentParser(description="Run network automation tests")
    parser.add_argument("--types", "-t", nargs="+", 
                       choices=["unit", "integration", "performance", "coverage"],
                       default=["unit", "integration"],
                       help="Test types to run")
    parser.add_argument("--output", "-o", default="tests/results",
                       help="Output directory for test results")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize test runner
    runner = TestRunner(args.output)
    
    # Run tests
    results = runner.run_all_tests(args.types)
    
    # Print final summary
    print("\n" + "=" * 60)
    print("🎉 Test Execution Complete!")
    print(f"📊 Summary: {results['summary']['passed']} passed, {results['summary']['failed']} failed, {results['summary']['errors']} errors")
    print(f"⏱️ Duration: {results['duration']:.2f} seconds")
    print(f"📁 Results: {args.output}")
    
    # Exit with appropriate code
    if results['summary']['failed'] > 0 or results['summary']['errors'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
