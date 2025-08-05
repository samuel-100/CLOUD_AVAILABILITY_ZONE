#!/usr/bin/env python3
"""
Simple Test Runner for Network Automation System

Basic test execution without complex dependencies.
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path
import yaml

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_basic_imports():
    """Test that core modules can be imported"""
    print("🔍 Testing module imports...")
    
    try:
        from services.network_topology import NetworkTopologyService
        print("   ✅ NetworkTopologyService imported successfully")
    except Exception as e:
        print(f"   ❌ NetworkTopologyService import failed: {e}")
        return False
    
    try:
        from services.device_details import DeviceDetailsService  
        print("   ✅ DeviceDetailsService imported successfully")
    except Exception as e:
        print(f"   ❌ DeviceDetailsService import failed: {e}")
        return False
    
    try:
        from services.monitoring_service import MonitoringService
        print("   ✅ MonitoringService imported successfully")
    except Exception as e:
        print(f"   ❌ MonitoringService import failed: {e}")
        return False
    
    try:
        from services.deployment_service import DeploymentService
        print("   ✅ DeploymentService imported successfully")
    except Exception as e:
        print(f"   ❌ DeploymentService import failed: {e}")
        return False
    
    return True

def test_config_files():
    """Test that configuration files exist and are valid"""
    print("\n📁 Testing configuration files...")
    
    base_dir = Path(__file__).parent.parent
    
    # Test YAML files
    yaml_files = [
        "network_topology.yaml",
        "devices.yaml", 
        "datacenter_topology.yaml"
    ]
    
    for yaml_file in yaml_files:
        file_path = base_dir / yaml_file
        try:
            if file_path.exists():
                with open(file_path, 'r') as f:
                    yaml.safe_load(f)
                print(f"   ✅ {yaml_file} is valid")
            else:
                print(f"   ⚠️  {yaml_file} not found")
        except Exception as e:
            print(f"   ❌ {yaml_file} validation failed: {e}")
            return False
    
    return True

def test_network_topology_service():
    """Test NetworkTopologyService basic functionality"""
    print("\n🌐 Testing NetworkTopologyService...")
    
    try:
        from services.network_topology import NetworkTopologyService
        
        # Test service initialization
        base_dir = Path(__file__).parent.parent
        service = NetworkTopologyService(base_dir)
        print("   ✅ Service initialized successfully")
        
        # Test topology retrieval
        topology = service.get_network_topology()
        print(f"   ✅ Topology retrieved: {topology.architecture}")
        print(f"   ✅ Found {len(topology.devices)} devices")
        
        return True
        
    except Exception as e:
        print(f"   ❌ NetworkTopologyService test failed: {e}")
        return False

def test_monitoring_service():
    """Test MonitoringService basic functionality"""
    print("\n📊 Testing MonitoringService...")
    
    try:
        from services.monitoring_service import MonitoringService
        
        # Test service initialization with minimal config
        service = MonitoringService(enable_prometheus=False)
        print("   ✅ Service initialized successfully")
        
        # Test metrics collection
        service.metrics.record_request("GET", "/test", "success", 0.1)
        service.metrics.record_device_status("test_device", "spine", True)
        print("   ✅ Metrics collection working")
        
        # Test health check registration
        def test_health():
            from services.monitoring_service import HealthStatus
            from datetime import datetime
            return HealthStatus("test", "healthy", "Test health check", datetime.now())
        
        service.health_checker.register_health_check("test_service", test_health)
        health_results = service.health_checker.run_all_health_checks()
        print(f"   ✅ Health checks working: {len(health_results)} checks")
        
        return True
        
    except Exception as e:
        print(f"   ❌ MonitoringService test failed: {e}")
        return False

def test_deployment_service():
    """Test DeploymentService basic functionality"""
    print("\n🚀 Testing DeploymentService...")
    
    try:
        from services.deployment_service import DeploymentService
        
        # Test service initialization
        service = DeploymentService()
        print("   ✅ Service initialized successfully")
        
        # Test configuration management
        config_manager = service.config_manager
        test_value = config_manager.get_config("test.key", "default_value")
        print(f"   ✅ Configuration management working: {test_value}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ DeploymentService test failed: {e}")
        return False

def run_all_tests():
    """Run all basic tests"""
    print("🧪 Network Automation Basic Test Suite")
    print("=" * 60)
    
    tests = [
        ("Module Imports", test_basic_imports),
        ("Configuration Files", test_config_files),
        ("Network Topology Service", test_network_topology_service),
        ("Monitoring Service", test_monitoring_service),
        ("Deployment Service", test_deployment_service),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n🔬 Running {test_name} tests...")
        try:
            result = test_func()
            results.append((test_name, result))
            if result:
                print(f"   🎉 {test_name} tests PASSED")
            else:
                print(f"   💥 {test_name} tests FAILED")
        except Exception as e:
            print(f"   💥 {test_name} tests ERROR: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 Test Results Summary:")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {status}: {test_name}")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! System is ready for production.")
        return True
    else:
        print("⚠️  Some tests failed. Please review and fix issues.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
