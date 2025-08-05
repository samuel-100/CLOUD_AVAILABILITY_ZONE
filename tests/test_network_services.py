"""
Unit Tests for Network Services

Comprehensive testing of network topology, device management, and network automation functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import asyncio
import json
import tempfile
import os
import sys
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from services.network_topology import NetworkTopologyService
from services.device_details import DeviceDetailsService
from services.network_status import NetworkStatusService
from services.config_generation_tool import ConfigGenerationService
from services.test_connectivity import ConnectivityTestService


class TestNetworkTopology(unittest.TestCase):
    """Test NetworkTopology service functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_topology_data = {
            "devices": {
                "SPINE1": {
                    "type": "spine",
                    "model": "Nexus 9000",
                    "os": "nxos",
                    "mgmt_ip": "192.168.1.10",
                    "interfaces": {
                        "Ethernet1/1": {"neighbor": "LEAF1", "neighbor_interface": "Ethernet1/1"},
                        "Ethernet1/2": {"neighbor": "LEAF2", "neighbor_interface": "Ethernet1/1"}
                    }
                },
                "LEAF1": {
                    "type": "leaf",
                    "model": "IOSv",
                    "os": "ios",
                    "mgmt_ip": "192.168.1.11",
                    "interfaces": {
                        "Ethernet1/1": {"neighbor": "SPINE1", "neighbor_interface": "Ethernet1/1"},
                        "GigabitEthernet0/1": {"description": "Server connection"}
                    }
                }
            },
            "links": [
                {"source": "SPINE1", "target": "LEAF1", "source_interface": "Ethernet1/1", "target_interface": "Ethernet1/1"},
                {"source": "SPINE1", "target": "LEAF2", "source_interface": "Ethernet1/2", "target_interface": "Ethernet1/1"}
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(self.test_topology_data, f)
            self.topology_file = f.name
        
        self.network_topology = NetworkTopologyService(self.topology_file)
    
    def tearDown(self):
        """Clean up test files"""
        if os.path.exists(self.topology_file):
            os.unlink(self.topology_file)
    
    def test_topology_loading(self):
        """Test topology file loading"""
        topology = self.network_topology.get_topology()
        
        self.assertIsNotNone(topology)
        self.assertIn("devices", topology)
        self.assertIn("links", topology)
        self.assertEqual(len(topology["devices"]), 2)
        self.assertEqual(len(topology["links"]), 2)
    
    def test_device_retrieval(self):
        """Test individual device retrieval"""
        spine1 = self.network_topology.get_device("SPINE1")
        
        self.assertIsNotNone(spine1)
        self.assertEqual(spine1["type"], "spine")
        self.assertEqual(spine1["model"], "Nexus 9000")
        self.assertEqual(spine1["mgmt_ip"], "192.168.1.10")
    
    def test_device_filtering(self):
        """Test device filtering by type"""
        spine_devices = self.network_topology.get_devices_by_type("spine")
        leaf_devices = self.network_topology.get_devices_by_type("leaf")
        
        self.assertEqual(len(spine_devices), 1)
        self.assertEqual(len(leaf_devices), 1)
        self.assertEqual(spine_devices[0]["name"], "SPINE1")
        self.assertEqual(leaf_devices[0]["name"], "LEAF1")
    
    def test_neighbor_discovery(self):
        """Test neighbor discovery functionality"""
        neighbors = self.network_topology.get_neighbors("SPINE1")
        
        self.assertIsInstance(neighbors, list)
        self.assertTrue(len(neighbors) >= 1)
        
        # Check if LEAF1 is a neighbor of SPINE1
        neighbor_names = [n["device"] for n in neighbors]
        self.assertIn("LEAF1", neighbor_names)
    
    def test_path_calculation(self):
        """Test path calculation between devices"""
        path = self.network_topology.find_path("SPINE1", "LEAF1")
        
        self.assertIsNotNone(path)
        self.assertIsInstance(path, list)
        self.assertIn("SPINE1", path)
        self.assertIn("LEAF1", path)
    
    def test_topology_validation(self):
        """Test topology validation"""
        is_valid = self.network_topology.validate_topology()
        
        self.assertTrue(is_valid)
    
    def test_interface_mapping(self):
        """Test interface mapping functionality"""
        interfaces = self.network_topology.get_device_interfaces("SPINE1")
        
        self.assertIsInstance(interfaces, dict)
        self.assertIn("Ethernet1/1", interfaces)
        self.assertIn("Ethernet1/2", interfaces)
    
    def test_topology_statistics(self):
        """Test topology statistics calculation"""
        stats = self.network_topology.get_topology_statistics()
        
        self.assertIn("total_devices", stats)
        self.assertIn("total_links", stats)
        self.assertIn("device_types", stats)
        self.assertEqual(stats["total_devices"], 2)
        self.assertEqual(stats["total_links"], 2)


class TestDeviceDetailsService(unittest.TestCase):
    """Test DeviceDetailsService functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.device_service = DeviceDetailsService()
        
        # Mock device inventory
        self.test_devices = {
            "SPINE1": {
                "hostname": "SPINE1",
                "mgmt_ip": "192.168.1.10",
                "device_type": "spine",
                "platform": "nexus",
                "os_version": "9.3(8)",
                "credentials": {
                    "username": "admin",
                    "password": "password"
                }
            },
            "LEAF1": {
                "hostname": "LEAF1",
                "mgmt_ip": "192.168.1.11", 
                "device_type": "leaf",
                "platform": "iosv",
                "os_version": "15.7(3)M3",
                "credentials": {
                    "username": "admin",
                    "password": "password"
                }
            }
        }
    
    @patch('services.device_details.DeviceDetailsService._connect_device')
    def test_device_connection(self, mock_connect):
        """Test device connection"""
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        connection = self.device_service.connect_device("SPINE1", self.test_devices["SPINE1"])
        
        self.assertIsNotNone(connection)
        mock_connect.assert_called_once()
    
    @patch('services.device_details.DeviceDetailsService._connect_device')
    def test_device_info_collection(self, mock_connect):
        """Test device information collection"""
        mock_connection = Mock()
        mock_connection.send_command.return_value = "Cisco Nexus Operating System (NX-OS) Software"
        mock_connect.return_value = mock_connection
        
        device_info = self.device_service.get_device_info("SPINE1", self.test_devices["SPINE1"])
        
        self.assertIsInstance(device_info, dict)
        mock_connect.assert_called_once()
    
    @patch('services.device_details.DeviceDetailsService._connect_device')
    def test_interface_status_collection(self, mock_connect):
        """Test interface status collection"""
        mock_connection = Mock()
        mock_connection.send_command.return_value = """
Interface          Status     Protocol Description
Eth1/1             up         up       Link to LEAF1
Eth1/2             up         up       Link to LEAF2
"""
        mock_connect.return_value = mock_connection
        
        interfaces = self.device_service.get_interface_status("SPINE1", self.test_devices["SPINE1"])
        
        self.assertIsInstance(interfaces, list)
        mock_connect.assert_called_once()
    
    def test_device_filtering(self):
        """Test device filtering functionality"""
        # Filter by device type
        spine_devices = self.device_service.filter_devices(self.test_devices, device_type="spine")
        self.assertEqual(len(spine_devices), 1)
        self.assertIn("SPINE1", spine_devices)
        
        # Filter by platform
        nexus_devices = self.device_service.filter_devices(self.test_devices, platform="nexus")
        self.assertEqual(len(nexus_devices), 1)
        self.assertIn("SPINE1", nexus_devices)
    
    def test_device_validation(self):
        """Test device configuration validation"""
        # Valid device
        is_valid = self.device_service.validate_device_config(self.test_devices["SPINE1"])
        self.assertTrue(is_valid)
        
        # Invalid device (missing required fields)
        invalid_device = {"hostname": "TEST"}
        is_valid = self.device_service.validate_device_config(invalid_device)
        self.assertFalse(is_valid)


class TestNetworkStatusService(unittest.TestCase):
    """Test NetworkStatusService functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.status_service = NetworkStatusService()
    
    @patch('services.network_status.subprocess.run')
    def test_ping_connectivity(self, mock_subprocess):
        """Test ping connectivity check"""
        # Mock successful ping
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "PING 192.168.1.10: 64 bytes: time=1.234ms"
        mock_subprocess.return_value = mock_result
        
        result = self.status_service.ping_device("192.168.1.10")
        
        self.assertTrue(result["success"])
        self.assertEqual(result["host"], "192.168.1.10")
        
        # Mock failed ping
        mock_result.returncode = 1
        mock_result.stderr = "ping: cannot resolve 192.168.1.999"
        
        result = self.status_service.ping_device("192.168.1.999")
        
        self.assertFalse(result["success"])
    
    @patch('socket.create_connection')
    def test_port_connectivity(self, mock_socket):
        """Test port connectivity check"""
        # Mock successful connection
        mock_socket.return_value.__enter__ = Mock()
        mock_socket.return_value.__exit__ = Mock()
        
        result = self.status_service.check_port("192.168.1.10", 22)
        
        self.assertTrue(result["success"])
        self.assertEqual(result["port"], 22)
        
        # Mock failed connection
        mock_socket.side_effect = OSError("Connection refused")
        
        result = self.status_service.check_port("192.168.1.10", 23)
        
        self.assertFalse(result["success"])
    
    @patch('services.network_status.NetworkStatusService.ping_device')
    @patch('services.network_status.NetworkStatusService.check_port')
    def test_comprehensive_status_check(self, mock_check_port, mock_ping):
        """Test comprehensive device status check"""
        # Mock successful checks
        mock_ping.return_value = {"success": True, "response_time": 5.2}
        mock_check_port.return_value = {"success": True, "response_time": 2.1}
        
        device_config = {
            "hostname": "SPINE1",
            "mgmt_ip": "192.168.1.10",
            "management_ports": [22, 443]
        }
        
        result = self.status_service.get_comprehensive_status(device_config)
        
        self.assertTrue(result["overall_status"])
        self.assertTrue(result["connectivity"]["ping"]["success"])
        self.assertEqual(len(result["connectivity"]["ports"]), 2)
    
    def test_status_aggregation(self):
        """Test status aggregation across multiple devices"""
        devices = [
            {"hostname": "SPINE1", "mgmt_ip": "192.168.1.10"},
            {"hostname": "LEAF1", "mgmt_ip": "192.168.1.11"},
            {"hostname": "LEAF2", "mgmt_ip": "192.168.1.12"}
        ]
        
        with patch.object(self.status_service, 'get_comprehensive_status') as mock_status:
            mock_status.side_effect = [
                {"overall_status": True, "device": "SPINE1"},
                {"overall_status": True, "device": "LEAF1"},
                {"overall_status": False, "device": "LEAF2"}
            ]
            
            aggregated_status = self.status_service.get_network_status(devices)
            
            self.assertIn("overall_health", aggregated_status)
            self.assertIn("device_status", aggregated_status)
            self.assertEqual(len(aggregated_status["device_status"]), 3)


class TestConfigGenerationService(unittest.TestCase):
    """Test ConfigGenerationService functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.config_service = ConfigGenerationService()
        
        self.test_device_data = {
            "hostname": "SPINE1",
            "mgmt_ip": "192.168.1.10",
            "device_type": "spine",
            "platform": "nexus",
            "interfaces": {
                "Ethernet1/1": {
                    "description": "Link to LEAF1",
                    "ip_address": "10.0.1.1/30",
                    "neighbor": "LEAF1"
                },
                "Ethernet1/2": {
                    "description": "Link to LEAF2", 
                    "ip_address": "10.0.1.5/30",
                    "neighbor": "LEAF2"
                }
            },
            "bgp": {
                "asn": 65001,
                "router_id": "1.1.1.1",
                "neighbors": [
                    {"ip": "10.0.1.2", "remote_asn": 65011},
                    {"ip": "10.0.1.6", "remote_asn": 65012}
                ]
            }
        }
    
    @patch('services.config_generation_tool.jinja2.Environment')
    def test_template_loading(self, mock_jinja_env):
        """Test template loading functionality"""
        mock_template = Mock()
        mock_jinja_env.return_value.get_template.return_value = mock_template
        
        template = self.config_service.load_template("spine_config.j2")
        
        self.assertIsNotNone(template)
        mock_jinja_env.return_value.get_template.assert_called_with("spine_config.j2")
    
    @patch('services.config_generation_tool.jinja2.Environment')
    def test_config_generation(self, mock_jinja_env):
        """Test configuration generation"""
        mock_template = Mock()
        mock_template.render.return_value = "hostname SPINE1\ninterface Ethernet1/1"
        mock_jinja_env.return_value.get_template.return_value = mock_template
        
        config = self.config_service.generate_device_config(self.test_device_data, "spine_config.j2")
        
        self.assertIsNotNone(config)
        self.assertIn("hostname SPINE1", config)
        mock_template.render.assert_called_once_with(device=self.test_device_data)
    
    def test_config_validation(self):
        """Test configuration validation"""
        valid_config = """
hostname SPINE1
interface Ethernet1/1
 description Link to LEAF1
 ip address 10.0.1.1 255.255.255.252
"""
        
        is_valid = self.config_service.validate_config(valid_config, "ios")
        self.assertTrue(is_valid)
        
        # Test invalid config
        invalid_config = "invalid command syntax"
        is_valid = self.config_service.validate_config(invalid_config, "ios")
        self.assertFalse(is_valid)
    
    def test_config_backup(self):
        """Test configuration backup functionality"""
        config_content = "hostname SPINE1\ninterface Ethernet1/1"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_path = self.config_service.backup_config("SPINE1", config_content, temp_dir)
            
            self.assertTrue(os.path.exists(backup_path))
            
            with open(backup_path, 'r') as f:
                saved_content = f.read()
            
            self.assertEqual(saved_content, config_content)
    
    def test_bulk_config_generation(self):
        """Test bulk configuration generation"""
        devices = [
            {**self.test_device_data, "hostname": "SPINE1"},
            {**self.test_device_data, "hostname": "SPINE2", "mgmt_ip": "192.168.1.20"}
        ]
        
        with patch.object(self.config_service, 'generate_device_config') as mock_generate:
            mock_generate.return_value = "sample config"
            
            configs = self.config_service.generate_bulk_configs(devices, "spine_config.j2")
            
            self.assertEqual(len(configs), 2)
            self.assertIn("SPINE1", configs)
            self.assertIn("SPINE2", configs)
            self.assertEqual(mock_generate.call_count, 2)


class TestConnectivityTestService(unittest.TestCase):
    """Test ConnectivityTestService functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.connectivity_service = ConnectivityTestService()
    
    @patch('subprocess.run')
    def test_ping_test(self, mock_subprocess):
        """Test ping connectivity test"""
        # Mock successful ping
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "PING 192.168.1.10: 5 packets transmitted, 5 received, 0% packet loss"
        mock_subprocess.return_value = mock_result
        
        result = self.connectivity_service.ping_test("192.168.1.10", count=5)
        
        self.assertTrue(result["success"])
        self.assertEqual(result["packets_sent"], 5)
        self.assertEqual(result["packet_loss"], 0)
    
    @patch('subprocess.run')
    def test_traceroute_test(self, mock_subprocess):
        """Test traceroute functionality"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
traceroute to 192.168.1.10, 30 hops max
1  192.168.1.1  1.234 ms
2  192.168.1.10  2.567 ms
"""
        mock_subprocess.return_value = mock_result
        
        result = self.connectivity_service.traceroute_test("192.168.1.10")
        
        self.assertTrue(result["success"])
        self.assertIn("hops", result)
        self.assertGreater(len(result["hops"]), 0)
    
    @patch('socket.create_connection')
    def test_port_scan(self, mock_socket):
        """Test port scanning functionality"""
        # Mock successful connections
        mock_socket.return_value.__enter__ = Mock()
        mock_socket.return_value.__exit__ = Mock()
        
        ports = [22, 23, 80, 443]
        results = self.connectivity_service.port_scan("192.168.1.10", ports)
        
        self.assertIsInstance(results, dict)
        self.assertEqual(len(results), len(ports))
        
        for port in ports:
            self.assertIn(port, results)
            self.assertIn("status", results[port])
    
    def test_bandwidth_test_simulation(self):
        """Test bandwidth test simulation"""
        # Since actual bandwidth testing requires real network, we simulate
        result = self.connectivity_service.simulate_bandwidth_test("192.168.1.10")
        
        self.assertIn("download_speed", result)
        self.assertIn("upload_speed", result)
        self.assertIn("latency", result)
        self.assertIsInstance(result["download_speed"], (int, float))
    
    def test_connectivity_report_generation(self):
        """Test connectivity report generation"""
        test_results = {
            "ping": {"success": True, "packet_loss": 0},
            "traceroute": {"success": True, "hops": 3},
            "port_scan": {22: {"status": "open"}, 80: {"status": "closed"}}
        }
        
        report = self.connectivity_service.generate_connectivity_report("192.168.1.10", test_results)
        
        self.assertIsInstance(report, dict)
        self.assertIn("summary", report)
        self.assertIn("detailed_results", report)
        self.assertIn("recommendations", report)


class TestNetworkServicesIntegration(unittest.TestCase):
    """Test integration between network services"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary topology file
        self.test_topology = {
            "devices": {
                "SPINE1": {
                    "type": "spine",
                    "mgmt_ip": "192.168.1.10",
                    "platform": "nexus"
                },
                "LEAF1": {
                    "type": "leaf", 
                    "mgmt_ip": "192.168.1.11",
                    "platform": "iosv"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(self.test_topology, f)
            self.topology_file = f.name
        
        self.network_topology = NetworkTopologyService(self.topology_file)
        self.device_service = DeviceDetailsService()
        self.status_service = NetworkStatusService()
        self.config_service = ConfigGenerationService()
    
    def tearDown(self):
        """Clean up test files"""
        if os.path.exists(self.topology_file):
            os.unlink(self.topology_file)
    
    @patch('services.device_details.DeviceDetailsService._connect_device')
    @patch('services.network_status.NetworkStatusService.ping_device')
    def test_end_to_end_network_discovery(self, mock_ping, mock_connect):
        """Test end-to-end network discovery workflow"""
        # Mock successful connectivity
        mock_ping.return_value = {"success": True, "response_time": 5.0}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Get devices from topology
        devices = self.network_topology.get_all_devices()
        self.assertEqual(len(devices), 2)
        
        # Test connectivity to each device
        for device in devices:
            connectivity_result = self.status_service.ping_device(device["mgmt_ip"])
            self.assertTrue(connectivity_result["success"])
        
        # Test device information collection
        for device in devices:
            device_info = self.device_service.get_device_info(device["name"], device)
            self.assertIsInstance(device_info, dict)
    
    @patch('services.config_generation_tool.jinja2.Environment')
    def test_topology_driven_config_generation(self, mock_jinja_env):
        """Test configuration generation based on topology"""
        mock_template = Mock()
        mock_template.render.return_value = "hostname SPINE1"
        mock_jinja_env.return_value.get_template.return_value = mock_template
        
        # Get spine devices from topology
        spine_devices = self.network_topology.get_devices_by_type("spine")
        self.assertEqual(len(spine_devices), 1)
        
        # Generate configs for spine devices
        for device in spine_devices:
            config = self.config_service.generate_device_config(device, "spine_config.j2")
            self.assertIsNotNone(config)
            self.assertIn("hostname", config)
    
    def test_network_health_assessment(self):
        """Test comprehensive network health assessment"""
        # Get all devices from topology
        devices = self.network_topology.get_all_devices()
        
        with patch.object(self.status_service, 'get_comprehensive_status') as mock_status:
            # Mock mixed health status
            mock_status.side_effect = [
                {"overall_status": True, "device": "SPINE1"},
                {"overall_status": False, "device": "LEAF1"}
            ]
            
            network_health = self.status_service.get_network_status(devices)
            
            self.assertIn("overall_health", network_health)
            self.assertIn("device_status", network_health)
            
            # Verify that unhealthy devices are identified
            unhealthy_devices = [
                device for device in network_health["device_status"] 
                if not device.get("overall_status", False)
            ]
            self.assertEqual(len(unhealthy_devices), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
