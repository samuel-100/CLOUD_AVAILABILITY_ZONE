#!/usr/bin/env python3
"""
Device Details Service for MCP Integration
Provides detailed information about individual network devices including
interface status, configuration snippets, and operational data.
"""

import os
import yaml
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import json
import re
from netmiko import ConnectHandler

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class InterfaceDetails:
    """Interface detailed information"""
    name: str
    status: str  # 'up', 'down', 'admin-down'
    protocol: str  # 'up', 'down'
    ip_address: Optional[str] = None
    description: Optional[str] = None
    mtu: Optional[int] = None
    speed: Optional[str] = None
    duplex: Optional[str] = None
    last_input: Optional[str] = None
    last_output: Optional[str] = None
    input_packets: Optional[int] = None
    output_packets: Optional[int] = None
    input_errors: Optional[int] = None
    output_errors: Optional[int] = None

@dataclass
class DeviceDetailsResponse:
    """Complete device details response"""
    device_name: str
    timestamp: str
    reachable: bool
    device_type: str  # 'ios', 'nxos'
    system_info: Dict[str, Any]
    interfaces: Dict[str, InterfaceDetails]
    routing_info: Dict[str, Any]
    protocol_details: Dict[str, Any]
    configuration_snippets: Dict[str, str]
    performance_data: Dict[str, Any]
    error_details: Optional[str] = None

class DeviceDetailsService:
    """Service for collecting detailed device information"""
    
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(__file__).parent.parent
        self.topology_file = self.base_dir / "network_topology.yaml"
        self.devices_file = self.base_dir / "devices.yaml"
        self._load_configuration()
    
    def _load_configuration(self):
        """Load network topology and device configurations"""
        try:
            with open(self.topology_file) as f:
                self.topology = yaml.safe_load(f)['topology']
            
            with open(self.devices_file) as f:
                devices_config = yaml.safe_load(f)
                self.device_credentials = {
                    device['name']: {
                        'username': device['username'],
                        'password': device['password'],
                        'mgmt_ip': device['mgmt_ip']
                    }
                    for device in devices_config['devices']
                }
            
            logger.info(f"Loaded configuration for {len(self.topology['devices'])} devices")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def _find_device_in_topology(self, device_name: str) -> Optional[Dict]:
        """Find device in topology configuration"""
        for device in self.topology['devices']:
            if device['name'] == device_name:
                return device
        return None
    
    def _get_device_connection(self, device_name: str) -> Optional[ConnectHandler]:
        """Establish connection to device"""
        device = self._find_device_in_topology(device_name)
        credentials = self.device_credentials.get(device_name)
        
        if not device or not credentials:
            logger.error(f"Device {device_name} not found in configuration")
            return None
        
        try:
            ip = credentials['mgmt_ip'].split('/')[0]
            device_os = device.get('os', 'ios')
            
            if device_os == 'nxos':
                netmiko_device_type = 'cisco_nxos'
            else:
                netmiko_device_type = 'cisco_ios'
            
            params = {
                'device_type': netmiko_device_type,
                'host': ip,
                'username': credentials['username'],
                'password': credentials['password'],
                'timeout': 30,
                'fast_cli': False
            }
            
            net_connect = ConnectHandler(**params)
            net_connect.enable()
            return net_connect
            
        except Exception as e:
            logger.error(f"Failed to connect to {device_name}: {e}")
            return None
    
    def _collect_system_info(self, net_connect, device_os: str) -> Dict[str, Any]:
        """Collect system information"""
        system_info = {}
        
        try:
            # Version information
            version_output = net_connect.send_command('show version')
            system_info['version_output'] = version_output
            
            # Extract key information
            if device_os == 'nxos':
                # NX-OS specific parsing
                hostname_match = re.search(r'Device name:\s*(\S+)', version_output)
                if hostname_match:
                    system_info['hostname'] = hostname_match.group(1)
                
                uptime_match = re.search(r'Kernel uptime is\s*(.+)', version_output)
                if uptime_match:
                    system_info['uptime'] = uptime_match.group(1)
                
                version_match = re.search(r'system:\s*version\s*(\S+)', version_output)
                if version_match:
                    system_info['os_version'] = version_match.group(1)
            else:
                # IOS specific parsing
                hostname_match = re.search(r'(\S+)\s+uptime is', version_output)
                if hostname_match:
                    system_info['hostname'] = hostname_match.group(1)
                
                uptime_match = re.search(r'uptime is\s*(.+)', version_output)
                if uptime_match:
                    system_info['uptime'] = uptime_match.group(1)
                
                version_match = re.search(r'Cisco IOS Software.*Version\s*(\S+)', version_output)
                if version_match:
                    system_info['os_version'] = version_match.group(1)
            
            # Memory and CPU info
            if device_os == 'nxos':
                resources = net_connect.send_command('show system resources')
                system_info['resources'] = resources[:1000]  # Truncate for storage
            else:
                processes = net_connect.send_command('show processes cpu')
                system_info['cpu_info'] = processes[:1000]  # Truncate for storage
                
                memory = net_connect.send_command('show memory summary')
                system_info['memory_info'] = memory[:1000]  # Truncate for storage
            
        except Exception as e:
            logger.warning(f"Error collecting system info: {e}")
            system_info['error'] = str(e)
        
        return system_info
    
    def _collect_interface_details(self, net_connect, device_os: str) -> Dict[str, InterfaceDetails]:
        """Collect detailed interface information"""
        interfaces = {}
        
        try:
            # Get interface brief
            if device_os == 'nxos':
                brief_output = net_connect.send_command('show interface brief')
            else:
                brief_output = net_connect.send_command('show ip interface brief')
            
            # Parse interface brief for basic info
            interface_names = []
            for line in brief_output.split('\n'):
                if device_os == 'nxos':
                    if 'Eth' in line or 'mgmt' in line:
                        parts = line.split()
                        if parts:
                            interface_names.append(parts[0])
                else:
                    if 'GigabitEthernet' in line or 'FastEthernet' in line or 'Ethernet' in line:
                        parts = line.split()
                        if parts:
                            interface_names.append(parts[0])
            
            # Get detailed info for each interface (limit to first 10 to avoid timeout)
            for interface_name in interface_names[:10]:
                try:
                    interface_output = net_connect.send_command(f'show interface {interface_name}')
                    interface_details = self._parse_interface_output(interface_name, interface_output, device_os)
                    interfaces[interface_name] = interface_details
                except Exception as e:
                    logger.debug(f"Error getting details for interface {interface_name}: {e}")
                    interfaces[interface_name] = InterfaceDetails(
                        name=interface_name,
                        status='unknown',
                        protocol='unknown'
                    )
            
        except Exception as e:
            logger.warning(f"Error collecting interface details: {e}")
        
        return interfaces
    
    def _parse_interface_output(self, interface_name: str, output: str, device_os: str) -> InterfaceDetails:
        """Parse interface output to extract details"""
        details = InterfaceDetails(name=interface_name, status='unknown', protocol='unknown')
        
        try:
            # Status and protocol
            if device_os == 'nxos':
                status_match = re.search(r'is\s+(up|down|admin-down)', output)
                if status_match:
                    details.status = status_match.group(1)
                
                protocol_match = re.search(r'line protocol is\s+(up|down)', output)
                if protocol_match:
                    details.protocol = protocol_match.group(1)
            else:
                status_match = re.search(r'is\s+(up|down|administratively down)', output)
                if status_match:
                    details.status = status_match.group(1).replace('administratively down', 'admin-down')
                
                protocol_match = re.search(r'line protocol is\s+(up|down)', output)
                if protocol_match:
                    details.protocol = protocol_match.group(1)
            
            # IP address
            ip_match = re.search(r'Internet address is\s+(\S+)', output)
            if ip_match:
                details.ip_address = ip_match.group(1)
            
            # Description
            desc_match = re.search(r'Description:\s*(.+)', output)
            if desc_match:
                details.description = desc_match.group(1).strip()
            
            # MTU
            mtu_match = re.search(r'MTU\s+(\d+)', output)
            if mtu_match:
                details.mtu = int(mtu_match.group(1))
            
            # Speed and duplex
            speed_match = re.search(r'(\d+)\s*Mbps', output)
            if speed_match:
                details.speed = f"{speed_match.group(1)} Mbps"
            
            duplex_match = re.search(r'(full|half)-duplex', output)
            if duplex_match:
                details.duplex = f"{duplex_match.group(1)}-duplex"
            
            # Packet counters
            input_packets_match = re.search(r'(\d+)\s+packets input', output)
            if input_packets_match:
                details.input_packets = int(input_packets_match.group(1))
            
            output_packets_match = re.search(r'(\d+)\s+packets output', output)
            if output_packets_match:
                details.output_packets = int(output_packets_match.group(1))
            
            # Error counters
            input_errors_match = re.search(r'(\d+)\s+input errors', output)
            if input_errors_match:
                details.input_errors = int(input_errors_match.group(1))
            
            output_errors_match = re.search(r'(\d+)\s+output errors', output)
            if output_errors_match:
                details.output_errors = int(output_errors_match.group(1))
            
        except Exception as e:
            logger.debug(f"Error parsing interface {interface_name}: {e}")
        
        return details
    
    def _collect_routing_info(self, net_connect, device_os: str) -> Dict[str, Any]:
        """Collect routing information"""
        routing_info = {}
        
        try:
            # Routing table
            route_output = net_connect.send_command('show ip route')
            routing_info['routing_table'] = route_output[:2000]  # Truncate for storage
            
            # OSPF neighbors
            ospf_output = net_connect.send_command('show ip ospf neighbor')
            routing_info['ospf_neighbors'] = ospf_output
            
            # BGP summary
            bgp_output = net_connect.send_command('show bgp summary')
            routing_info['bgp_summary'] = bgp_output
            
        except Exception as e:
            logger.warning(f"Error collecting routing info: {e}")
            routing_info['error'] = str(e)
        
        return routing_info
    
    def _collect_protocol_details(self, net_connect, device_os: str) -> Dict[str, Any]:
        """Collect detailed protocol information"""
        protocol_details = {}
        
        try:
            # OSPF details
            try:
                ospf_database = net_connect.send_command('show ip ospf database')
                protocol_details['ospf_database'] = ospf_database[:1500]  # Truncate
            except:
                protocol_details['ospf_database'] = 'Not available'
            
            # BGP details
            try:
                bgp_neighbors = net_connect.send_command('show bgp neighbors')
                protocol_details['bgp_neighbors'] = bgp_neighbors[:1500]  # Truncate
            except:
                protocol_details['bgp_neighbors'] = 'Not available'
            
        except Exception as e:
            logger.warning(f"Error collecting protocol details: {e}")
            protocol_details['error'] = str(e)
        
        return protocol_details
    
    def _collect_configuration_snippets(self, net_connect, device_os: str) -> Dict[str, str]:
        """Collect key configuration snippets"""
        config_snippets = {}
        
        try:
            # Interface configurations
            if device_os == 'nxos':
                interface_config = net_connect.send_command('show running-config interface')
            else:
                interface_config = net_connect.send_command('show running-config | section interface')
            config_snippets['interfaces'] = interface_config[:2000]  # Truncate
            
            # Routing protocol configurations
            if device_os == 'nxos':
                routing_config = net_connect.send_command('show running-config | include "router|ip route"')
            else:
                routing_config = net_connect.send_command('show running-config | section router')
            config_snippets['routing'] = routing_config[:1500]  # Truncate
            
        except Exception as e:
            logger.warning(f"Error collecting configuration snippets: {e}")
            config_snippets['error'] = str(e)
        
        return config_snippets
    
    def _collect_performance_data(self, net_connect, device_os: str) -> Dict[str, Any]:
        """Collect performance and operational data"""
        performance_data = {}
        
        try:
            # CPU utilization
            if device_os == 'nxos':
                cpu_output = net_connect.send_command('show system resources')
                cpu_match = re.search(r'CPU states\s*:\s*(\d+\.\d+)%', cpu_output)
                if cpu_match:
                    performance_data['cpu_utilization'] = float(cpu_match.group(1))
            else:
                cpu_output = net_connect.send_command('show processes cpu | include CPU')
                cpu_match = re.search(r'CPU utilization.*?(\d+)%', cpu_output)
                if cpu_match:
                    performance_data['cpu_utilization'] = float(cpu_match.group(1))
            
            # Memory utilization
            if device_os == 'nxos':
                memory_match = re.search(r'Memory usage:\s*(\d+)K total,\s*(\d+)K used', cpu_output)
                if memory_match:
                    total_mem = int(memory_match.group(1))
                    used_mem = int(memory_match.group(2))
                    performance_data['memory_utilization'] = (used_mem / total_mem) * 100
            else:
                memory_output = net_connect.send_command('show memory summary')
                memory_match = re.search(r'Processor\s+(\d+)\s+(\d+)\s+(\d+)', memory_output)
                if memory_match:
                    total_mem = int(memory_match.group(1))
                    used_mem = int(memory_match.group(2))
                    performance_data['memory_utilization'] = (used_mem / total_mem) * 100
            
            # Interface statistics summary
            interface_stats = {}
            if device_os == 'nxos':
                stats_output = net_connect.send_command('show interface brief')
            else:
                stats_output = net_connect.send_command('show ip interface brief')
            
            up_count = len([line for line in stats_output.split('\n') if 'up' in line.lower()])
            total_count = len([line for line in stats_output.split('\n') if ('Eth' in line or 'Gigabit' in line or 'Fast' in line)])
            
            interface_stats['interfaces_up'] = up_count
            interface_stats['total_interfaces'] = total_count
            interface_stats['availability_percentage'] = (up_count / total_count * 100) if total_count > 0 else 0
            
            performance_data['interface_stats'] = interface_stats
            
        except Exception as e:
            logger.warning(f"Error collecting performance data: {e}")
            performance_data['error'] = str(e)
        
        return performance_data
    
    def get_device_details(self, device_name: str) -> DeviceDetailsResponse:
        """Get comprehensive details for a specific device"""
        logger.info(f"Collecting detailed information for device: {device_name}")
        
        device = self._find_device_in_topology(device_name)
        if not device:
            return DeviceDetailsResponse(
                device_name=device_name,
                timestamp=datetime.now().isoformat(),
                reachable=False,
                device_type='unknown',
                system_info={},
                interfaces={},
                routing_info={},
                protocol_details={},
                configuration_snippets={},
                performance_data={},
                error_details=f"Device {device_name} not found in topology"
            )
        
        device_os = device.get('os', 'ios')
        net_connect = self._get_device_connection(device_name)
        
        if not net_connect:
            return DeviceDetailsResponse(
                device_name=device_name,
                timestamp=datetime.now().isoformat(),
                reachable=False,
                device_type=device_os,
                system_info={},
                interfaces={},
                routing_info={},
                protocol_details={},
                configuration_snippets={},
                performance_data={},
                error_details=f"Failed to connect to device {device_name}"
            )
        
        try:
            # Collect all information
            system_info = self._collect_system_info(net_connect, device_os)
            interfaces = self._collect_interface_details(net_connect, device_os)
            routing_info = self._collect_routing_info(net_connect, device_os)
            protocol_details = self._collect_protocol_details(net_connect, device_os)
            config_snippets = self._collect_configuration_snippets(net_connect, device_os)
            performance_data = self._collect_performance_data(net_connect, device_os)
            
            response = DeviceDetailsResponse(
                device_name=device_name,
                timestamp=datetime.now().isoformat(),
                reachable=True,
                device_type=device_os,
                system_info=system_info,
                interfaces=interfaces,
                routing_info=routing_info,
                protocol_details=protocol_details,
                configuration_snippets=config_snippets,
                performance_data=performance_data
            )
            
            logger.info(f"Successfully collected details for {device_name}")
            return response
            
        except Exception as e:
            logger.error(f"Error collecting details for {device_name}: {e}")
            return DeviceDetailsResponse(
                device_name=device_name,
                timestamp=datetime.now().isoformat(),
                reachable=False,
                device_type=device_os,
                system_info={},
                interfaces={},
                routing_info={},
                protocol_details={},
                configuration_snippets={},
                performance_data={},
                error_details=str(e)
            )
        
        finally:
            if net_connect:
                net_connect.disconnect()

# Convenience function for MCP integration
def get_device_details(device_name: str) -> Dict[str, Any]:
    """Get device details as dictionary for MCP tool"""
    service = DeviceDetailsService()
    details = service.get_device_details(device_name)
    return asdict(details)

if __name__ == "__main__":
    # Test the service
    import sys
    if len(sys.argv) > 1:
        device_name = sys.argv[1]
        service = DeviceDetailsService()
        details = service.get_device_details(device_name)
        print(json.dumps(asdict(details), indent=2, default=str))
    else:
        print("Usage: python device_details.py <device_name>")