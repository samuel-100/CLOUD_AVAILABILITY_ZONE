#!/usr/bin/env python3
"""
Device Details Tool for MCP Integration
Provides detailed information about individual network devices including interfaces,
configuration snippets, operational data, and historical performance metrics.
"""

import os
import yaml
import logging
import paramiko
import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import subprocess

# File paths
TOPOLOGY_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/network_topology.yaml'
DEVICES_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/devices.yaml'
LOGS_DIR = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class InterfaceStatus:
    """Interface status information"""
    name: str
    status: str  # 'up', 'down', 'admin-down'
    protocol: str  # 'up', 'down'
    ip_address: Optional[str] = None
    description: Optional[str] = None
    speed: Optional[str] = None
    duplex: Optional[str] = None
    vlan: Optional[str] = None
    errors_in: Optional[int] = None
    errors_out: Optional[int] = None
    packets_in: Optional[int] = None
    packets_out: Optional[int] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None

@dataclass
class ConfigurationSnippet:
    """Configuration snippet information"""
    section: str
    content: str
    last_modified: Optional[str] = None

@dataclass
class PerformanceMetric:
    """Performance metric data point"""
    timestamp: str
    metric_name: str
    value: float
    unit: str

@dataclass
class HistoricalData:
    """Historical performance and error data"""
    cpu_usage: List[PerformanceMetric]
    memory_usage: List[PerformanceMetric]
    interface_utilization: Dict[str, List[PerformanceMetric]]
    error_counts: List[PerformanceMetric]
    uptime_events: List[Dict[str, Any]]

@dataclass
class DeviceDetailsResponse:
    """Complete device details response"""
    device_name: str
    device_role: str
    mgmt_ip: str
    data_ip: Optional[str]
    device_type: str
    os_version: str
    uptime: str
    last_checked: str
    
    # System information
    cpu_usage: Optional[float]
    memory_usage: Optional[float]
    temperature: Optional[float]
    power_status: Optional[str]
    
    # Interface information
    interfaces: List[InterfaceStatus]
    interface_summary: Dict[str, int]  # {'up': 5, 'down': 2, 'admin-down': 1}
    
    # Configuration snippets
    configuration_snippets: List[ConfigurationSnippet]
    
    # Operational data
    routing_table_size: Optional[int]
    arp_table_size: Optional[int]
    mac_table_size: Optional[int]
    
    # Protocol-specific data
    ospf_neighbors: List[Dict[str, Any]]
    bgp_neighbors: List[Dict[str, Any]]
    vxlan_peers: List[Dict[str, Any]]
    
    # Historical data
    historical_data: HistoricalData
    
    # Error and alert information
    recent_errors: List[str]
    active_alarms: List[str]
    
    # Additional metadata
    last_config_change: Optional[str]
    backup_status: Optional[str]
    compliance_status: Optional[str]

def load_topology():
    """Load network topology configuration"""
    with open(TOPOLOGY_FILE) as f:
        data = yaml.safe_load(f)
        if not data or 'topology' not in data:
            logger.error('network_topology.yaml is empty or missing "topology" key.')
            raise ValueError('network_topology.yaml is empty or missing "topology" key.')
        return data['topology']

def load_device_credentials():
    """Load device credentials"""
    with open(DEVICES_FILE) as f:
        devices_config = yaml.safe_load(f)
        return {
            device['name']: {
                'username': device['username'],
                'password': device['password'],
                'mgmt_ip': device['mgmt_ip']
            }
            for device in devices_config['devices']
        }

def get_device_from_topology(device_name):
    """Get device configuration from topology"""
    topology = load_topology()
    for device in topology['devices']:
        if device['name'] == device_name:
            return device
    return None

def establish_ssh_connection(device_name):
    """Establish SSH connection to device"""
    credentials = load_device_credentials()
    device_creds = credentials.get(device_name)
    
    if not device_creds:
        logger.error(f"No credentials found for device {device_name}")
        return None
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            device_creds['mgmt_ip'].split('/')[0],
            username=device_creds['username'],
            password=device_creds['password'],
            timeout=15,
            look_for_keys=False,
            allow_agent=False
        )
        return client
    except Exception as e:
        logger.error(f"Failed to connect to {device_name}: {e}")
        return None

def execute_command(client, command):
    """Execute command on device and return output"""
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        if error:
            logger.warning(f"Command '{command}' produced error: {error}")
        return output
    except Exception as e:
        logger.error(f"Failed to execute command '{command}': {e}")
        return ""

def parse_ios_interfaces(output):
    """Parse IOS interface information"""
    interfaces = []
    lines = output.split('\n')
    
    for line in lines:
        if re.match(r'^(GigabitEthernet|FastEthernet|Ethernet|Loopback|Vlan)', line):
            parts = line.split()
            if len(parts) >= 6:
                interface = InterfaceStatus(
                    name=parts[0],
                    ip_address=parts[1] if parts[1] != 'unassigned' else None,
                    status=parts[4].lower(),
                    protocol=parts[5].lower()
                )
                interfaces.append(interface)
    
    return interfaces

def parse_nxos_interfaces(output):
    """Parse NX-OS interface information"""
    interfaces = []
    lines = output.split('\n')
    
    for line in lines:
        if re.match(r'^(Eth|Lo|Vlan|mgmt)', line):
            parts = line.split()
            if len(parts) >= 4:
                interface = InterfaceStatus(
                    name=parts[0],
                    ip_address=parts[1] if len(parts) > 1 and parts[1] != '--' else None,
                    status=parts[2].lower() if len(parts) > 2 else 'unknown',
                    protocol=parts[3].lower() if len(parts) > 3 else 'unknown'
                )
                interfaces.append(interface)
    
    return interfaces

def get_interface_details(client, interface_name, device_type):
    """Get detailed information for a specific interface"""
    if device_type == 'nxos':
        command = f"show interface {interface_name}"
    else:
        command = f"show interfaces {interface_name}"
    
    output = execute_command(client, command)
    
    # Parse interface details from output
    interface = InterfaceStatus(name=interface_name, status='unknown', protocol='unknown')
    
    # Extract description
    desc_match = re.search(r'Description:\s*(.+)', output)
    if desc_match:
        interface.description = desc_match.group(1).strip()
    
    # Extract speed and duplex
    speed_match = re.search(r'(\d+)\s*Mbps|(\d+)\s*Gbps', output)
    if speed_match:
        if speed_match.group(1):
            interface.speed = f"{speed_match.group(1)} Mbps"
        elif speed_match.group(2):
            interface.speed = f"{speed_match.group(2)} Gbps"
    
    duplex_match = re.search(r'(full|half)-duplex', output, re.IGNORECASE)
    if duplex_match:
        interface.duplex = duplex_match.group(1).lower()
    
    # Extract error counters
    input_errors = re.search(r'(\d+)\s+input\s+errors', output)
    if input_errors:
        interface.errors_in = int(input_errors.group(1))
    
    output_errors = re.search(r'(\d+)\s+output\s+errors', output)
    if output_errors:
        interface.errors_out = int(output_errors.group(1))
    
    # Extract packet counters
    input_packets = re.search(r'(\d+)\s+packets\s+input', output)
    if input_packets:
        interface.packets_in = int(input_packets.group(1))
    
    output_packets = re.search(r'(\d+)\s+packets\s+output', output)
    if output_packets:
        interface.packets_out = int(output_packets.group(1))
    
    # Extract byte counters
    input_bytes = re.search(r'(\d+)\s+bytes\s+input', output)
    if input_bytes:
        interface.bytes_in = int(input_bytes.group(1))
    
    output_bytes = re.search(r'(\d+)\s+bytes\s+output', output)
    if output_bytes:
        interface.bytes_out = int(output_bytes.group(1))
    
    return interface

def get_configuration_snippets(client, device_type):
    """Get important configuration snippets"""
    snippets = []
    
    try:
        # Get running configuration
        running_config = execute_command(client, 'show running-config')
        
        # Extract key sections
        sections = {
            'interfaces': r'interface\s+\S+.*?(?=^interface|\Z)',
            'routing': r'router\s+\w+.*?(?=^router|^interface|\Z)',
            'vlans': r'vlan\s+\d+.*?(?=^vlan|^interface|\Z)',
            'access-lists': r'access-list\s+.*?(?=^access-list|^interface|\Z)'
        }
        
        for section_name, pattern in sections.items():
            matches = re.findall(pattern, running_config, re.MULTILINE | re.DOTALL)
            if matches:
                content = '\n'.join(matches[:3])  # Limit to first 3 matches
                snippets.append(ConfigurationSnippet(
                    section=section_name,
                    content=content[:1000],  # Limit content size
                    last_modified=datetime.now().isoformat()
                ))
    
    except Exception as e:
        logger.error(f"Failed to get configuration snippets: {e}")
    
    return snippets

def get_ospf_neighbors(client, device_type):
    """Get OSPF neighbor information"""
    neighbors = []
    
    try:
        if device_type == 'nxos':
            output = execute_command(client, 'show ip ospf neighbors')
        else:
            output = execute_command(client, 'show ip ospf neighbor')
        
        lines = output.split('\n')
        for line in lines:
            if re.search(r'\d+\.\d+\.\d+\.\d+', line) and 'Full' in line:
                parts = line.split()
                if len(parts) >= 5:
                    neighbors.append({
                        'neighbor_id': parts[0],
                        'priority': parts[1] if parts[1].isdigit() else '0',
                        'state': parts[2] if 'Full' in parts[2] else 'Full',
                        'dead_time': parts[3] if ':' in parts[3] else 'N/A',
                        'address': parts[4],
                        'interface': parts[5] if len(parts) > 5 else 'N/A'
                    })
    
    except Exception as e:
        logger.error(f"Failed to get OSPF neighbors: {e}")
    
    return neighbors

def get_bgp_neighbors(client, device_type):
    """Get BGP neighbor information"""
    neighbors = []
    
    try:
        output = execute_command(client, 'show bgp summary')
        lines = output.split('\n')
        
        for line in lines:
            if re.search(r'\d+\.\d+\.\d+\.\d+', line):
                parts = line.split()
                if len(parts) >= 10:
                    neighbors.append({
                        'neighbor': parts[0],
                        'version': parts[1],
                        'as': parts[2],
                        'msg_rcvd': parts[3],
                        'msg_sent': parts[4],
                        'tbl_ver': parts[5],
                        'in_queue': parts[6],
                        'out_queue': parts[7],
                        'up_down': parts[8],
                        'state_pfx_rcd': parts[9]
                    })
    
    except Exception as e:
        logger.error(f"Failed to get BGP neighbors: {e}")
    
    return neighbors

def get_vxlan_peers(client, device_type):
    """Get VXLAN peer information"""
    peers = []
    
    try:
        if device_type == 'nxos':
            output = execute_command(client, 'show nve peers')
            lines = output.split('\n')
            
            for line in lines:
                if re.search(r'\d+\.\d+\.\d+\.\d+', line) and 'Up' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        peers.append({
                            'peer_ip': parts[0],
                            'state': parts[1],
                            'learn_type': parts[2] if len(parts) > 2 else 'N/A',
                            'uptime': parts[3] if len(parts) > 3 else 'N/A',
                            'router_mac': parts[4] if len(parts) > 4 else 'N/A'
                        })
    
    except Exception as e:
        logger.debug(f"VXLAN peers check failed (may not be configured): {e}")
    
    return peers

def get_operational_data(client, device_type):
    """Get operational data like routing table size, ARP table size, etc."""
    data = {
        'routing_table_size': None,
        'arp_table_size': None,
        'mac_table_size': None
    }
    
    try:
        # Get routing table size
        if device_type == 'nxos':
            route_output = execute_command(client, 'show ip route summary')
        else:
            route_output = execute_command(client, 'show ip route summary')
        
        route_match = re.search(r'Total:\s*(\d+)', route_output)
        if route_match:
            data['routing_table_size'] = int(route_match.group(1))
        
        # Get ARP table size
        arp_output = execute_command(client, 'show ip arp | count')
        if arp_output.strip().isdigit():
            data['arp_table_size'] = int(arp_output.strip())
        
        # Get MAC table size
        if device_type == 'nxos':
            mac_output = execute_command(client, 'show mac address-table | count')
        else:
            mac_output = execute_command(client, 'show mac address-table | count')
        
        if mac_output.strip().isdigit():
            data['mac_table_size'] = int(mac_output.strip())
    
    except Exception as e:
        logger.error(f"Failed to get operational data: {e}")
    
    return data

def get_system_information(client, device_type):
    """Get system information like OS version, uptime, etc."""
    info = {
        'os_version': 'Unknown',
        'uptime': 'Unknown',
        'cpu_usage': None,
        'memory_usage': None,
        'temperature': None,
        'power_status': None
    }
    
    try:
        # Get version information
        version_output = execute_command(client, 'show version')
        
        # Extract OS version
        if device_type == 'nxos':
            version_match = re.search(r'system:\s*version\s*(\S+)', version_output, re.IGNORECASE)
        else:
            version_match = re.search(r'Version\s*(\S+)', version_output, re.IGNORECASE)
        
        if version_match:
            info['os_version'] = version_match.group(1)
        
        # Extract uptime
        uptime_match = re.search(r'uptime\s+is\s+(.+)', version_output, re.IGNORECASE)
        if uptime_match:
            info['uptime'] = uptime_match.group(1).strip()
        
        # Get CPU usage
        if device_type == 'nxos':
            cpu_output = execute_command(client, 'show system resources')
            cpu_match = re.search(r'CPU states\s*:\s*(\d+\.\d+)%', cpu_output)
            if cpu_match:
                info['cpu_usage'] = float(cpu_match.group(1))
        else:
            cpu_output = execute_command(client, 'show processes cpu | include CPU')
            cpu_match = re.search(r'CPU utilization.*?(\d+)%', cpu_output)
            if cpu_match:
                info['cpu_usage'] = float(cpu_match.group(1))
        
        # Get memory usage
        if device_type == 'nxos':
            mem_output = execute_command(client, 'show system resources')
            mem_match = re.search(r'Memory usage:\s*(\d+)K total,\s*(\d+)K used', mem_output)
            if mem_match:
                total_mem = int(mem_match.group(1))
                used_mem = int(mem_match.group(2))
                info['memory_usage'] = (used_mem / total_mem) * 100
        else:
            mem_output = execute_command(client, 'show memory summary')
            mem_match = re.search(r'Processor\s+(\d+)\s+(\d+)\s+(\d+)', mem_output)
            if mem_match:
                total_mem = int(mem_match.group(1))
                used_mem = int(mem_match.group(2))
                info['memory_usage'] = (used_mem / total_mem) * 100
        
        # Get temperature (if available)
        if device_type == 'nxos':
            temp_output = execute_command(client, 'show environment temperature')
            temp_match = re.search(r'(\d+)\s*C', temp_output)
            if temp_match:
                info['temperature'] = float(temp_match.group(1))
    
    except Exception as e:
        logger.error(f"Failed to get system information: {e}")
    
    return info

def get_historical_data(device_name):
    """Get historical performance data (placeholder implementation)"""
    # This would typically read from log files or monitoring databases
    # For now, return empty historical data structure
    return HistoricalData(
        cpu_usage=[],
        memory_usage=[],
        interface_utilization={},
        error_counts=[],
        uptime_events=[]
    )

def get_recent_errors(client, device_type):
    """Get recent error messages from device logs"""
    errors = []
    
    try:
        if device_type == 'nxos':
            log_output = execute_command(client, 'show logging last 10')
        else:
            log_output = execute_command(client, 'show logging | tail 10')
        
        lines = log_output.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in ['error', 'warning', 'critical', 'alert']):
                errors.append(line.strip())
    
    except Exception as e:
        logger.error(f"Failed to get recent errors: {e}")
    
    return errors

def get_device_details(device_name):
    """Get comprehensive device details - Main MCP tool function"""
    logger.info(f"Getting detailed information for device: {device_name}")
    
    try:
        # Get device configuration from topology
        device_config = get_device_from_topology(device_name)
        if not device_config:
            return {
                'error': f'Device {device_name} not found in topology',
                'timestamp': datetime.now().isoformat()
            }
        
        # Establish SSH connection
        client = establish_ssh_connection(device_name)
        if not client:
            return {
                'error': f'Failed to establish SSH connection to {device_name}',
                'timestamp': datetime.now().isoformat()
            }
        
        device_type = device_config.get('os', 'ios')
        device_role = device_config.get('role', 'unknown')
        mgmt_ip = device_config['mgmt_ip']
        data_ip = device_config.get('loopback', {}).get('ip')
        
        # Enable mode for IOS devices
        if device_type != 'nxos':
            execute_command(client, 'enable')
        
        # Get system information
        system_info = get_system_information(client, device_type)
        
        # Get interface information
        if device_type == 'nxos':
            interface_output = execute_command(client, 'show interface brief')
            interfaces = parse_nxos_interfaces(interface_output)
        else:
            interface_output = execute_command(client, 'show ip interface brief')
            interfaces = parse_ios_interfaces(interface_output)
        
        # Calculate interface summary
        interface_summary = {
            'up': len([i for i in interfaces if i.status == 'up']),
            'down': len([i for i in interfaces if i.status == 'down']),
            'admin-down': len([i for i in interfaces if i.status == 'admin-down'])
        }
        
        # Get configuration snippets
        config_snippets = get_configuration_snippets(client, device_type)
        
        # Get operational data
        operational_data = get_operational_data(client, device_type)
        
        # Get protocol-specific data
        ospf_neighbors = get_ospf_neighbors(client, device_type)
        bgp_neighbors = get_bgp_neighbors(client, device_type)
        vxlan_peers = get_vxlan_peers(client, device_type)
        
        # Get recent errors
        recent_errors = get_recent_errors(client, device_type)
        
        # Get historical data (placeholder)
        historical_data = get_historical_data(device_name)
        
        # Close SSH connection
        client.close()
        
        # Create response
        response = DeviceDetailsResponse(
            device_name=device_name,
            device_role=device_role,
            mgmt_ip=mgmt_ip,
            data_ip=data_ip,
            device_type=device_type,
            os_version=system_info['os_version'],
            uptime=system_info['uptime'],
            last_checked=datetime.now().isoformat(),
            
            # System information
            cpu_usage=system_info['cpu_usage'],
            memory_usage=system_info['memory_usage'],
            temperature=system_info['temperature'],
            power_status=system_info['power_status'],
            
            # Interface information
            interfaces=interfaces,
            interface_summary=interface_summary,
            
            # Configuration snippets
            configuration_snippets=config_snippets,
            
            # Operational data
            routing_table_size=operational_data['routing_table_size'],
            arp_table_size=operational_data['arp_table_size'],
            mac_table_size=operational_data['mac_table_size'],
            
            # Protocol-specific data
            ospf_neighbors=ospf_neighbors,
            bgp_neighbors=bgp_neighbors,
            vxlan_peers=vxlan_peers,
            
            # Historical data
            historical_data=historical_data,
            
            # Error and alert information
            recent_errors=recent_errors,
            active_alarms=[],  # Placeholder
            
            # Additional metadata
            last_config_change=None,  # Placeholder
            backup_status=None,  # Placeholder
            compliance_status=None  # Placeholder
        )
        
        logger.info(f"Successfully collected details for device: {device_name}")
        return asdict(response)
        
    except Exception as e:
        logger.error(f"Failed to get device details for {device_name}: {e}")
        return {
            'error': f'Failed to get device details: {e}',
            'device_name': device_name,
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Test the device details tool
    import sys
    if len(sys.argv) > 1:
        device_name = sys.argv[1]
        details = get_device_details(device_name)
        print(json.dumps(details, indent=2, default=str))
    else:
        print("Usage: python device_details_tool.py <device_name>")
        print("Available devices: SPINE1, SPINE2, LEAF1, LEAF2, LEAF3, LEAF4")