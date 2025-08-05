#!/usr/bin/env python3
"""
Comprehensive Network Status Tool for MCP Integration
Provides real-time device connectivity, protocol states, and health metrics
"""

import os
import yaml
import logging
import paramiko
import subprocess
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from threading import Lock
import json
import re

# File paths
TOPOLOGY_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/network_topology.yaml'
DEVICES_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/devices.yaml'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ProtocolStatus:
    """Protocol status information"""
    name: str
    status: str  # 'up', 'down', 'partial', 'unknown'
    neighbors: int
    details: Dict[str, Any]

@dataclass
class DeviceStatus:
    """Individual device status information"""
    name: str
    role: str
    mgmt_ip: str
    reachable: bool
    ssh_accessible: bool
    last_checked: str
    protocols: Dict[str, ProtocolStatus]
    health: str  # 'healthy', 'degraded', 'critical'
    uptime: Optional[str] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    interface_count: Optional[int] = None
    error_details: Optional[str] = None

@dataclass
class Alert:
    """Network alert information"""
    severity: str  # 'critical', 'warning', 'info'
    device: str
    message: str
    timestamp: str
    category: str  # 'connectivity', 'protocol', 'performance'

@dataclass
class NetworkStatusResponse:
    """Complete network status response"""
    timestamp: str
    overall_health: str  # 'healthy', 'degraded', 'critical'
    device_status: Dict[str, DeviceStatus]
    protocol_status: Dict[str, str]  # Overall protocol status across network
    alerts: List[Alert]
    summary: str
    topology_info: Dict[str, Any]
    performance_metrics: Dict[str, Any]

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

def ping_device(ip):
    """Test basic connectivity to device"""
    response = os.system(f'ping -c 2 -W 2 {ip.split("/")[0]} > /dev/null 2>&1')
    return response == 0

def ssh_check(ip, username, password):
    """Test SSH connectivity to device"""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip.split("/")[0], username=username, password=password, timeout=5)
        client.close()
        return True
    except Exception as e:
        logger.warning(f'SSH failed for {ip}: {e}')
        return False

def execute_command(client, command):
    """Execute command on device and return output"""
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        return output
    except Exception as e:
        logger.error(f"Failed to execute command '{command}': {e}")
        return ""

def check_ospf_status(client, device_type):
    """Check OSPF protocol status"""
    try:
        if device_type == 'nxos':
            output = execute_command(client, 'show ip ospf neighbors')
        else:
            output = execute_command(client, 'show ip ospf neighbor')
        
        # Count neighbors in Full state
        neighbors = len([line for line in output.split('\n') if 'Full' in line])
        status = 'up' if neighbors > 0 else 'down'
        
        return ProtocolStatus(
            name='OSPF',
            status=status,
            neighbors=neighbors,
            details={'output': output[:500]}
        )
    except Exception as e:
        logger.error(f"Failed to check OSPF status: {e}")
        return ProtocolStatus(name='OSPF', status='unknown', neighbors=0, details={'error': str(e)})

def check_bgp_status(client, device_type):
    """Check BGP protocol status"""
    try:
        output = execute_command(client, 'show bgp summary')
        
        # Count established BGP sessions
        neighbors = len([line for line in output.split('\n') 
                        if re.search(r'\d+\.\d+\.\d+\.\d+.*\d+', line) and 'Established' in line])
        status = 'up' if neighbors > 0 else 'down'
        
        return ProtocolStatus(
            name='BGP',
            status=status,
            neighbors=neighbors,
            details={'output': output[:500]}
        )
    except Exception as e:
        logger.error(f"Failed to check BGP status: {e}")
        return ProtocolStatus(name='BGP', status='unknown', neighbors=0, details={'error': str(e)})

def check_vxlan_status(client, device_type):
    """Check VXLAN protocol status"""
    try:
        if device_type == 'nxos':
            output = execute_command(client, 'show nve peers')
            # Count peers in Up state
            peers = len([line for line in output.split('\n') if 'Up' in line])
        else:
            # IOS devices may not have VXLAN
            output = execute_command(client, 'show vxlan tunnel')
            peers = len([line for line in output.split('\n') if 'up' in line.lower()])
        
        status = 'up' if peers > 0 else 'down'
        
        return ProtocolStatus(
            name='VXLAN',
            status=status,
            neighbors=peers,
            details={'output': output[:500]}
        )
    except Exception as e:
        logger.debug(f"VXLAN check failed (may not be configured): {e}")
        return ProtocolStatus(name='VXLAN', status='down', neighbors=0, details={'error': str(e)})

def check_evpn_status(client, device_type):
    """Check EVPN protocol status"""
    try:
        if device_type == 'nxos':
            output = execute_command(client, 'show bgp l2vpn evpn summary')
            # Count EVPN neighbors
            neighbors = len([line for line in output.split('\n') 
                           if re.search(r'\d+\.\d+\.\d+\.\d+.*Established', line)])
        else:
            # IOS may not support EVPN
            output = ""
            neighbors = 0
        
        status = 'up' if neighbors > 0 else 'down'
        
        return ProtocolStatus(
            name='EVPN',
            status=status,
            neighbors=neighbors,
            details={'output': output[:500]}
        )
    except Exception as e:
        logger.debug(f"EVPN check failed (may not be configured): {e}")
        return ProtocolStatus(name='EVPN', status='down', neighbors=0, details={'error': str(e)})

def get_device_info(client, device_type):
    """Collect detailed device information"""
    info = {
        'uptime': None,
        'cpu_usage': None,
        'memory_usage': None,
        'interface_count': None
    }
    
    try:
        # Get uptime
        if device_type == 'nxos':
            uptime_output = execute_command(client, 'show version | include uptime')
        else:
            uptime_output = execute_command(client, 'show version | include uptime')
        
        if uptime_output:
            info['uptime'] = uptime_output.strip()
        
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
        
        # Get interface count
        if device_type == 'nxos':
            int_output = execute_command(client, 'show interface brief | count')
        else:
            int_output = execute_command(client, 'show ip interface brief | count')
        
        if int_output.strip().isdigit():
            info['interface_count'] = int(int_output.strip())
    
    except Exception as e:
        logger.error(f"Failed to collect device info: {e}")
    
    return info

def check_device_protocols(client, device_type):
    """Check all protocol statuses for a device"""
    protocols = {}
    
    # Check OSPF
    protocols['OSPF'] = check_ospf_status(client, device_type)
    
    # Check BGP
    protocols['BGP'] = check_bgp_status(client, device_type)
    
    # Check VXLAN
    protocols['VXLAN'] = check_vxlan_status(client, device_type)
    
    # Check EVPN
    protocols['EVPN'] = check_evpn_status(client, device_type)
    
    return protocols

def check_single_device(device, credentials, print_lock):
    """Check status of a single device with comprehensive monitoring"""
    device_name = device['name']
    device_role = device.get('role', 'unknown')
    mgmt_ip = device['mgmt_ip']
    device_type = device.get('os', 'ios')
    
    username = credentials[device_name]['username']
    password = credentials[device_name]['password']
    
    # Basic connectivity tests
    reachable = ping_device(mgmt_ip)
    ssh_accessible = False
    protocols = {}
    device_info = {}
    error_details = None
    
    if reachable:
        ssh_accessible = ssh_check(mgmt_ip, username, password)
        
        if ssh_accessible:
            try:
                # Establish SSH connection for detailed checks
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    mgmt_ip.split("/")[0], 
                    username=username, 
                    password=password, 
                    timeout=15,
                    look_for_keys=False,
                    allow_agent=False
                )
                
                # Enable mode for IOS devices
                if device_type != 'nxos':
                    execute_command(client, 'enable')
                
                # Collect device information
                device_info = get_device_info(client, device_type)
                
                # Check protocol statuses
                protocols = check_device_protocols(client, device_type)
                
                client.close()
                
            except Exception as e:
                error_details = f"Failed to collect detailed info: {e}"
                logger.error(f"Error collecting info for {device_name}: {e}")
    
    # Determine health status
    if not reachable:
        health = 'critical'
    elif not ssh_accessible:
        health = 'degraded'
    elif protocols and any(p.status == 'down' for p in protocols.values() if p.name in ['OSPF', 'BGP']):
        health = 'degraded'
    else:
        health = 'healthy'
    
    status = DeviceStatus(
        name=device_name,
        role=device_role,
        mgmt_ip=mgmt_ip,
        reachable=reachable,
        ssh_accessible=ssh_accessible,
        last_checked=datetime.now().isoformat(),
        protocols=protocols,
        health=health,
        uptime=device_info.get('uptime'),
        cpu_usage=device_info.get('cpu_usage'),
        memory_usage=device_info.get('memory_usage'),
        interface_count=device_info.get('interface_count'),
        error_details=error_details
    )
    
    with print_lock:
        logger.info(f'{device_name}: Health={health}, Reachable={reachable}, SSH={ssh_accessible}')
        print(f'{device_name}: Health={health}, Reachable={reachable}, SSH={ssh_accessible}')
    
    return status

def aggregate_protocol_status(device_status):
    """Aggregate protocol status across all devices"""
    protocol_status = {}
    all_protocols = set()
    
    # Collect all protocol names
    for device in device_status.values():
        all_protocols.update(device.protocols.keys())
    
    # Aggregate status for each protocol
    for protocol in all_protocols:
        protocol_devices = []
        for device in device_status.values():
            if protocol in device.protocols:
                protocol_devices.append(device.protocols[protocol].status)
        
        if not protocol_devices:
            protocol_status[protocol] = 'unknown'
        elif all(status == 'up' for status in protocol_devices):
            protocol_status[protocol] = 'up'
        elif any(status == 'up' for status in protocol_devices):
            protocol_status[protocol] = 'partial'
        else:
            protocol_status[protocol] = 'down'
    
    return protocol_status

def generate_alerts(device_status, protocol_status):
    """Generate network alerts based on current status"""
    alerts = []
    timestamp = datetime.now().isoformat()
    
    # Device connectivity alerts
    for device in device_status.values():
        if not device.reachable:
            alerts.append(Alert(
                severity='critical',
                device=device.name,
                message=f"Device {device.name} is unreachable",
                timestamp=timestamp,
                category='connectivity'
            ))
        elif not device.ssh_accessible:
            alerts.append(Alert(
                severity='warning',
                device=device.name,
                message=f"Device {device.name} SSH access failed",
                timestamp=timestamp,
                category='connectivity'
            ))
        
        # Protocol alerts
        for protocol_name, protocol in device.protocols.items():
            if protocol.status == 'down' and protocol_name in ['OSPF', 'BGP']:
                alerts.append(Alert(
                    severity='warning',
                    device=device.name,
                    message=f"Protocol {protocol_name} is down on {device.name}",
                    timestamp=timestamp,
                    category='protocol'
                ))
        
        # Performance alerts
        if device.cpu_usage and device.cpu_usage > 80:
            alerts.append(Alert(
                severity='warning',
                device=device.name,
                message=f"High CPU usage on {device.name}: {device.cpu_usage}%",
                timestamp=timestamp,
                category='performance'
            ))
        
        if device.memory_usage and device.memory_usage > 85:
            alerts.append(Alert(
                severity='warning',
                device=device.name,
                message=f"High memory usage on {device.name}: {device.memory_usage:.1f}%",
                timestamp=timestamp,
                category='performance'
            ))
    
    # Network-wide protocol alerts
    for protocol, status in protocol_status.items():
        if status == 'down' and protocol in ['OSPF', 'BGP']:
            alerts.append(Alert(
                severity='critical',
                device='network',
                message=f"Protocol {protocol} is down network-wide",
                timestamp=timestamp,
                category='protocol'
            ))
        elif status == 'partial' and protocol in ['OSPF', 'BGP']:
            alerts.append(Alert(
                severity='warning',
                device='network',
                message=f"Protocol {protocol} has partial connectivity",
                timestamp=timestamp,
                category='protocol'
            ))
    
    return alerts

def determine_overall_health(device_status, alerts):
    """Determine overall network health"""
    critical_alerts = [a for a in alerts if a.severity == 'critical']
    unreachable_devices = [d for d in device_status.values() if not d.reachable]
    
    if critical_alerts or len(unreachable_devices) > 1:
        return 'critical'
    elif alerts or unreachable_devices:
        return 'degraded'
    else:
        return 'healthy'

def calculate_performance_metrics(device_status):
    """Calculate network performance metrics"""
    metrics = {
        'availability': 0.0,
        'avg_cpu_usage': 0.0,
        'avg_memory_usage': 0.0,
        'protocol_health': {}
    }
    
    reachable_devices = [d for d in device_status.values() if d.reachable]
    total_devices = len(device_status)
    
    if total_devices > 0:
        metrics['availability'] = (len(reachable_devices) / total_devices) * 100
    
    if reachable_devices:
        cpu_values = [d.cpu_usage for d in reachable_devices if d.cpu_usage is not None]
        if cpu_values:
            metrics['avg_cpu_usage'] = sum(cpu_values) / len(cpu_values)
        
        memory_values = [d.memory_usage for d in reachable_devices if d.memory_usage is not None]
        if memory_values:
            metrics['avg_memory_usage'] = sum(memory_values) / len(memory_values)
    
    return metrics

def get_network_status():
    """Get comprehensive network status - Main MCP tool function"""
    logger.info("Starting comprehensive network status collection")
    
    try:
        # Load configuration
        topology = load_topology()
        credentials = load_device_credentials()
        devices = topology['devices']
        
        device_status = {}
        print_lock = Lock()
        
        # Collect device status concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            future_to_device = {
                executor.submit(check_single_device, device, credentials, print_lock): device 
                for device in devices
            }
            
            for future in concurrent.futures.as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    status = future.result()
                    device_status[status.name] = status
                except Exception as e:
                    logger.error(f"Failed to check device {device['name']}: {e}")
                    # Create a minimal status for failed devices
                    device_status[device['name']] = DeviceStatus(
                        name=device['name'],
                        role=device.get('role', 'unknown'),
                        mgmt_ip=device['mgmt_ip'],
                        reachable=False,
                        ssh_accessible=False,
                        last_checked=datetime.now().isoformat(),
                        protocols={},
                        health='critical',
                        error_details=str(e)
                    )
        
        # Aggregate protocol status across network
        protocol_status = aggregate_protocol_status(device_status)
        
        # Generate alerts
        alerts = generate_alerts(device_status, protocol_status)
        
        # Determine overall health
        overall_health = determine_overall_health(device_status, alerts)
        
        # Create topology info
        topology_info = {
            'architecture': 'spine-leaf',
            'spine_count': len([d for d in devices if d.get('role') == 'spine']),
            'leaf_count': len([d for d in devices if d.get('role') == 'leaf']),
            'total_devices': len(devices)
        }
        
        # Performance metrics
        performance_metrics = calculate_performance_metrics(device_status)
        
        # Generate summary
        reachable_count = len([d for d in device_status.values() if d.reachable])
        summary = (f"Network Status: {overall_health.upper()} | "
                  f"Devices: {reachable_count}/{len(devices)} reachable | "
                  f"Protocols: {', '.join([f'{k}={v}' for k, v in protocol_status.items()])} | "
                  f"Alerts: {len(alerts)}")
        
        response = NetworkStatusResponse(
            timestamp=datetime.now().isoformat(),
            overall_health=overall_health,
            device_status=device_status,
            protocol_status=protocol_status,
            alerts=alerts,
            summary=summary,
            topology_info=topology_info,
            performance_metrics=performance_metrics
        )
        
        logger.info(f"Network status collection completed: {overall_health}")
        return asdict(response)
        
    except Exception as e:
        logger.error(f"Failed to get network status: {e}")
        return {
            'timestamp': datetime.now().isoformat(),
            'overall_health': 'critical',
            'device_status': {},
            'protocol_status': {},
            'alerts': [{'severity': 'critical', 'device': 'system', 'message': f'Network status collection failed: {e}', 'timestamp': datetime.now().isoformat(), 'category': 'system'}],
            'summary': f'Network status collection failed: {e}',
            'topology_info': {},
            'performance_metrics': {}
        }

if __name__ == "__main__":
    # Test the network status tool
    status = get_network_status()
    print(json.dumps(status, indent=2, default=str))