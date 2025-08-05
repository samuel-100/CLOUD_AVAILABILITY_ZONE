#!/usr/bin/env python3
"""
Comprehensive Network Status Service for MCP Integration
Provides real-time device connectivity, protocol states, and health metrics
"""

import os
import yaml
import logging
import subprocess
import concurrent.futures
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

class NetworkStatusService:
    """Service for collecting comprehensive network status"""
    
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
    
    def _ping_device(self, ip: str) -> bool:
        """Test basic connectivity to device"""
        try:
            result = subprocess.run(
                ["ping", "-c", "2", "-W", "2", ip.split("/")[0]], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Ping failed for {ip}: {e}")
            return False
    
    def _ssh_check(self, ip: str, username: str, password: str) -> bool:
        """Test SSH connectivity to device"""
        try:
            params = {
                'device_type': 'cisco_ios',
                'host': ip.split("/")[0],
                'username': username,
                'password': password,
                'timeout': 10,
                'fast_cli': False
            }
            with ConnectHandler(**params) as net_connect:
                # Just test connection, don't run commands
                pass
            return True
        except Exception as e:
            logger.debug(f"SSH failed for {ip}: {e}")
            return False
    
    def _get_device_info(self, device: Dict, credentials: Dict) -> Dict[str, Any]:
        """Collect detailed device information via SSH"""
        device_info = {
            'uptime': None,
            'cpu_usage': None,
            'memory_usage': None,
            'interface_count': None,
            'protocols': {}
        }
        
        try:
            ip = device['mgmt_ip'].split('/')[0]
            
            # Determine device type for appropriate commands and netmiko device_type
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
                'timeout': 15,
                'fast_cli': False
            }
            
            with ConnectHandler(**params) as net_connect:
                net_connect.enable()
                
                # Collect basic system information
                if device_os == 'nxos':
                    device_info.update(self._collect_nxos_info(net_connect))
                else:
                    device_info.update(self._collect_ios_info(net_connect))
            
        except Exception as e:
            logger.warning(f"Failed to collect detailed info for {device['name']}: {e}")
            device_info['error'] = str(e)
        
        return device_info
    
    def _collect_nxos_info(self, net_connect) -> Dict[str, Any]:
        """Collect information from NX-OS devices - L3 fabric focus"""
        info = {'protocols': {}, 'interfaces': {}}
        
        try:
            # System uptime
            uptime_output = net_connect.send_command('show version | include uptime')
            if uptime_output:
                info['uptime'] = uptime_output.strip()
            
            # Interface status - focus on L3 fabric interfaces
            interface_brief = net_connect.send_command('show interface brief')
            interface_lines = [line for line in interface_brief.split('\n') if 'Eth' in line]
            info['interface_count'] = len(interface_lines)
            
            # Get interface status details
            interface_status = net_connect.send_command('show interface status')
            up_interfaces = len([line for line in interface_status.split('\n') if 'connected' in line.lower()])
            info['interfaces'] = {
                'total': len(interface_lines),
                'up': up_interfaces,
                'down': len(interface_lines) - up_interfaces
            }
            
            # Protocol status - OSPF and BGP only
            info['protocols'].update(self._check_nxos_protocols(net_connect))
            
        except Exception as e:
            logger.debug(f"Error collecting NX-OS info: {e}")
        
        return info
    
    def _collect_ios_info(self, net_connect) -> Dict[str, Any]:
        """Collect information from IOS devices - L3 fabric focus"""
        info = {'protocols': {}, 'interfaces': {}}
        
        try:
            # System uptime
            uptime_output = net_connect.send_command('show version | include uptime')
            if uptime_output:
                info['uptime'] = uptime_output.strip()
            
            # Interface status - focus on L3 fabric interfaces
            interface_brief = net_connect.send_command('show ip interface brief')
            interface_lines = [line for line in interface_brief.split('\n') 
                             if any(iface in line for iface in ['GigabitEthernet', 'FastEthernet', 'Ethernet'])]
            info['interface_count'] = len(interface_lines)
            
            # Get interface status details
            up_interfaces = len([line for line in interface_lines if 'up' in line.lower() and 'up' in line.lower().split()[4:6]])
            info['interfaces'] = {
                'total': len(interface_lines),
                'up': up_interfaces,
                'down': len(interface_lines) - up_interfaces
            }
            
            # Protocol status - OSPF and BGP only
            info['protocols'].update(self._check_ios_protocols(net_connect))
            
        except Exception as e:
            logger.debug(f"Error collecting IOS info: {e}")
        
        return info
    
    def _check_nxos_protocols(self, net_connect) -> Dict[str, ProtocolStatus]:
        """Check protocol status on NX-OS devices - L3 fabric focus"""
        protocols = {}
        
        try:
            # Interface status
            interface_output = net_connect.send_command('show interface brief')
            up_interfaces = len([line for line in interface_output.split('\n') if 'up' in line.lower() and ('Eth' in line or 'mgmt' in line)])
            total_interfaces = len([line for line in interface_output.split('\n') if 'Eth' in line or 'mgmt' in line])
            protocols['INTERFACES'] = ProtocolStatus(
                name='INTERFACES',
                status='up' if up_interfaces > 0 else 'down',
                neighbors=up_interfaces,
                details={'up': up_interfaces, 'total': total_interfaces, 'output': interface_output[:500]}
            )
            
            # OSPF status
            ospf_output = net_connect.send_command('show ip ospf neighbors')
            ospf_neighbors = len([line for line in ospf_output.split('\n') if 'Full' in line])
            protocols['OSPF'] = ProtocolStatus(
                name='OSPF',
                status='up' if ospf_neighbors > 0 else 'down',
                neighbors=ospf_neighbors,
                details={'output': ospf_output[:500]}
            )
            
            # BGP status
            bgp_output = net_connect.send_command('show bgp summary')
            bgp_neighbors = len([line for line in bgp_output.split('\n') if re.search(r'\d+\.\d+\.\d+\.\d+.*\d+', line)])
            protocols['BGP'] = ProtocolStatus(
                name='BGP',
                status='up' if bgp_neighbors > 0 else 'down',
                neighbors=bgp_neighbors,
                details={'output': bgp_output[:500]}
            )
            
        except Exception as e:
            logger.debug(f"Error checking NX-OS protocols: {e}")
        
        return protocols
    
    def _check_ios_protocols(self, net_connect) -> Dict[str, ProtocolStatus]:
        """Check protocol status on IOS devices - L3 fabric focus"""
        protocols = {}
        
        try:
            # Interface status
            interface_output = net_connect.send_command('show ip interface brief')
            up_interfaces = len([line for line in interface_output.split('\n') if 'up' in line.lower() and ('GigabitEthernet' in line or 'FastEthernet' in line or 'Ethernet' in line)])
            total_interfaces = len([line for line in interface_output.split('\n') if 'GigabitEthernet' in line or 'FastEthernet' in line or 'Ethernet' in line])
            protocols['INTERFACES'] = ProtocolStatus(
                name='INTERFACES',
                status='up' if up_interfaces > 0 else 'down',
                neighbors=up_interfaces,
                details={'up': up_interfaces, 'total': total_interfaces, 'output': interface_output[:500]}
            )
            
            # OSPF status
            ospf_output = net_connect.send_command('show ip ospf neighbor')
            ospf_neighbors = len([line for line in ospf_output.split('\n') if 'Full' in line])
            protocols['OSPF'] = ProtocolStatus(
                name='OSPF',
                status='up' if ospf_neighbors > 0 else 'down',
                neighbors=ospf_neighbors,
                details={'output': ospf_output[:500]}
            )
            
            # BGP status
            bgp_output = net_connect.send_command('show bgp summary')
            bgp_neighbors = len([line for line in bgp_output.split('\n') if re.search(r'\d+\.\d+\.\d+\.\d+.*\d+', line)])
            protocols['BGP'] = ProtocolStatus(
                name='BGP',
                status='up' if bgp_neighbors > 0 else 'down',
                neighbors=bgp_neighbors,
                details={'output': bgp_output[:500]}
            )
            
        except Exception as e:
            logger.debug(f"Error checking IOS protocols: {e}")
        
        return protocols
    
    def _check_single_device(self, device: Dict) -> DeviceStatus:
        """Check status of a single device"""
        device_name = device['name']
        device_role = device.get('role', 'unknown')
        mgmt_ip = device['mgmt_ip']
        credentials = self.device_credentials.get(device_name, {})
        
        # Basic connectivity tests
        reachable = self._ping_device(mgmt_ip)
        ssh_accessible = False
        protocols = {}
        device_info = {}
        error_details = None
        
        if reachable and credentials:
            ssh_accessible = self._ssh_check(
                mgmt_ip, 
                credentials['username'], 
                credentials['password']
            )
            
            if ssh_accessible:
                try:
                    device_info = self._get_device_info(device, credentials)
                    protocols = device_info.get('protocols', {})
                except Exception as e:
                    error_details = f"Failed to collect device info: {e}"
        
        # Determine health status
        if not reachable:
            health = 'critical'
        elif not ssh_accessible:
            health = 'degraded'
        elif protocols and any(p.status == 'down' for p in protocols.values()):
            health = 'degraded'
        else:
            health = 'healthy'
        
        return DeviceStatus(
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
    
    def get_network_status(self) -> NetworkStatusResponse:
        """Get comprehensive network status"""
        logger.info("Starting comprehensive network status collection")
        
        devices = self.topology['devices']
        device_status = {}
        
        # Collect device status concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            future_to_device = {
                executor.submit(self._check_single_device, device): device 
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
        protocol_status = self._aggregate_protocol_status(device_status)
        
        # Generate alerts
        alerts = self._generate_alerts(device_status, protocol_status)
        
        # Determine overall health
        overall_health = self._determine_overall_health(device_status, alerts)
        
        # Create topology info
        topology_info = {
            'architecture': 'spine-leaf',
            'spine_count': len([d for d in devices if d.get('role') == 'spine']),
            'leaf_count': len([d for d in devices if d.get('role') == 'leaf']),
            'total_devices': len(devices)
        }
        
        # Performance metrics
        performance_metrics = self._calculate_performance_metrics(device_status)
        
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
        return response
    
    def _aggregate_protocol_status(self, device_status: Dict[str, DeviceStatus]) -> Dict[str, str]:
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
    
    def _generate_alerts(self, device_status: Dict[str, DeviceStatus], 
                        protocol_status: Dict[str, str]) -> List[Alert]:
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
                if protocol.status == 'down':
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
            if status == 'down':
                alerts.append(Alert(
                    severity='critical',
                    device='network',
                    message=f"Protocol {protocol} is down network-wide",
                    timestamp=timestamp,
                    category='protocol'
                ))
            elif status == 'partial':
                alerts.append(Alert(
                    severity='warning',
                    device='network',
                    message=f"Protocol {protocol} has partial connectivity",
                    timestamp=timestamp,
                    category='protocol'
                ))
        
        return alerts
    
    def _determine_overall_health(self, device_status: Dict[str, DeviceStatus], 
                                 alerts: List[Alert]) -> str:
        """Determine overall network health"""
        critical_alerts = [a for a in alerts if a.severity == 'critical']
        unreachable_devices = [d for d in device_status.values() if not d.reachable]
        
        if critical_alerts or len(unreachable_devices) > 1:
            return 'critical'
        elif alerts or unreachable_devices:
            return 'degraded'
        else:
            return 'healthy'
    
    def _calculate_performance_metrics(self, device_status: Dict[str, DeviceStatus]) -> Dict[str, Any]:
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

# Convenience function for MCP integration
def get_network_status() -> Dict[str, Any]:
    """Get network status as dictionary for MCP tool"""
    service = NetworkStatusService()
    status = service.get_network_status()
    return asdict(status)

# Convenience function for MCP integration
def get_network_status() -> Dict[str, Any]:
    """Get network status as dictionary for MCP tool"""
    service = NetworkStatusService()
    status = service.get_network_status()
    return asdict(status)

if __name__ == "__main__":
    # Test the service
    service = NetworkStatusService()
    status = service.get_network_status()
    print(json.dumps(asdict(status), indent=2, default=str))
    print(json.dumps(asdict(status), indent=2, default=str))