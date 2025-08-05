#!/usr/bin/env python3
"""
Network Topology Service for MCP Integration
Provides spine-leaf architecture details, device relationships, and connection mapping
with visual topology representation for Claude.
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

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class DeviceConnection:
    """Device connection information"""
    local_interface: str
    remote_device: str
    remote_interface: str
    connection_type: str  # 'p2p', 'access', 'trunk'
    ip_address: Optional[str] = None
    status: str = 'unknown'  # 'up', 'down', 'unknown'

@dataclass
class TopologyDevice:
    """Device in topology"""
    name: str
    role: str  # 'spine', 'leaf'
    device_type: str  # 'ios', 'nxos'
    mgmt_ip: str
    loopback_ip: Optional[str] = None
    connections: List[DeviceConnection] = None
    
    def __post_init__(self):
        if self.connections is None:
            self.connections = []

@dataclass
class NetworkTopologyResponse:
    """Complete network topology response"""
    timestamp: str
    architecture: str  # 'spine-leaf'
    devices: Dict[str, TopologyDevice]
    connections_matrix: Dict[str, Dict[str, List[str]]]  # device -> device -> [interfaces]
    spine_devices: List[str]
    leaf_devices: List[str]
    topology_summary: Dict[str, Any]
    visual_representation: str
    health_status: str  # 'healthy', 'degraded', 'critical'

class NetworkTopologyService:
    """Service for network topology analysis and visualization"""
    
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
            
            logger.info(f"Loaded topology configuration for {len(self.topology['devices'])} devices")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def _parse_device_connections(self, device: Dict) -> List[DeviceConnection]:
        """Parse device connections from topology configuration"""
        connections = []
        
        try:
            interfaces = device.get('interfaces', [])
            
            for interface in interfaces:
                interface_name = interface.get('name', '')
                description = interface.get('description', '')
                ip_address = interface.get('ip')
                
                # Parse P2P connections from description
                if 'P2P-Link-to-' in description:
                    # Extract remote device name
                    remote_device_match = re.search(r'P2P-Link-to-(\w+)', description)
                    if remote_device_match:
                        remote_device = remote_device_match.group(1)
                        
                        # Try to find the corresponding interface on remote device
                        remote_interface = self._find_remote_interface(device['name'], remote_device, interface_name)
                        
                        connection = DeviceConnection(
                            local_interface=interface_name,
                            remote_device=remote_device,
                            remote_interface=remote_interface or 'unknown',
                            connection_type='p2p',
                            ip_address=ip_address,
                            status='up' if not interface.get('shutdown', False) else 'down'
                        )
                        connections.append(connection)
                
                # Parse access connections (server-facing interfaces)
                elif interface.get('switchport') and interface.get('mode') == 'access':
                    connection = DeviceConnection(
                        local_interface=interface_name,
                        remote_device='server/host',
                        remote_interface='unknown',
                        connection_type='access',
                        ip_address=ip_address,
                        status='up' if not interface.get('shutdown', False) else 'down'
                    )
                    connections.append(connection)
        
        except Exception as e:
            logger.debug(f"Error parsing connections for {device.get('name', 'unknown')}: {e}")
        
        return connections
    
    def _find_remote_interface(self, local_device: str, remote_device: str, local_interface: str) -> Optional[str]:
        """Find the corresponding interface on the remote device"""
        try:
            # Find remote device in topology
            remote_device_config = None
            for device in self.topology['devices']:
                if device['name'] == remote_device:
                    remote_device_config = device
                    break
            
            if not remote_device_config:
                return None
            
            # Look for interface with description pointing back to local device
            for interface in remote_device_config.get('interfaces', []):
                description = interface.get('description', '')
                if f'P2P-Link-to-{local_device}' in description:
                    return interface.get('name')
            
            return None
            
        except Exception as e:
            logger.debug(f"Error finding remote interface: {e}")
            return None
    
    def _create_topology_devices(self) -> Dict[str, TopologyDevice]:
        """Create topology device objects from configuration"""
        devices = {}
        
        for device_config in self.topology['devices']:
            device_name = device_config['name']
            
            # Extract loopback IP
            loopback_ip = None
            for interface in device_config.get('interfaces', []):
                if interface.get('name', '').startswith('loopback'):
                    loopback_ip = interface.get('ip', '').split('/')[0]
                    break
            
            # Get management IP from credentials
            mgmt_ip = self.device_credentials.get(device_name, {}).get('mgmt_ip', 'unknown')
            
            # Parse connections
            connections = self._parse_device_connections(device_config)
            
            topology_device = TopologyDevice(
                name=device_name,
                role=device_config.get('role', 'unknown'),
                device_type=device_config.get('os', 'ios'),
                mgmt_ip=mgmt_ip,
                loopback_ip=loopback_ip,
                connections=connections
            )
            
            devices[device_name] = topology_device
        
        return devices
    
    def _create_connections_matrix(self, devices: Dict[str, TopologyDevice]) -> Dict[str, Dict[str, List[str]]]:
        """Create a matrix of device-to-device connections"""
        matrix = {}
        
        for device_name, device in devices.items():
            matrix[device_name] = {}
            
            for connection in device.connections:
                remote_device = connection.remote_device
                
                # Skip non-network devices
                if remote_device in ['server/host', 'unknown']:
                    continue
                
                if remote_device not in matrix[device_name]:
                    matrix[device_name][remote_device] = []
                
                interface_pair = f"{connection.local_interface} <-> {connection.remote_interface}"
                matrix[device_name][remote_device].append(interface_pair)
        
        return matrix
    
    def _generate_topology_summary(self, devices: Dict[str, TopologyDevice]) -> Dict[str, Any]:
        """Generate topology summary statistics"""
        spine_devices = [name for name, device in devices.items() if device.role == 'spine']
        leaf_devices = [name for name, device in devices.items() if device.role == 'leaf']
        
        # Count connections
        total_p2p_connections = 0
        total_access_connections = 0
        
        for device in devices.values():
            for connection in device.connections:
                if connection.connection_type == 'p2p':
                    total_p2p_connections += 1
                elif connection.connection_type == 'access':
                    total_access_connections += 1
        
        # P2P connections are counted twice (once for each end), so divide by 2
        total_p2p_connections = total_p2p_connections // 2
        
        summary = {
            'architecture': 'spine-leaf',
            'total_devices': len(devices),
            'spine_count': len(spine_devices),
            'leaf_count': len(leaf_devices),
            'total_p2p_links': total_p2p_connections,
            'total_access_ports': total_access_connections,
            'expected_p2p_links': len(spine_devices) * len(leaf_devices),  # Full mesh between spines and leaves
            'connectivity_ratio': (total_p2p_connections / (len(spine_devices) * len(leaf_devices))) if spine_devices and leaf_devices else 0,
            'device_types': {
                'ios': len([d for d in devices.values() if d.device_type == 'ios']),
                'nxos': len([d for d in devices.values() if d.device_type == 'nxos'])
            }
        }
        
        return summary
    
    def _generate_visual_representation(self, devices: Dict[str, TopologyDevice], 
                                      connections_matrix: Dict[str, Dict[str, List[str]]]) -> str:
        """Generate ASCII art visual representation of the topology"""
        
        spine_devices = [name for name, device in devices.items() if device.role == 'spine']
        leaf_devices = [name for name, device in devices.items() if device.role == 'leaf']
        
        # Sort for consistent output
        spine_devices.sort()
        leaf_devices.sort()
        
        visual = []
        visual.append("Network Topology - Spine-Leaf Architecture")
        visual.append("=" * 50)
        visual.append("")
        
        # Spine layer
        visual.append("SPINE LAYER:")
        spine_line = "  "
        for i, spine in enumerate(spine_devices):
            spine_line += f"┌─────────┐"
            if i < len(spine_devices) - 1:
                spine_line += "     "
        visual.append(spine_line)
        
        spine_name_line = "  "
        for i, spine in enumerate(spine_devices):
            spine_name_line += f"│ {spine:^7} │"
            if i < len(spine_devices) - 1:
                spine_name_line += "     "
        visual.append(spine_name_line)
        
        spine_bottom_line = "  "
        for i, spine in enumerate(spine_devices):
            spine_bottom_line += f"└────┬────┘"
            if i < len(spine_devices) - 1:
                spine_bottom_line += "     "
        visual.append(spine_bottom_line)
        
        # Connection lines
        visual.append("       │           │")
        visual.append("   ┌───┴───┐   ┌───┴───┐")
        visual.append("   │       │   │       │")
        visual.append("   ▼       ▼   ▼       ▼")
        
        # Leaf layer
        visual.append("")
        visual.append("LEAF LAYER:")
        leaf_line = ""
        for i, leaf in enumerate(leaf_devices):
            leaf_line += f"┌─────────┐"
            if i < len(leaf_devices) - 1:
                leaf_line += " "
        visual.append(leaf_line)
        
        leaf_name_line = ""
        for i, leaf in enumerate(leaf_devices):
            leaf_name_line += f"│ {leaf:^7} │"
            if i < len(leaf_devices) - 1:
                leaf_name_line += " "
        visual.append(leaf_name_line)
        
        leaf_bottom_line = ""
        for i, leaf in enumerate(leaf_devices):
            leaf_bottom_line += f"└─────────┘"
            if i < len(leaf_devices) - 1:
                leaf_bottom_line += " "
        visual.append(leaf_bottom_line)
        
        # Connection details
        visual.append("")
        visual.append("CONNECTION DETAILS:")
        visual.append("-" * 30)
        
        for device_name in spine_devices + leaf_devices:
            device = devices[device_name]
            if device.connections:
                visual.append(f"\n{device_name} ({device.role.upper()}):")
                for connection in device.connections:
                    if connection.connection_type == 'p2p':
                        visual.append(f"  {connection.local_interface} -> {connection.remote_device}:{connection.remote_interface}")
                        if connection.ip_address:
                            visual.append(f"    IP: {connection.ip_address}")
        
        # Protocol information
        visual.append("")
        visual.append("PROTOCOLS:")
        visual.append("-" * 15)
        visual.append("• OSPF: IGP for underlay routing")
        visual.append("• BGP: Used for overlay and external routing")
        visual.append("• BFD: Fast failure detection")
        
        return "\n".join(visual)
    
    def _assess_topology_health(self, devices: Dict[str, TopologyDevice], 
                               summary: Dict[str, Any]) -> str:
        """Assess overall topology health"""
        
        # Check if we have the expected spine-leaf connectivity
        connectivity_ratio = summary.get('connectivity_ratio', 0)
        
        if connectivity_ratio >= 0.9:  # 90% or more of expected connections
            return 'healthy'
        elif connectivity_ratio >= 0.7:  # 70% or more of expected connections
            return 'degraded'
        else:
            return 'critical'
    
    def get_network_topology(self) -> NetworkTopologyResponse:
        """Get comprehensive network topology information"""
        logger.info("Generating network topology information")
        
        try:
            # Create topology devices
            devices = self._create_topology_devices()
            
            # Create connections matrix
            connections_matrix = self._create_connections_matrix(devices)
            
            # Generate summary
            summary = self._generate_topology_summary(devices)
            
            # Generate visual representation
            visual = self._generate_visual_representation(devices, connections_matrix)
            
            # Assess health
            health_status = self._assess_topology_health(devices, summary)
            
            # Extract device lists
            spine_devices = [name for name, device in devices.items() if device.role == 'spine']
            leaf_devices = [name for name, device in devices.items() if device.role == 'leaf']
            
            response = NetworkTopologyResponse(
                timestamp=datetime.now().isoformat(),
                architecture='spine-leaf',
                devices=devices,
                connections_matrix=connections_matrix,
                spine_devices=spine_devices,
                leaf_devices=leaf_devices,
                topology_summary=summary,
                visual_representation=visual,
                health_status=health_status
            )
            
            logger.info(f"Generated topology with {len(devices)} devices, health: {health_status}")
            return response
            
        except Exception as e:
            logger.error(f"Error generating network topology: {e}")
            # Return minimal response on error
            return NetworkTopologyResponse(
                timestamp=datetime.now().isoformat(),
                architecture='spine-leaf',
                devices={},
                connections_matrix={},
                spine_devices=[],
                leaf_devices=[],
                topology_summary={'error': str(e)},
                visual_representation=f"Error generating topology: {e}",
                health_status='critical'
            )

# Convenience function for MCP integration
def get_network_topology() -> Dict[str, Any]:
    """Get network topology as dictionary for MCP tool"""
    service = NetworkTopologyService()
    topology = service.get_network_topology()
    return asdict(topology)

if __name__ == "__main__":
    # Test the service
    service = NetworkTopologyService()
    topology = service.get_network_topology()
    print(json.dumps(asdict(topology), indent=2, default=str))