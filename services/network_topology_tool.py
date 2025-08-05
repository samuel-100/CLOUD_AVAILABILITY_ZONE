#!/usr/bin/env python3
"""
Network Topology Tool for MCP Integration
Provides spine-leaf architecture details, device relationships, connection mapping,
and visual topology representation for Claude.
"""

import os
import yaml
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import re

# File paths
TOPOLOGY_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/network_topology.yaml'
DEVICES_FILE = '/opt/network-automation/CLOUD_AVAILABILITY_ZONE/devices.yaml'

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """Device information for topology"""
    name: str
    role: str  # 'spine' or 'leaf'
    os: str
    mgmt_ip: str
    loopback_ip: Optional[str] = None
    router_id: Optional[str] = None
    bgp_asn: Optional[int] = None
    interfaces: List[Dict[str, Any]] = None
    vlans: List[Dict[str, Any]] = None

@dataclass
class Connection:
    """Network connection between devices"""
    source_device: str
    source_interface: str
    destination_device: str
    destination_interface: str
    connection_type: str  # 'p2p', 'access', 'trunk'
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    subnet: Optional[str] = None
    description: Optional[str] = None
    protocols: List[str] = None  # ['ospf', 'bgp', 'bfd']

@dataclass
class VLANInfo:
    """VLAN information"""
    vlan_id: int
    name: str
    description: Optional[str] = None
    devices: List[str] = None
    svi_ips: Dict[str, str] = None  # device_name -> svi_ip

@dataclass
class ProtocolInfo:
    """Protocol configuration information"""
    protocol: str  # 'ospf', 'bgp', 'bfd'
    enabled_devices: List[str]
    configuration: Dict[str, Any]

@dataclass
class TopologyVisualization:
    """Visual representation data for topology"""
    mermaid_diagram: str
    ascii_diagram: str
    connection_matrix: Dict[str, List[str]]
    device_positions: Dict[str, Dict[str, int]]  # device -> {x, y}

@dataclass
class NetworkTopologyResponse:
    """Complete network topology response"""
    timestamp: str
    architecture: str  # 'spine-leaf'
    total_devices: int
    spine_count: int
    leaf_count: int
    
    # Device information
    devices: List[DeviceInfo]
    device_roles: Dict[str, List[str]]  # role -> [device_names]
    
    # Connection information
    connections: List[Connection]
    connection_summary: Dict[str, int]  # connection_type -> count
    
    # VLAN information
    vlans: List[VLANInfo]
    
    # Protocol information
    protocols: List[ProtocolInfo]
    
    # Visualization
    visualization: TopologyVisualization
    
    # Network segments and subnets
    network_segments: Dict[str, List[str]]  # segment_type -> [subnets]
    ip_addressing_scheme: Dict[str, str]  # description -> subnet
    
    # Redundancy and resilience info
    redundancy_info: Dict[str, Any]
    
    # Additional metadata
    last_updated: str
    configuration_source: str

def load_topology():
    """Load network topology configuration"""
    with open(TOPOLOGY_FILE) as f:
        data = yaml.safe_load(f)
        if not data or 'topology' not in data:
            logger.error('network_topology.yaml is empty or missing "topology" key.')
            raise ValueError('network_topology.yaml is empty or missing "topology" key.')
        return data['topology']

def load_device_credentials():
    """Load device credentials for additional info"""
    try:
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
    except Exception as e:
        logger.warning(f"Could not load device credentials: {e}")
        return {}

def parse_devices(topology_data):
    """Parse device information from topology"""
    devices = []
    
    for device_data in topology_data['devices']:
        device = DeviceInfo(
            name=device_data['name'],
            role=device_data.get('role', 'unknown'),
            os=device_data.get('os', 'unknown'),
            mgmt_ip=device_data['mgmt_ip'],
            loopback_ip=device_data.get('loopback', {}).get('ip'),
            router_id=device_data.get('ospf', {}).get('router_id') or device_data.get('bgp', {}).get('router_id'),
            bgp_asn=device_data.get('bgp', {}).get('asn'),
            interfaces=device_data.get('interfaces', []),
            vlans=device_data.get('vlans', [])
        )
        devices.append(device)
    
    return devices

def extract_connections(topology_data):
    """Extract network connections from topology data"""
    connections = []
    
    # Create a mapping of IP addresses to devices and interfaces
    ip_to_device = {}
    
    for device_data in topology_data['devices']:
        device_name = device_data['name']
        for interface in device_data.get('interfaces', []):
            if 'ip' in interface:
                ip = interface['ip'].split('/')[0]  # Remove subnet mask
                ip_to_device[ip] = {
                    'device': device_name,
                    'interface': interface['name'],
                    'subnet': interface['ip']
                }
    
    # Find connections by matching subnets
    processed_subnets = set()
    
    for device_data in topology_data['devices']:
        device_name = device_data['name']
        
        for interface in device_data.get('interfaces', []):
            if 'ip' not in interface or interface.get('switchport', False):
                continue
            
            interface_ip = interface['ip']
            subnet = get_subnet_from_ip(interface_ip)
            
            if subnet in processed_subnets:
                continue
            
            # Find other devices in the same subnet
            connected_devices = []
            for other_device_data in topology_data['devices']:
                if other_device_data['name'] == device_name:
                    continue
                
                for other_interface in other_device_data.get('interfaces', []):
                    if 'ip' not in other_interface:
                        continue
                    
                    other_subnet = get_subnet_from_ip(other_interface['ip'])
                    if other_subnet == subnet:
                        connected_devices.append({
                            'device': other_device_data['name'],
                            'interface': other_interface['name'],
                            'ip': other_interface['ip']
                        })
            
            # Create connections
            for connected_device in connected_devices:
                protocols = []
                if interface.get('ospf_area') is not None:
                    protocols.append('ospf')
                if interface.get('ospf_bfd'):
                    protocols.append('bfd')
                
                connection = Connection(
                    source_device=device_name,
                    source_interface=interface['name'],
                    destination_device=connected_device['device'],
                    destination_interface=connected_device['interface'],
                    connection_type='p2p',
                    source_ip=interface_ip,
                    destination_ip=connected_device['ip'],
                    subnet=subnet,
                    description=interface.get('description', ''),
                    protocols=protocols
                )
                connections.append(connection)
            
            processed_subnets.add(subnet)
    
    return connections

def get_subnet_from_ip(ip_with_mask):
    """Extract subnet from IP address with mask"""
    try:
        ip, mask = ip_with_mask.split('/')
        mask_int = int(mask)
        
        # Convert IP to integer
        ip_parts = [int(part) for part in ip.split('.')]
        ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
        
        # Apply subnet mask
        mask_bits = (0xFFFFFFFF << (32 - mask_int)) & 0xFFFFFFFF
        subnet_int = ip_int & mask_bits
        
        # Convert back to dotted decimal
        subnet_ip = f"{(subnet_int >> 24) & 0xFF}.{(subnet_int >> 16) & 0xFF}.{(subnet_int >> 8) & 0xFF}.{subnet_int & 0xFF}"
        
        return f"{subnet_ip}/{mask}"
    except Exception:
        return ip_with_mask

def extract_vlans(topology_data):
    """Extract VLAN information from topology"""
    vlan_map = {}
    
    for device_data in topology_data['devices']:
        device_name = device_data['name']
        
        # Process VLANs
        for vlan in device_data.get('vlans', []):
            vlan_id = vlan['id']
            vlan_name = vlan['name']
            
            if vlan_id not in vlan_map:
                vlan_map[vlan_id] = VLANInfo(
                    vlan_id=vlan_id,
                    name=vlan_name,
                    devices=[],
                    svi_ips={}
                )
            
            vlan_map[vlan_id].devices.append(device_name)
        
        # Process SVIs
        for svi in device_data.get('svis', []):
            vlan_id = svi['vlan_id']
            svi_ip = svi['ip']
            
            if vlan_id in vlan_map:
                vlan_map[vlan_id].svi_ips[device_name] = svi_ip
    
    return list(vlan_map.values())

def extract_protocols(topology_data):
    """Extract protocol configuration information"""
    protocols = []
    
    # OSPF Protocol
    ospf_devices = []
    ospf_config = {}
    
    for device_data in topology_data['devices']:
        if 'ospf' in device_data:
            ospf_devices.append(device_data['name'])
            ospf_config[device_data['name']] = device_data['ospf']
    
    if ospf_devices:
        protocols.append(ProtocolInfo(
            protocol='ospf',
            enabled_devices=ospf_devices,
            configuration=ospf_config
        ))
    
    # BGP Protocol
    bgp_devices = []
    bgp_config = {}
    
    for device_data in topology_data['devices']:
        if 'bgp' in device_data:
            bgp_devices.append(device_data['name'])
            bgp_config[device_data['name']] = device_data['bgp']
    
    if bgp_devices:
        protocols.append(ProtocolInfo(
            protocol='bgp',
            enabled_devices=bgp_devices,
            configuration=bgp_config
        ))
    
    # BFD Protocol
    bfd_devices = []
    bfd_config = {}
    
    for device_data in topology_data['devices']:
        if 'bfd' in device_data:
            bfd_devices.append(device_data['name'])
            bfd_config[device_data['name']] = device_data['bfd']
    
    if bfd_devices:
        protocols.append(ProtocolInfo(
            protocol='bfd',
            enabled_devices=bfd_devices,
            configuration=bfd_config
        ))
    
    return protocols

def create_mermaid_diagram(devices, connections):
    """Create Mermaid diagram representation"""
    mermaid = ["graph TD"]
    
    # Add devices with styling based on role
    for device in devices:
        if device.role == 'spine':
            mermaid.append(f"    {device.name}[{device.name}<br/>Spine<br/>{device.mgmt_ip}]")
            mermaid.append(f"    {device.name} --> {device.name}")
            mermaid.append(f"    class {device.name} spine")
        else:
            mermaid.append(f"    {device.name}[{device.name}<br/>Leaf<br/>{device.mgmt_ip}]")
            mermaid.append(f"    class {device.name} leaf")
    
    # Add connections
    for conn in connections:
        label = f"{conn.source_interface}<br/>to<br/>{conn.destination_interface}"
        mermaid.append(f"    {conn.source_device} ---|{label}| {conn.destination_device}")
    
    # Add styling
    mermaid.extend([
        "    classDef spine fill:#e1f5fe,stroke:#01579b,stroke-width:2px",
        "    classDef leaf fill:#f3e5f5,stroke:#4a148c,stroke-width:2px"
    ])
    
    return "\n".join(mermaid)

def create_ascii_diagram(devices, connections):
    """Create ASCII art representation of the topology"""
    spines = [d for d in devices if d.role == 'spine']
    leaves = [d for d in devices if d.role == 'leaf']
    
    ascii_lines = []
    ascii_lines.append("Network Topology - Spine-Leaf Architecture")
    ascii_lines.append("=" * 50)
    ascii_lines.append("")
    
    # Spine layer
    ascii_lines.append("SPINE LAYER:")
    spine_line = "  "
    for i, spine in enumerate(spines):
        spine_line += f"[{spine.name}]"
        if i < len(spines) - 1:
            spine_line += " ---- "
    ascii_lines.append(spine_line)
    ascii_lines.append("")
    
    # Connection lines
    connection_line = "  "
    for spine in spines:
        connection_line += "   |   "
        if spine != spines[-1]:
            connection_line += "      "
    ascii_lines.append(connection_line)
    ascii_lines.append("")
    
    # Leaf layer
    ascii_lines.append("LEAF LAYER:")
    leaf_line = "  "
    for i, leaf in enumerate(leaves):
        leaf_line += f"[{leaf.name}]"
        if i < len(leaves) - 1:
            leaf_line += "  "
    ascii_lines.append(leaf_line)
    ascii_lines.append("")
    
    # Add connection details
    ascii_lines.append("CONNECTIONS:")
    for conn in connections:
        ascii_lines.append(f"  {conn.source_device}:{conn.source_interface} <-> {conn.destination_device}:{conn.destination_interface}")
        if conn.subnet:
            ascii_lines.append(f"    Subnet: {conn.subnet}")
        if conn.protocols:
            ascii_lines.append(f"    Protocols: {', '.join(conn.protocols)}")
        ascii_lines.append("")
    
    return "\n".join(ascii_lines)

def create_connection_matrix(devices, connections):
    """Create connection matrix showing device interconnections"""
    device_names = [d.name for d in devices]
    matrix = {device: [] for device in device_names}
    
    for conn in connections:
        if conn.destination_device not in matrix[conn.source_device]:
            matrix[conn.source_device].append(conn.destination_device)
        if conn.source_device not in matrix[conn.destination_device]:
            matrix[conn.destination_device].append(conn.source_device)
    
    return matrix

def calculate_device_positions(devices):
    """Calculate positions for visual representation"""
    spines = [d for d in devices if d.role == 'spine']
    leaves = [d for d in devices if d.role == 'leaf']
    
    positions = {}
    
    # Position spines at the top
    spine_spacing = 200
    spine_start_x = -(len(spines) - 1) * spine_spacing // 2
    
    for i, spine in enumerate(spines):
        positions[spine.name] = {
            'x': spine_start_x + i * spine_spacing,
            'y': 100
        }
    
    # Position leaves at the bottom
    leaf_spacing = 150
    leaf_start_x = -(len(leaves) - 1) * leaf_spacing // 2
    
    for i, leaf in enumerate(leaves):
        positions[leaf.name] = {
            'x': leaf_start_x + i * leaf_spacing,
            'y': 300
        }
    
    return positions

def analyze_network_segments(topology_data, connections):
    """Analyze network segments and IP addressing"""
    segments = {
        'p2p_links': [],
        'management': [],
        'loopbacks': [],
        'server_vlans': []
    }
    
    addressing_scheme = {}
    
    # P2P links
    for conn in connections:
        if conn.connection_type == 'p2p' and conn.subnet:
            segments['p2p_links'].append(conn.subnet)
    
    # Management network
    for device_data in topology_data['devices']:
        mgmt_ip = device_data['mgmt_ip']
        if '/' in mgmt_ip:
            mgmt_subnet = get_subnet_from_ip(mgmt_ip)
            if mgmt_subnet not in segments['management']:
                segments['management'].append(mgmt_subnet)
    
    # Loopbacks
    for device_data in topology_data['devices']:
        loopback = device_data.get('loopback', {})
        if 'ip' in loopback:
            segments['loopbacks'].append(loopback['ip'])
    
    # Server VLANs
    for device_data in topology_data['devices']:
        for svi in device_data.get('svis', []):
            if 'ip' in svi:
                svi_subnet = get_subnet_from_ip(svi['ip'])
                if svi_subnet not in segments['server_vlans']:
                    segments['server_vlans'].append(svi_subnet)
    
    # Create addressing scheme descriptions
    addressing_scheme['P2P Links'] = '10.100.100.0/24 (subdivided into /30s)'
    addressing_scheme['Management'] = '192.168.100.0/24'
    addressing_scheme['Loopbacks'] = '1.1.1.0/24 - 14.14.14.0/24'
    addressing_scheme['Server VLANs'] = '192.168.x.0/24 networks'
    
    return segments, addressing_scheme

def analyze_redundancy(devices, connections):
    """Analyze network redundancy and resilience"""
    redundancy_info = {
        'spine_redundancy': False,
        'leaf_uplinks': {},
        'protocol_redundancy': {},
        'single_points_of_failure': []
    }
    
    spines = [d for d in devices if d.role == 'spine']
    leaves = [d for d in devices if d.role == 'leaf']
    
    # Check spine redundancy
    redundancy_info['spine_redundancy'] = len(spines) >= 2
    
    # Check leaf uplinks
    for leaf in leaves:
        uplinks = [c for c in connections if c.source_device == leaf.name and 
                  any(c.destination_device == s.name for s in spines)]
        redundancy_info['leaf_uplinks'][leaf.name] = len(uplinks)
    
    # Check protocol redundancy
    protocols = ['ospf', 'bgp', 'bfd']
    for protocol in protocols:
        enabled_devices = []
        for device_data in [d for d in devices]:
            # This would need to check the actual topology data
            pass
        redundancy_info['protocol_redundancy'][protocol] = len(enabled_devices) > 1
    
    # Identify single points of failure
    if len(spines) == 1:
        redundancy_info['single_points_of_failure'].append('Single spine device')
    
    for leaf in leaves:
        if redundancy_info['leaf_uplinks'].get(leaf.name, 0) < 2:
            redundancy_info['single_points_of_failure'].append(f'{leaf.name} has insufficient uplinks')
    
    return redundancy_info

def get_network_topology():
    """Get comprehensive network topology information - Main MCP tool function"""
    logger.info("Getting network topology information")
    
    try:
        # Load topology data
        topology_data = load_topology()
        
        # Parse devices
        devices = parse_devices(topology_data)
        
        # Extract connections
        connections = extract_connections(topology_data)
        
        # Extract VLANs
        vlans = extract_vlans(topology_data)
        
        # Extract protocols
        protocols = extract_protocols(topology_data)
        
        # Create visualizations
        mermaid_diagram = create_mermaid_diagram(devices, connections)
        ascii_diagram = create_ascii_diagram(devices, connections)
        connection_matrix = create_connection_matrix(devices, connections)
        device_positions = calculate_device_positions(devices)
        
        visualization = TopologyVisualization(
            mermaid_diagram=mermaid_diagram,
            ascii_diagram=ascii_diagram,
            connection_matrix=connection_matrix,
            device_positions=device_positions
        )
        
        # Analyze network segments
        network_segments, ip_addressing_scheme = analyze_network_segments(topology_data, connections)
        
        # Analyze redundancy
        redundancy_info = analyze_redundancy(devices, connections)
        
        # Create device role mapping
        device_roles = {
            'spine': [d.name for d in devices if d.role == 'spine'],
            'leaf': [d.name for d in devices if d.role == 'leaf']
        }
        
        # Create connection summary
        connection_summary = {
            'p2p': len([c for c in connections if c.connection_type == 'p2p']),
            'total': len(connections)
        }
        
        # Create response
        response = NetworkTopologyResponse(
            timestamp=datetime.now().isoformat(),
            architecture='spine-leaf',
            total_devices=len(devices),
            spine_count=len([d for d in devices if d.role == 'spine']),
            leaf_count=len([d for d in devices if d.role == 'leaf']),
            
            devices=devices,
            device_roles=device_roles,
            
            connections=connections,
            connection_summary=connection_summary,
            
            vlans=vlans,
            protocols=protocols,
            
            visualization=visualization,
            
            network_segments=network_segments,
            ip_addressing_scheme=ip_addressing_scheme,
            
            redundancy_info=redundancy_info,
            
            last_updated=datetime.now().isoformat(),
            configuration_source=TOPOLOGY_FILE
        )
        
        logger.info(f"Successfully analyzed network topology: {len(devices)} devices, {len(connections)} connections")
        return asdict(response)
        
    except Exception as e:
        logger.error(f"Failed to get network topology: {e}")
        return {
            'error': f'Failed to get network topology: {e}',
            'timestamp': datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Test the network topology tool
    topology = get_network_topology()
    print(json.dumps(topology, indent=2, default=str))