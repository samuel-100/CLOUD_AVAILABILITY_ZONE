#!/usr/bin/env python3
"""
Enhanced Network Protocol Configuration Generator
Generates comprehensive OSPF, BGP, HSRP, QoS, and Security configurations
Based on the Clos Architecture topology with correct management IPs and credentials
"""

import asyncio
import yaml
import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedNetworkConfigurator:
    """Enhanced Network Protocol Configuration Generator"""
    
    def __init__(self, config_path: str = "./config", templates_path: str = "./templates"):
        self.config_path = Path(config_path)
        self.templates_path = Path(templates_path)
        self.jinja_env = Environment(loader=FileSystemLoader(str(self.templates_path)))
        
    async def generate_device_configurations(self) -> None:
        """Generate configurations for all devices in the topology"""
        
        # Load topology data
        topology_file = Path("network_topology.yaml")
        with open(topology_file, 'r') as f:
            topology_data = yaml.safe_load(f)
        
        devices = topology_data['topology']['devices']
        
        logger.info("Starting configuration generation for all devices...")
        
        for device in devices:
            try:
                device_name = device['name']
                logger.info(f"Generating configuration for {device_name}")
                
                # Generate comprehensive configuration
                config = await self.generate_complete_config(device)
                
                # Save configuration to file
                config_file = Path(f"configs/generated/{device_name}_complete_config.txt")
                config_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(config_file, 'w') as f:
                    f.write(config)
                
                logger.info(f"✅ Configuration saved: {config_file}")
                
            except Exception as e:
                logger.error(f"❌ Error generating config for {device['name']}: {e}")
    
    async def generate_complete_config(self, device: Dict[str, Any]) -> str:
        """Generate complete device configuration"""
        
        device_name = device['name']
        device_role = device['role']
        device_os = device['os']
        
        # Generate timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Base configuration
        base_config = self._generate_base_config(device)
        
        # Interface configuration
        interface_config = self._generate_interface_config(device)
        
        # OSPF configuration
        ospf_config = self._generate_ospf_config(device)
        
        # BGP configuration  
        bgp_config = self._generate_bgp_config(device)
        
        # HSRP configuration (for spine switches)
        hsrp_config = ""
        if device_role == 'spine' and 'svis' in device:
            hsrp_config = self._generate_hsrp_config(device)
        
        # QoS configuration
        qos_config = self._generate_qos_config(device)
        
        # Security configuration
        security_config = self._generate_security_config(device)
        
        # Monitoring configuration
        monitoring_config = self._generate_monitoring_config(device)
        
        # Combine all configurations
        complete_config = f"""!
! ================================================================
! CLOUD AVAILABILITY ZONE - {device_name.upper()} CONFIGURATION
! ================================================================
! Generated: {timestamp}
! Device: {device_name} ({device_role.upper()})
! OS: {device_os.upper()}
! Management IP: {device['mgmt_ip']}
! Credentials: {device['ssh']['username']}/{device['ssh']['password']}
! ================================================================
!

{base_config}

{interface_config}

{ospf_config}

{bgp_config}

{hsrp_config}

{qos_config}

{security_config}

{monitoring_config}

!
! ================================================================
! END OF CONFIGURATION - {device_name.upper()}
! ================================================================
!
"""
        
        return complete_config
    
    def _generate_base_config(self, device: Dict[str, Any]) -> str:
        """Generate base system configuration"""
        
        device_name = device['name']
        device_os = device['os']
        mgmt_ip = device['mgmt_ip']
        username = device['ssh']['username']
        password = device['ssh']['password']
        
        if device_os.lower() == 'nxos':
            return f"""!
! === BASE SYSTEM CONFIGURATION (NX-OS) ===
!
hostname {device_name}
!
feature ospf
feature bgp
feature hsrp
feature interface-vlan
feature vpc
feature lacp
feature lldp
feature bfd
feature dhcp
!
no password strength-check
username {username} password 0 {password} role network-admin
username {username} keypair generate rsa
!
ip domain-name cloud-automation.local
ip name-server 8.8.8.8 8.8.4.4
!
interface mgmt0
  description Management Interface
  ip address {mgmt_ip}/24
  no shutdown
!
vrf context management
  ip route 0.0.0.0/0 192.168.100.1
!
boot nxos bootflash:nxos.9.3.8.bin
!
clock timezone UTC 0 0
clock summer-time UTC recurring
!
banner motd ^
================================================================
    CLOUD AVAILABILITY ZONE - {device_name.upper()}
    Network Automation Platform
    Unauthorized access prohibited
================================================================
^
!"""
        else:  # IOS
            return f"""!
! === BASE SYSTEM CONFIGURATION (IOS) ===
!
hostname {device_name}
!
enable secret 5 $1$mERr$9cTjUIEqNGurQiFU2ZNPh0
!
username {username} privilege 15 secret 0 {password}
!
ip domain-name cloud-automation.local
ip name-server 8.8.8.8
ip name-server 8.8.4.4
!
interface GigabitEthernet0/0
  description Management Interface  
  ip address {mgmt_ip} 255.255.255.0
  no shutdown
!
ip route 0.0.0.0 0.0.0.0 192.168.100.1
!
clock timezone UTC 0 0
clock summer-time UTC recurring
!
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
!
banner motd ^
================================================================
    CLOUD AVAILABILITY ZONE - {device_name.upper()}
    Network Automation Platform
    Unauthorized access prohibited
================================================================
^
!"""
    
    def _generate_interface_config(self, device: Dict[str, Any]) -> str:
        """Generate interface configuration"""
        
        device_os = device['os']
        interfaces = device.get('interfaces', [])
        
        config = "!\n! === INTERFACE CONFIGURATION ===\n!\n"
        
        for interface in interfaces:
            interface_name = interface['name']
            description = interface.get('description', 'Network Interface')
            
            config += f"interface {interface_name}\n"
            config += f"  description {description}\n"
            
            # Handle different interface types
            if interface.get('switchport', True) == False:
                # Routed interface
                if device_os.lower() == 'nxos':
                    config += "  no switchport\n"
                config += f"  ip address {interface['ip']}\n"
                config += "  no shutdown\n"
                
                # BFD configuration
                if interface.get('ospf_bfd', False):
                    if device_os.lower() == 'nxos':
                        config += "  ip ospf bfd\n"
                    else:
                        config += "  bfd interval 300 min_rx 300 multiplier 3\n"
                        config += "  ip ospf bfd\n"
                        
            else:
                # Switched interface
                if 'mode' in interface:
                    config += f"  switchport mode {interface['mode']}\n"
                if 'vlan' in interface:
                    config += f"  switchport access vlan {interface['vlan']}\n"
                if 'trunk_vlans' in interface:
                    config += f"  switchport trunk allowed vlan {interface['trunk_vlans']}\n"
                    
                config += "  no shutdown\n"
            
            config += "!\n"
        
        return config
    
    def _generate_ospf_config(self, device: Dict[str, Any]) -> str:
        """Generate OSPF configuration"""
        
        device_name = device['name']
        device_os = device['os']
        ospf_data = device.get('ospf', {})
        interfaces = device.get('interfaces', [])
        
        process_id = ospf_data.get('process_id', 1)
        router_id = ospf_data.get('router_id')
        
        config = "!\n! === OSPF CONFIGURATION ===\n!\n"
        
        if device_os.lower() == 'nxos':
            config += f"""router ospf {process_id}
  router-id {router_id}
  log-adjacency-changes detail
  auto-cost reference-bandwidth 100000
  area 0 authentication message-digest
  graceful-restart
  graceful-restart grace-period 60
  max-lsa 12000
  timers throttle lsa 0 50 5000
  timers throttle spf 50 200 5000
  passive-interface default
  bfd all-interfaces
!"""
            
            # Interface-specific OSPF config for NX-OS
            for interface in interfaces:
                if interface.get('ospf_area') is not None:
                    config += f"""interface {interface['name']}
  ip router ospf {process_id} area {interface['ospf_area']}
  ip ospf network point-to-point
  ip ospf hello-interval 1
  ip ospf dead-interval 3
  ip ospf message-digest-key 1 md5 CloudAutomation123!
  no passive-interface {interface['name']}
!"""
        else:
            # IOS OSPF Configuration
            config += f"""router ospf {process_id}
  router-id {router_id}
  log-adjacency-changes detail
  auto-cost reference-bandwidth 10000
  area 0 authentication message-digest
  timers throttle spf 50 200 5000
  timers throttle lsa 0 50 5000
  passive-interface default
  bfd all-interfaces
"""
            
            # Network statements for IOS
            networks = ospf_data.get('networks', [])
            for network in networks:
                config += f"  network {network['address']} {network['wildcard']} area {network['area']}\n"
            
            config += "!\n"
            
            # Interface-specific OSPF config for IOS
            for interface in interfaces:
                if interface.get('ospf_area') is not None:
                    config += f"""interface {interface['name']}
  ip ospf {process_id} area {interface['ospf_area']}
  ip ospf network point-to-point
  ip ospf hello-interval 1
  ip ospf dead-interval 3
  ip ospf message-digest-key 1 md5 CloudAutomation123!
  no passive-interface {interface['name']}
!"""
        
        return config
    
    def _generate_bgp_config(self, device: Dict[str, Any]) -> str:
        """Generate BGP configuration"""
        
        device_name = device['name']
        device_os = device['os']
        device_role = device['role']
        bgp_data = device.get('bgp', {})
        
        if not bgp_data:
            return "! No BGP configuration required\n"
        
        asn = bgp_data.get('asn')
        router_id = bgp_data.get('router_id')
        neighbors = bgp_data.get('neighbors', [])
        
        config = "!\n! === BGP CONFIGURATION ===\n!\n"
        
        if device_os.lower() == 'nxos':
            config += f"""router bgp {asn}
  router-id {router_id}
  bestpath as-path multipath-relax
  bestpath compare-routerid
  reconnect-interval 12
  log-neighbor-changes
  graceful-restart restart-time 120
  graceful-restart stalepath-time 300
  
  address-family ipv4 unicast
    redistribute ospf 1 route-map OSPF-TO-BGP
    redistribute direct route-map CONNECTED-TO-BGP
    maximum-paths 8
    maximum-paths ibgp 8
    distance bgp 20 200 200
    dampening 15 750 2000 60
  
  address-family l2vpn evpn
    maximum-paths 8
    maximum-paths ibgp 8
    retain route-target all
"""
            
            # BGP neighbors for NX-OS
            if device_role == 'spine':
                config += """  
  template peer LEAF-PEERS
    remote-as {asn}
    update-source loopback0
    timers 3 9
    password CloudBGP123!
    address-family ipv4 unicast
      send-community
      send-community extended
      route-reflector-client
      soft-reconfiguration inbound
      maximum-prefix 1000 85 restart 5
    address-family l2vpn evpn
      send-community
      send-community extended
      route-reflector-client
""".format(asn=asn)
            
            for neighbor in neighbors:
                config += f"""  
  neighbor {neighbor['ip']}
    description {neighbor.get('desc', f"BGP-Peer-{neighbor['ip']}")}
    inherit peer {'LEAF-PEERS' if device_role == 'spine' else 'SPINE-PEERS'}
"""
        else:
            # IOS BGP Configuration
            config += f"""router bgp {asn}
  bgp router-id {router_id}
  bgp log-neighbor-changes
  bgp bestpath as-path multipath-relax
  bgp bestpath compare-routerid
  bgp graceful-restart restart-time 120
  bgp graceful-restart stalepath-time 300
  maximum-paths 8
  maximum-paths ibgp 8
  bgp dampening 15 750 2000 60
  
  redistribute ospf 1 route-map OSPF-TO-BGP
  redistribute connected route-map CONNECTED-TO-BGP
"""
            
            for neighbor in neighbors:
                config += f"""
  neighbor {neighbor['ip']} remote-as {neighbor['asn']}
  neighbor {neighbor['ip']} description {neighbor.get('desc', f"BGP-Peer-{neighbor['ip']}")}
  neighbor {neighbor['ip']} update-source Loopback0
  neighbor {neighbor['ip']} timers 3 9
  neighbor {neighbor['ip']} password CloudBGP123!
  neighbor {neighbor['ip']} send-community
  neighbor {neighbor['ip']} send-community extended
  neighbor {neighbor['ip']} soft-reconfiguration inbound
  neighbor {neighbor['ip']} maximum-prefix 1000 85 restart 5"""
                
                if device_role == 'spine' and 'LEAF' in neighbor.get('desc', '').upper():
                    config += f"""
  neighbor {neighbor['ip']} route-reflector-client"""
        
        config += "\n!\n"
        
        # Route-maps
        config += """!
! BGP Route Maps
!
route-map OSPF-TO-BGP permit 10
  match ip address prefix-list LOOPBACKS
  set origin igp
  set local-preference 200
  set community 65000:100
!
route-map OSPF-TO-BGP permit 20
  match ip address prefix-list SERVER-NETWORKS
  set origin igp
  set local-preference 150
  set community 65000:200
!
route-map OSPF-TO-BGP deny 30
!
route-map CONNECTED-TO-BGP permit 10
  match ip address prefix-list LOOPBACKS
  set origin igp
  set local-preference 200
  set community 65000:100
!
route-map CONNECTED-TO-BGP deny 20
!
ip prefix-list LOOPBACKS permit 1.1.1.1/32
ip prefix-list LOOPBACKS permit 2.2.2.2/32
ip prefix-list LOOPBACKS permit 11.11.11.11/32
ip prefix-list LOOPBACKS permit 12.12.12.12/32
ip prefix-list LOOPBACKS permit 13.13.13.13/32
ip prefix-list LOOPBACKS permit 14.14.14.14/32
!
ip prefix-list SERVER-NETWORKS permit 192.168.100.0/24
ip prefix-list SERVER-NETWORKS permit 192.168.200.0/24
ip prefix-list SERVER-NETWORKS permit 192.168.30.0/24
!"""
        
        return config
    
    def _generate_hsrp_config(self, device: Dict[str, Any]) -> str:
        """Generate HSRP configuration for spine switches"""
        
        device_os = device['os']
        svis = device.get('svis', [])
        
        if not svis:
            return "! No HSRP configuration required\n"
        
        config = "!\n! === HSRP CONFIGURATION ===\n!\n"
        
        # Track objects for interface monitoring
        config += """!
! Track Objects
track 1 interface ethernet1/1 line-protocol
track 2 interface ethernet1/2 line-protocol
track 3 interface ethernet1/3 line-protocol
track 4 interface ethernet1/4 line-protocol
!
"""
        
        for svi in svis:
            vlan_id = svi['vlan_id']
            description = svi.get('description', f'VLAN {vlan_id} Gateway')
            ip_address = svi['ip']
            hsrp_ip = svi.get('hsrp_ip')
            priority = svi.get('priority', 100)
            
            if device_os.lower() == 'nxos':
                config += f"""interface vlan{vlan_id}
  description {description}
  no shutdown
  ip address {ip_address}
  
  hsrp version 2
  hsrp {vlan_id}
    authentication md5 key-string CloudHSRP123!
    preempt delay minimum 30
    priority {priority}
    timers 1 3
    ip {hsrp_ip}
    track 1 decrement 20
    track 2 decrement 20
    track 3 decrement 20
    track 4 decrement 20
    use-bia
!"""
            else:
                config += f"""interface vlan{vlan_id}
  description {description}
  ip address {ip_address}
  no shutdown
  
  standby version 2
  standby {vlan_id} authentication md5 key-string CloudHSRP123!
  standby {vlan_id} ip {hsrp_ip}
  standby {vlan_id} priority {priority}
  standby {vlan_id} preempt delay minimum 30
  standby {vlan_id} timers 1 3
  standby {vlan_id} track 1 decrement 20
  standby {vlan_id} track 2 decrement 20
  standby {vlan_id} track 3 decrement 20
  standby {vlan_id} track 4 decrement 20
!"""
        
        return config
    
    def _generate_qos_config(self, device: Dict[str, Any]) -> str:
        """Generate QoS configuration"""
        
        device_os = device['os']
        
        config = "!\n! === QoS CONFIGURATION ===\n!\n"
        
        if device_os.lower() == 'nxos':
            config += """system qos
qos statistics
!
class-map type qos match-any VOICE
  match dscp ef
!
class-map type qos match-any VIDEO
  match dscp af41
  match dscp af42
  match dscp af43
!
class-map type qos match-any CRITICAL-DATA
  match dscp af31
  match dscp af32
  match dscp af33
!
policy-map type qos EGRESS-POLICY
  class VOICE
    priority level 1
    bandwidth percent 20
    queue-limit 64 packets
    set dscp ef
  class VIDEO
    bandwidth percent 30
    queue-limit 64 packets
    set dscp af41
  class CRITICAL-DATA
    bandwidth percent 25
    queue-limit 64 packets
    set dscp af31
  class class-default
    bandwidth percent remaining
    queue-limit 64 packets
    random-detect
!"""
        else:
            config += """class-map match-any VOICE
  match dscp ef
!
class-map match-any VIDEO
  match dscp af41
  match dscp af42
  match dscp af43
!
class-map match-any CRITICAL-DATA
  match dscp af31
  match dscp af32
  match dscp af33
!
policy-map EGRESS-POLICY
  class VOICE
    priority percent 20
    set dscp ef
  class VIDEO
    bandwidth percent 30
    set dscp af41
  class CRITICAL-DATA
    bandwidth percent 25
    set dscp af31
  class class-default
    fair-queue
    random-detect
!"""
        
        return config
    
    def _generate_security_config(self, device: Dict[str, Any]) -> str:
        """Generate security configuration"""
        
        device_os = device['os']
        device_name = device['name']
        username = device['ssh']['username']
        password = device['ssh']['password']
        
        config = "!\n! === SECURITY CONFIGURATION ===\n!\n"
        
        # AAA Configuration
        config += """aaa new-model
aaa authentication login default local
aaa authentication enable default enable
aaa authorization console
aaa authorization exec default local
aaa accounting exec default start-stop local
aaa accounting commands 15 default start-stop local
!"""
        
        # User configuration with device-specific password
        config += f"""username {username} privilege 15 secret 0 {password}
username operator privilege 10 secret 0 operator123
username readonly privilege 1 secret 0 readonly123
!"""
        
        # SSH Configuration
        config += """ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
crypto key generate rsa general-keys modulus 2048
!"""
        
        # Line security
        config += """line console 0
  login authentication default
  logging synchronous
  exec-timeout 10 0
line vty 0 15
  login authentication default
  transport input ssh
  exec-timeout 10 0
  logging synchronous
!"""
        
        # Disable unnecessary services
        if device_os.lower() == 'nxos':
            config += """no feature telnet
no ip http server
no ip http secure-server
!"""
        else:
            config += """no ip http server
no ip http secure-server
no cdp run
service password-encryption
!"""
        
        return config
    
    def _generate_monitoring_config(self, device: Dict[str, Any]) -> str:
        """Generate monitoring configuration"""
        
        device_os = device['os']
        
        config = "!\n! === MONITORING CONFIGURATION ===\n!\n"
        
        # SNMP Configuration
        config += f"""snmp-server community CloudRO RO
snmp-server community CloudRW RW
snmp-server location Cloud Availability Zone
snmp-server contact Network Operations Center
snmp-server enable traps
!"""
        
        # Syslog Configuration
        config += """logging buffered 32768
logging console warnings
logging monitor warnings
logging trap informational
logging facility local0
logging source-interface loopback0
logging host 192.168.100.200
!"""
        
        # NTP Configuration
        config += """ntp authenticate
ntp authentication-key 1 md5 CloudNTP123!
ntp trusted-key 1
ntp server 192.168.100.201 key 1 prefer
ntp server 192.168.100.202 key 1
ntp source loopback0
!"""
        
        return config

async def main():
    """Main function to generate all configurations"""
    
    print("🚀 Starting Enhanced Network Configuration Generation...")
    print("=" * 70)
    
    configurator = EnhancedNetworkConfigurator()
    await configurator.generate_device_configurations()
    
    print("=" * 70)
    print("✅ Configuration generation completed successfully!")
    print("📁 Configurations saved to: configs/generated/")

if __name__ == "__main__":
    asyncio.run(main())
