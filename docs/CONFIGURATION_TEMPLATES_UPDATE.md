# Configuration Templates Update - NX-OS vs IOS Device Support

**Date**: August 4, 2025  
**Update Type**: Device-Specific Configuration Templates  
**Scope**: Complete template library for SPINE (NX-OS) and LEAF (IOS) devices

## Summary

Updated all configuration templates to properly support device-specific commands and syntax differences between NX-OS (SPINE devices) and IOS (LEAF devices). Templates now automatically detect device type based on device name patterns and generate appropriate configuration syntax.

## Updated Templates

### 1. Base Configuration Templates

#### `base_config.j2`
- **Device Detection**: Automatic NX-OS vs IOS detection based on device name
- **NX-OS Features**: Feature enablement, VDC configuration, NX-OS specific settings
- **IOS Features**: AAA configuration, line settings, archive configuration
- **Common Elements**: Security settings, management configuration, banner

#### `spine_nxos_config.j2` (NEW - Complete NX-OS Template)
- **Features**: BGP, OSPF, VPC, NV overlay, VXLAN
- **Interfaces**: Management, loopback, physical interfaces to leafs
- **Protocols**: OSPF underlay, BGP overlay with EVPN
- **VXLAN**: EVPN/VXLAN configuration for overlay networking
- **Optimization**: Route-maps, prefix-lists, system tuning

#### `leaf_iosv_config.j2` (NEW - Complete IOS Template)
- **Basic Config**: Hostname, users, domain, routing enablement
- **VLANs**: VLAN database and SVI configuration
- **Interfaces**: Access, trunk, uplink interfaces with proper IOS syntax
- **Protocols**: OSPF for underlay, BGP for overlay (if supported)
- **Services**: DHCP pools, access control, management features

### 2. Protocol-Specific Templates

#### BGP Configuration
- **`spine_bgp.j2`**: NX-OS BGP with route reflector, EVPN address family, templates
- **`leaf_bgp.j2`**: IOS BGP client configuration with proper IOS syntax
- **`bgp_config.j2`**: Device-aware template that selects appropriate BGP syntax

#### OSPF Configuration  
- **`spine_ospf.j2`**: NX-OS OSPF with graceful restart, BFD support, area configuration
- **`leaf_ospf.j2`**: IOS OSPF with network statements, passive interfaces, timers
- **`ospf_config.j2`**: Device-aware template that selects appropriate OSPF syntax

### 3. Interface Configuration Templates

#### `spine_interfaces.j2` (NX-OS Interface Configuration)
- **Physical Interfaces**: No switchport, IP addressing, OSPF configuration
- **Loopbacks**: Router ID and VTEP source interfaces
- **Management**: VRF-aware management interface
- **Port-Channels**: Link aggregation with LACP
- **Optimization**: BFD, QoS, storm control

#### `leaf_interfaces.j2` (IOS Interface Configuration)
- **Uplink Interfaces**: Layer 3 interfaces to spines with proper IOS syntax
- **Access Interfaces**: Switchport configuration, port security, STP optimization
- **Trunk Interfaces**: 802.1Q encapsulation, VLAN configuration
- **SVIs**: Inter-VLAN routing with HSRP redundancy
- **EtherChannel**: Link aggregation with LACP

### 4. L3 Fabric Templates

#### `spine_l3_fabric.j2` (NX-OS L3 Fabric)
- **EVPN/VXLAN**: Complete overlay configuration
- **Multicast**: PIM configuration for BUM traffic
- **VRFs**: L3VNI and tenant VRF configuration
- **NVE Interface**: VTEP configuration
- **Hardware**: Optimization for VXLAN performance

#### `leaf_l3_fabric.j2` (IOS L3 Fabric)
- **VRF Support**: Multi-tenancy with VRF lite
- **SVIs**: Gateway interfaces with anycast gateway (if supported)
- **DHCP**: Local DHCP pools for VLANs
- **BGP**: Fabric participation for reachability
- **QoS**: Quality of service policies

#### `l3_fabric_config.j2` (Device-Aware L3 Fabric)
- **Auto-Detection**: Selects NX-OS or IOS L3 fabric configuration
- **Feature Parity**: Maintains functionality across both platforms
- **Fallback**: Generic configuration for unknown device types

## Key Template Features

### Device Detection Logic
```jinja2
{% if 'SPINE' in device_name.upper() %}
  <!-- NX-OS Configuration -->
{% elif 'LEAF' in device_name.upper() %}
  <!-- IOS Configuration -->
{% else %}
  <!-- Generic Configuration -->
{% endif %}
```

### Command Syntax Differences Addressed

#### Interface Configuration
- **NX-OS**: `no switchport`, `ip address x.x.x.x/yy`
- **IOS**: `no switchport`, `ip address x.x.x.x y.y.y.y`

#### OSPF Configuration
- **NX-OS**: `ip router ospf <process> area <area>`
- **IOS**: `ip ospf <process> area <area>`

#### BGP Configuration
- **NX-OS**: Templates, address-family structure, route-reflector-client
- **IOS**: Traditional neighbor configuration, address-family activation

#### Feature Enablement
- **NX-OS**: `feature bgp`, `feature ospf`, `feature nv overlay`
- **IOS**: Features enabled by default or via global commands

### Template Variables

#### Common Variables
- `device_name`: Device hostname (used for type detection)
- `mgmt_ip`: Management IP address
- `loopback0_ip`: Router ID and BGP router ID
- `bgp_asn`: BGP autonomous system number
- `ospf_process_id`: OSPF process ID

#### NX-OS Specific Variables
- `vtep_ip`: VXLAN tunnel endpoint IP
- `l3vni_base`: Layer 3 VNI for tenant separation
- `anycast_gateway_mac`: Distributed anycast gateway MAC
- `pim_rp_address`: PIM rendezvous point address

#### IOS Specific Variables
- `enable_secret`: Enable password
- `admin_user`: Administrative username
- `dhcp_pools`: DHCP pool configurations
- `access_lists`: Access control list definitions

## Template Usage

### Ansible Playbook Integration
```yaml
- name: Generate device configuration
  template:
    src: "{{ device_config_template }}"
    dest: "configs/generated/{{ inventory_hostname }}_config.txt"
  vars:
    device_config_template: >-
      {% if 'SPINE' in inventory_hostname.upper() %}
        spine_nxos_config.j2
      {% elif 'LEAF' in inventory_hostname.upper() %}
        leaf_iosv_config.j2
      {% else %}
        base_config.j2
      {% endif %}
```

### Variable File Structure
```yaml
# Group variables for spine devices (NX-OS)
spine_devices:
  bgp_asn: 65001
  ospf_process_id: 1
  l3vni_base: 10001
  vtep_ip: "10.1.1.{{ ansible_play_hosts.index(inventory_hostname) + 1 }}"

# Group variables for leaf devices (IOS)  
leaf_devices:
  bgp_asn: 65001
  ospf_process_id: 1
  enable_secret: "{{ vault_enable_secret }}"
  admin_user: admin
```

## Validation and Testing

### Template Syntax Validation
- All templates validated for Jinja2 syntax
- Device-specific logic tested with sample variables
- Command syntax verified against platform documentation

### Configuration Generation Testing
- Generated configurations tested against device parsers
- Syntax validation performed for both NX-OS and IOS
- Template rendering verified with various device scenarios

## Benefits

1. **Automatic Platform Detection**: No manual template selection required
2. **Syntax Accuracy**: Platform-specific command syntax ensures successful deployment
3. **Feature Optimization**: Templates optimized for each platform's capabilities
4. **Maintenance Efficiency**: Single template set supports both device types
5. **Error Reduction**: Eliminates configuration syntax errors between platforms
6. **Scalability**: Easy addition of new device types and platforms

## Next Steps

1. **Testing**: Deploy templates in lab environment for validation
2. **Documentation**: Create configuration deployment procedures
3. **Automation**: Integrate templates with existing deployment workflows
4. **Monitoring**: Implement template-aware monitoring and validation
5. **Expansion**: Add support for additional device types (e.g., border routers)

This comprehensive template update ensures accurate configuration generation for both NX-OS (SPINE) and IOS (LEAF) devices while maintaining automation efficiency and reducing deployment errors.
