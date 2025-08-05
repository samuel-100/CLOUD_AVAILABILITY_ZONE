 NX-OS vs IOS Command Reference

This document outlines the command differences between NX-OS (SPINE devices) and IOS (LEAF devices) that are important for network monitoring and analysis.

 Device Types
- SPINE devices: NX-OS (Cisco Nexus)
- LEAF devices: IOS (Cisco IOS/IOSv)

 Command Differences

 1. System Information

 Version Information
- NX-OS: show version
  - Output format: system: version 9.3(x)
  - Uptime format: System uptime: X day(s), Y hour(s), Z minute(s)

- IOS: show version
  - Output format: Version X.Y(Z)
  - Uptime format: Router uptime is X days, Y hours, Z minutes

 CPU Utilization
- NX-OS: show system resources
  - Output format: CPU states: X.X% user, Y.Y% kernel, Z.Z% idle
  - Alternative: show processes cpu

- IOS: show processes cpu
  - Output format: CPU utilization for five seconds: X%/Y%; one minute: Z%

 Memory Information
- NX-OS: show system resources
  - Output format: Memory usage: XXXXK total, YYYYK used, ZZZZK free

- IOS: show memory summary or show memory
  - Output format: Various formats, often in table format

 2. Interface Information

 Interface Status
- NX-OS: show interface brief
  - More compact output
  - Different column headers

- IOS: show ip interface brief
  - Standard IOS format
  - Different status indicators

 Interface Details
- NX-OS: show interface <interface>
  - NX-OS specific counters and statistics

- IOS: show interfaces <interface>
  - IOS specific counters and statistics

 3. Routing Protocols

 OSPF
- NX-OS: show ip ospf neighbors
  - NX-OS OSPF implementation
  - Different state representations

- IOS: show ip ospf neighbor
  - Classic IOS OSPF
  - Standard OSPF states (FULL, FULL/DR, etc.)

 BGP
- NX-OS: show bgp summary or show ip bgp summary
  - NX-OS BGP implementation

- IOS: show ip bgp summary
  - IOS BGP implementation

 4. VXLAN/EVPN (Primarily NX-OS)

 VXLAN Tunnels
- NX-OS: show nve peers
  - show vxlan
  - show bgp l2vpn evpn summary

- IOS: Generally not supported in traditional IOS
  - Some newer IOS-XE versions support VXLAN

 5. Environmental Information

 Temperature
- NX-OS: show environment temperature
  - Detailed environmental sensors

- IOS: show environment or show environment temperature
  - May vary by platform

 Power
- NX-OS: show environment power

- IOS: show environment power or show power

 Parsing Considerations

 CPU Utilization Parsing
- NX-OS: Look for percentage in show system resources or show processes cpu
- IOS: Parse the "five seconds" value from show processes cpu

 Memory Utilization Parsing
- NX-OS: Calculate percentage from total/used in show system resources
- IOS: Parse from various memory command outputs, format varies

 Uptime Parsing
- NX-OS: Parse "System uptime: X day(s), Y hour(s)" format
- IOS: Parse "Router uptime is X days, Y hours" format

 Interface Parsing
- NX-OS: Use show interface brief and parse NX-OS format
- IOS: Use show ip interface brief and parse IOS format

 Protocol State Differences

 OSPF States
Both support standard OSPF states, but output formatting differs:
- FULL - Fully adjacent
- FULL/DR - Fully adjacent, neighbor is DR
- FULL/BDR - Fully adjacent, neighbor is BDR
- FULL/DROTHER - Fully adjacent, neighbor is neither DR nor BDR

 BGP States
- NX-OS: More detailed BGP information available
- IOS: Standard BGP states and neighbor information

 Implementation Notes

1. Device Type Detection: Use device name pattern (SPINE/LEAF) to determine command set
2. Command Selection: Choose appropriate commands based on device type
3. Output Parsing: Use device-specific regex patterns for parsing
4. Error Handling: Different devices may have different error responses
5. Feature Availability: Some features (like VXLAN) are primarily available on NX-OS

 Example Command Mapping

python
 Command mapping by device type
COMMANDS = {
    'nxos': {
        'cpu': 'show system resources',
        'memory': 'show system resources', 
        'interfaces': 'show interface brief',
        'ospf': 'show ip ospf neighbors',
        'bgp': 'show bgp summary',
        'vxlan': 'show nve peers'
    },
    'ios': {
        'cpu': 'show processes cpu',
        'memory': 'show memory summary',
        'interfaces': 'show ip interface brief', 
        'ospf': 'show ip ospf neighbor',
        'bgp': 'show ip bgp summary',
        'vxlan': None   Not typically available
    }
}


This reference should be used when implementing device-specific monitoring and analysis features.
