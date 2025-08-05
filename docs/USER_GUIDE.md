# 🚀 Network Automation Platform - User Guide

## 🎯 **Getting Started**

### **What is the Network Automation Platform?**

The Network Automation Platform is an AI-powered Model Context Protocol (MCP) server that provides intelligent network management capabilities through conversation with Claude AI. It enables network engineers to:

- Monitor network health and performance
- Troubleshoot issues with AI assistance
- Generate and deploy configurations automatically
- Perform proactive network optimization
- Track changes and maintain audit trails

### **Prerequisites**

- **Claude AI Access**: Available through Claude.ai, Claude Desktop, or API
- **Network Access**: Connection to target network devices
- **Python Environment**: Python 3.8+ with required dependencies
- **Permissions**: Appropriate network device credentials

## 🛠️ **Installation & Setup**

### **1. Environment Setup**

```bash
# Clone the repository
git clone <repository-url>
cd network-automation/CLOUD_AVAILABILITY_ZONE

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp config/auth_config.yaml.example config/auth_config.yaml
cp config/api_keys.yaml.example config/api_keys.yaml
```

### **2. Configuration**

#### **Device Configuration** (`devices.yaml`)
```yaml
devices:
  SPINE1:
    ip: 192.168.1.10
    type: spine
    os: nxos
    credentials:
      username: admin
      password: ${DEVICE_PASSWORD}
  LEAF1:
    ip: 192.168.1.20
    type: leaf
    os: ios
    credentials:
      username: admin
      password: ${DEVICE_PASSWORD}
```

#### **Network Topology** (`network_topology.yaml`)
```yaml
topology:
  type: spine-leaf
  spine_devices: [SPINE1, SPINE2]
  leaf_devices: [LEAF1, LEAF2, LEAF3]
  connections:
    - from: SPINE1
      to: LEAF1
      interface_from: Eth1/1
      interface_to: GigabitEthernet0/1
```

### **3. Start the MCP Server**

```bash
# Start the enhanced MCP server
python3 mcp/enhanced_mcp_server.py
```

### **4. Connect to Claude**

Add the MCP server to your Claude configuration:

```json
{
  "mcp_servers": {
    "network-automation": {
      "command": "python",
      "args": ["/path/to/mcp/enhanced_mcp_server.py"],
      "env": {
        "API_KEY": "your-api-key"
      }
    }
  }
}
```

## 💬 **Using Claude for Network Automation**

### **Basic Network Monitoring**

**Example Conversation:**

👤 **You**: "What's the current status of my network?"

🤖 **Claude**: "I'll check your network status now."

*[Claude calls `get_network_status` tool]*

🤖 **Claude**: "Your network shows:
- **Overall Status**: Healthy
- **Total Devices**: 6 (5 active, 1 down)
- **Topology**: Spine-leaf architecture
- **Issue**: LEAF3 appears to be unreachable

Would you like me to investigate the LEAF3 issue further?"

👤 **You**: "Yes, please check what's wrong with LEAF3"

🤖 **Claude**: "Let me analyze the LEAF3 issue."

*[Claude calls `get_device_details` and `analyze_network_issue` tools]*

🤖 **Claude**: "Analysis of LEAF3:
- **Status**: Unreachable
- **Last Seen**: 2 hours ago
- **Likely Cause**: Interface Eth1/1 is down
- **Recommendation**: Check physical connectivity and interface configuration

Would you like me to generate a configuration to bring the interface back up?"

### **Configuration Management**

**Example Conversation:**

👤 **You**: "I need to configure VLAN 100 on LEAF1 interface Ethernet0/1"

🤖 **Claude**: "I'll generate the VLAN configuration for LEAF1."

*[Claude calls `generate_configuration` tool]*

🤖 **Claude**: "Generated configuration for LEAF1:
```
interface Ethernet0/1
 switchport mode access
 switchport access vlan 100
 no shutdown
```

This configuration will:
- Set the interface to access mode
- Assign it to VLAN 100
- Ensure the interface is enabled

Would you like me to deploy this configuration?"

👤 **You**: "Yes, but schedule it for maintenance window tonight at 2 AM"

🤖 **Claude**: "I'll schedule the configuration deployment."

*[Claude calls `deploy_configuration` tool with scheduled deployment]*

🤖 **Claude**: "Configuration deployment scheduled:
- **Deployment ID**: dep_12345
- **Device**: LEAF1
- **Scheduled Time**: 2025-08-06 02:00:00 UTC
- **Status**: Pending approval

The deployment is now in the approval queue. You can approve it when ready."

### **Troubleshooting with AI**

**Example Conversation:**

👤 **You**: "Users are complaining about slow network performance between Building A and Building B"

🤖 **Claude**: "I'll analyze the performance issue between your buildings."

*[Claude calls multiple tools: `get_network_trends`, `analyze_network_correlation`, `get_performance_optimizations`]*

🤖 **Claude**: "Performance Analysis Results:

**Identified Issues:**
1. High utilization (85%) on SPINE1-LEAF2 link
2. Suboptimal BGP routing causing traffic hairpinning
3. Interface buffer overruns on SPINE1 Eth1/2

**Root Cause**: Traffic from Building A to Building B is routing through an inefficient path due to BGP route preference.

**Recommended Solutions:**
1. Adjust BGP local preference on LEAF2
2. Enable ECMP load balancing on spine switches
3. Increase buffer sizes on high-utilization interfaces

**Estimated Impact**: 40-60% improvement in inter-building latency

Would you like me to generate the configurations to implement these optimizations?"

### **Proactive Monitoring**

**Example Conversation:**

👤 **You**: "Start monitoring my network for any performance issues"

🤖 **Claude**: "I'll set up comprehensive network monitoring."

*[Claude calls `start_network_monitoring` and `start_proactive_monitoring`]*

🤖 **Claude**: "Proactive monitoring is now active:

**Monitoring Scope:**
- Performance metrics (every 60 seconds)
- Device health checks (every 5 minutes)
- Security events (real-time)
- Capacity utilization trends

**Alert Thresholds:**
- Interface utilization > 80%
- Device CPU > 75%
- Memory usage > 85%
- Packet loss > 0.1%

I'll proactively alert you to any issues and provide AI-powered recommendations for resolution. You can ask me anytime for the current monitoring status or recent alerts."

## 🎯 **Common Use Cases**

### **1. Daily Network Health Check**

**Prompt**: "Give me a complete health check of my network"

**What Claude Does:**
1. Checks overall network status
2. Reviews device health
3. Analyzes recent trends
4. Identifies potential issues
5. Provides proactive recommendations

### **2. Incident Response**

**Prompt**: "Network is down in the east wing, help me troubleshoot"

**What Claude Does:**
1. Analyzes affected devices and topology
2. Correlates recent changes with the outage
3. Identifies most likely root causes
4. Provides step-by-step troubleshooting guide
5. Generates recovery configurations if needed

### **3. Configuration Changes**

**Prompt**: "I need to add a new VLAN across all leaf switches"

**What Claude Does:**
1. Understands the topology and affected devices
2. Generates consistent configurations for all devices
3. Creates a deployment plan with proper sequencing
4. Schedules changes for maintenance windows
5. Provides rollback procedures

### **4. Performance Optimization**

**Prompt**: "Optimize my network for better performance"

**What Claude Does:**
1. Analyzes current performance metrics
2. Identifies bottlenecks and inefficiencies
3. Generates optimization recommendations
4. Calculates expected performance improvements
5. Creates implementation timeline

### **5. Compliance and Auditing**

**Prompt**: "Show me all configuration changes made last week"

**What Claude Does:**
1. Reviews audit logs and change history
2. Identifies who made what changes
3. Analyzes compliance with policies
4. Highlights any unauthorized changes
5. Provides detailed change reports

## 🔧 **Advanced Features**

### **Custom Network Policies**

Define custom policies that Claude will enforce:

```yaml
# validation_rules.yaml
policies:
  interface_naming:
    pattern: "^(Ethernet|GigabitEthernet|TenGigabitEthernet)\\d+/\\d+$"
    required: true
  vlan_ranges:
    production: "100-199"
    staging: "200-299"
    management: "300-399"
  security:
    require_description: true
    max_access_ports_per_vlan: 48
```

**Usage**: "Configure a new VLAN following our naming standards"

### **Integration with External Systems**

Connect to external monitoring and ticketing systems:

```python
# External integrations
integrations:
  monitoring:
    type: "prometheus"
    endpoint: "http://prometheus:9090"
  ticketing:
    type: "servicenow"
    instance: "company.service-now.com"
  backup:
    type: "git"
    repository: "git@github.com:company/network-configs.git"
```

### **Custom AI Models**

Enhance Claude's network knowledge with custom training:

```yaml
# Custom network context
network_knowledge:
  vendor_specific:
    cisco:
      command_reference: "docs/cisco_commands.yaml"
      best_practices: "docs/cisco_best_practices.md"
  company_specific:
    naming_conventions: "docs/naming_standards.md"
    network_diagrams: "docs/topology_diagrams/"
    escalation_procedures: "docs/escalation.md"
```

## 🚨 **Troubleshooting**

### **Common Issues**

#### **"Claude can't see my network tools"**
- Verify MCP server is running: `ps aux | grep enhanced_mcp_server`
- Check Claude configuration includes the network-automation MCP server
- Restart Claude application

#### **"Authentication failed"**
- Verify API keys in `config/api_keys.yaml`
- Check device credentials in `devices.yaml`
- Ensure proper RBAC permissions

#### **"Device unreachable"**
- Test network connectivity: `ping <device_ip>`
- Verify management interface configuration
- Check firewall rules and access lists

#### **"Configuration deployment failed"**
- Review device logs for syntax errors
- Check user privileges on target device
- Verify configuration compatibility with device OS

### **Logging and Diagnostics**

**View system logs:**
```bash
# Audit log (all API calls)
tail -f logs/audit.log

# Application logs
tail -f logs/automation.log

# Configuration deployment logs
tail -f logs/config_collection.log
```

**Enable debug mode:**
```bash
export LOG_LEVEL=DEBUG
python3 mcp/enhanced_mcp_server.py
```

## 📊 **Best Practices**

### **Security**
- Use least-privilege access for device credentials
- Regularly rotate API keys
- Enable audit logging for all changes
- Implement approval workflows for critical changes

### **Performance**
- Monitor network connectivity to devices
- Use scheduled deployments during maintenance windows
- Implement change batching for large configurations
- Cache frequently accessed device information

### **Reliability**
- Test configurations in staging environment first
- Maintain configuration backups
- Implement automatic rollback procedures
- Use incremental deployment strategies

### **Maintenance**
- Regularly update device inventory
- Keep network documentation current
- Monitor system resource usage
- Perform periodic health checks

## 📞 **Support and Resources**

### **Getting Help**
- **Documentation**: `/docs/` directory
- **API Reference**: `docs/API_DOCUMENTATION.md`
- **Troubleshooting**: This user guide
- **Community**: GitHub discussions

### **Reporting Issues**
1. Check logs for error messages
2. Gather relevant configuration files
3. Document steps to reproduce
4. Submit issue with full context

### **Feature Requests**
- Submit enhancement requests through GitHub issues
- Include use case and business justification
- Propose implementation approach if possible

---

**Version**: 1.0  
**Last Updated**: August 5, 2025  
**Compatibility**: Claude AI, Python 3.8+, Cisco IOS/NX-OS
