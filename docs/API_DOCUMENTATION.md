# 📚 Network Automation MCP API Documentation

## 🎯 **Overview**

This document provides comprehensive API documentation for all 18 MCP tools in the Network Automation platform. Each tool is accessible through the Enhanced MCP Server with secure authentication and role-based access control.

## 🔧 **Available Tools**

### **Core Network Tools**

#### 1. `get_network_status`
**Purpose**: Retrieve overall network health and status information
**Parameters**: None
**Returns**: 
```json
{
  "status": "healthy|degraded|critical",
  "total_devices": 6,
  "active_devices": 5,
  "failed_devices": 1,
  "last_check": "2025-08-05T10:30:00Z",
  "topology_type": "spine-leaf"
}
```
**Usage Example**:
```bash
# Query network status
mcp_client.call_tool("get_network_status", {})
```

#### 2. `get_device_details`
**Purpose**: Get detailed information about specific network devices
**Parameters**:
- `device_name` (string): Name of the device (e.g., "SPINE1", "LEAF1")
**Returns**:
```json
{
  "device_name": "SPINE1",
  "ip_address": "192.168.1.10",
  "device_type": "spine",
  "os_type": "nxos",
  "management_ip": "10.0.0.10",
  "status": "active",
  "last_seen": "2025-08-05T10:30:00Z",
  "interfaces": [...],
  "neighbors": [...]
}
```

#### 3. `get_network_topology`
**Purpose**: Retrieve complete network topology and device relationships
**Parameters**: None
**Returns**:
```json
{
  "topology_type": "spine-leaf",
  "devices": [...],
  "connections": [...],
  "health_summary": {...}
}
```

### **AI-Powered Analysis Tools**

#### 4. `analyze_network_issue`
**Purpose**: AI-powered analysis of network problems and issues
**Parameters**:
- `issue_description` (string): Description of the network issue
- `affected_devices` (array, optional): List of affected device names
**Returns**:
```json
{
  "analysis": "Root cause analysis...",
  "recommendations": [...],
  "severity": "high|medium|low",
  "estimated_impact": "...",
  "suggested_actions": [...]
}
```

#### 5. `generate_configuration`
**Purpose**: Generate device configurations using AI
**Parameters**:
- `device_name` (string): Target device name
- `config_type` (string): Type of configuration ("bgp", "ospf", "interfaces", etc.)
- `requirements` (string): Specific configuration requirements
**Returns**:
```json
{
  "generated_config": "configuration commands...",
  "config_type": "bgp",
  "device_name": "SPINE1",
  "validation_status": "valid",
  "estimated_lines": 25
}
```

### **Configuration Deployment Tools**

#### 6. `deploy_configuration`
**Purpose**: Deploy configuration changes to network devices
**Parameters**:
- `device_name` (string): Target device name
- `configuration` (string): Configuration commands to deploy
- `deployment_mode` (string): "immediate" or "scheduled"
**Returns**:
```json
{
  "deployment_id": "dep_12345",
  "status": "pending_approval",
  "device_name": "SPINE1",
  "scheduled_time": "2025-08-05T11:00:00Z"
}
```

#### 7. `get_deployment_status`
**Purpose**: Check status of configuration deployments
**Parameters**:
- `deployment_id` (string): Deployment ID to check
**Returns**:
```json
{
  "deployment_id": "dep_12345",
  "status": "completed|pending|failed",
  "progress": 100,
  "start_time": "2025-08-05T11:00:00Z",
  "completion_time": "2025-08-05T11:05:00Z"
}
```

#### 8. `approve_deployment`
**Purpose**: Approve pending configuration deployments
**Parameters**:
- `deployment_id` (string): Deployment ID to approve
- `approver` (string): Name/ID of approver
**Returns**:
```json
{
  "deployment_id": "dep_12345",
  "approval_status": "approved",
  "approver": "admin",
  "approval_time": "2025-08-05T10:45:00Z"
}
```

#### 9. `get_pending_approvals`
**Purpose**: Get list of deployments pending approval
**Parameters**: None
**Returns**:
```json
{
  "pending_deployments": [
    {
      "deployment_id": "dep_12345",
      "device_name": "SPINE1",
      "submitted_time": "2025-08-05T10:30:00Z",
      "submitter": "user1"
    }
  ]
}
```

### **Workflow Monitoring Tools**

#### 10. `get_workflow_status`
**Purpose**: Monitor status of network automation workflows
**Parameters**:
- `workflow_id` (string): Workflow ID to check
**Returns**:
```json
{
  "workflow_id": "wf_12345",
  "status": "running|completed|failed",
  "current_step": "configuration_generation",
  "progress": 60,
  "estimated_completion": "2025-08-05T11:15:00Z"
}
```

#### 11. `get_workflow_history`
**Purpose**: Get history of workflow executions
**Parameters**:
- `limit` (number, optional): Number of workflows to return (default: 10)
**Returns**:
```json
{
  "workflows": [
    {
      "workflow_id": "wf_12345",
      "type": "config_deployment",
      "status": "completed",
      "start_time": "2025-08-05T10:00:00Z",
      "duration": "15 minutes"
    }
  ]
}
```

### **Network Context & Intelligence**

#### 12. `get_network_context`
**Purpose**: Get contextual information about network state
**Parameters**:
- `context_type` (string, optional): "performance", "security", "topology"
**Returns**:
```json
{
  "context_type": "performance",
  "timestamp": "2025-08-05T10:30:00Z",
  "metrics": {...},
  "insights": [...],
  "recommendations": [...]
}
```

#### 13. `start_network_monitoring`
**Purpose**: Start continuous network monitoring
**Parameters**:
- `monitoring_type` (string): "performance", "security", "health"
- `interval` (number): Monitoring interval in seconds
**Returns**:
```json
{
  "monitoring_id": "mon_12345",
  "status": "started",
  "monitoring_type": "performance",
  "interval": 60
}
```

#### 14. `get_network_trends`
**Purpose**: Get network performance and health trends
**Parameters**:
- `time_range` (string): "1h", "24h", "7d", "30d"
**Returns**:
```json
{
  "time_range": "24h",
  "trends": {...},
  "anomalies": [...],
  "predictions": [...]
}
```

### **Advanced Analytics Tools**

#### 15. `analyze_network_correlation`
**Purpose**: Analyze correlations between network events
**Parameters**:
- `event_types` (array): Types of events to correlate
- `time_window` (string): Time window for analysis
**Returns**:
```json
{
  "correlations": [...],
  "confidence_scores": {...},
  "causal_relationships": [...]
}
```

#### 16. `detect_network_patterns`
**Purpose**: Detect patterns in network behavior
**Parameters**:
- `pattern_type` (string): "traffic", "failures", "performance"
**Returns**:
```json
{
  "patterns": [...],
  "pattern_confidence": {...},
  "recommendations": [...]
}
```

#### 17. `get_performance_optimizations`
**Purpose**: Get AI-generated performance optimization recommendations
**Parameters**: None
**Returns**:
```json
{
  "optimizations": [...],
  "impact_analysis": {...},
  "implementation_complexity": "low|medium|high"
}
```

#### 18. `get_proactive_recommendations`
**Purpose**: Get proactive recommendations for network improvements
**Parameters**:
- `focus_area` (string, optional): "performance", "security", "reliability"
**Returns**:
```json
{
  "recommendations": [...],
  "priority_scores": {...},
  "implementation_timeline": [...]
}
```

## 🔐 **Authentication & Security**

### **API Key Authentication**
```python
# Generate API key
api_key = server.generate_client_api_key("client-name", ["read_status", "execute_command"])

# Use API key in requests
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}
```

### **Role-Based Access Control**
Available roles:
- `read_status`: Read-only access to network status
- `execute_command`: Execute configuration commands
- `admin`: Full administrative access
- `monitor`: Access to monitoring and analytics tools

## 📝 **Usage Examples**

### **Complete Network Health Check**
```python
# 1. Get overall network status
status = mcp_client.call_tool("get_network_status", {})

# 2. Get detailed topology
topology = mcp_client.call_tool("get_network_topology", {})

# 3. Check specific device if issues found
if status["failed_devices"] > 0:
    device_details = mcp_client.call_tool("get_device_details", {
        "device_name": "SPINE1"
    })
```

### **AI-Powered Troubleshooting**
```python
# 1. Analyze network issue
analysis = mcp_client.call_tool("analyze_network_issue", {
    "issue_description": "High latency between SPINE1 and LEAF2",
    "affected_devices": ["SPINE1", "LEAF2"]
})

# 2. Get performance optimization recommendations
optimizations = mcp_client.call_tool("get_performance_optimizations", {})

# 3. Generate configuration fix
config = mcp_client.call_tool("generate_configuration", {
    "device_name": "SPINE1",
    "config_type": "bgp",
    "requirements": "Optimize BGP routing for reduced latency"
})
```

### **Configuration Deployment Workflow**
```python
# 1. Generate configuration
config = mcp_client.call_tool("generate_configuration", {
    "device_name": "LEAF1",
    "config_type": "interfaces",
    "requirements": "Configure VLAN 100 on interface Eth1/1"
})

# 2. Deploy configuration
deployment = mcp_client.call_tool("deploy_configuration", {
    "device_name": "LEAF1",
    "configuration": config["generated_config"],
    "deployment_mode": "scheduled"
})

# 3. Approve deployment
approval = mcp_client.call_tool("approve_deployment", {
    "deployment_id": deployment["deployment_id"],
    "approver": "admin"
})

# 4. Monitor deployment status
status = mcp_client.call_tool("get_deployment_status", {
    "deployment_id": deployment["deployment_id"]
})
```

## ⚠️ **Error Handling**

All tools return consistent error responses:
```json
{
  "success": false,
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {...}
}
```

Common error codes:
- `AUTHENTICATION_FAILED`: Invalid API key
- `INSUFFICIENT_PERMISSIONS`: Role lacks required permissions
- `DEVICE_NOT_FOUND`: Specified device doesn't exist
- `CONFIGURATION_INVALID`: Invalid configuration syntax
- `DEPLOYMENT_FAILED`: Configuration deployment failed

## 📊 **Rate Limiting**

- **Read operations**: 100 requests/minute
- **Write operations**: 20 requests/minute  
- **Admin operations**: 10 requests/minute

## 🔍 **Monitoring & Logging**

All API calls are logged with:
- Timestamp
- Client identification
- Tool called
- Parameters (sanitized)
- Response status
- Execution time

Logs are available in `/opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/audit.log`
