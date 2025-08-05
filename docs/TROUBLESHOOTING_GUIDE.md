# 🔧 Network Automation Platform - Troubleshooting Guide

## 🎯 **Quick Diagnostics**

### **System Health Check**

Run this quick diagnostic script to identify common issues:

```bash
#!/bin/bash
# quick_diagnostics.sh

echo "🔍 Network Automation Platform - Quick Diagnostics"
echo "=================================================="

# 1. Check if MCP server is running
if pgrep -f "enhanced_mcp_server.py" > /dev/null; then
    echo "✅ MCP Server is running"
else
    echo "❌ MCP Server is not running"
fi

# 2. Check database connectivity
if pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
    echo "✅ Database is accessible"
else
    echo "❌ Database connection failed"
fi

# 3. Check Redis connectivity
if redis-cli ping > /dev/null 2>&1; then
    echo "✅ Redis is accessible"
else
    echo "❌ Redis connection failed"
fi

# 4. Check disk space
DISK_USAGE=$(df /opt/network-automation | awk 'NR==2{print $5}' | sed 's/%//')
if [ $DISK_USAGE -lt 80 ]; then
    echo "✅ Disk usage: ${DISK_USAGE}%"
else
    echo "⚠️  Disk usage high: ${DISK_USAGE}%"
fi

# 5. Check log files for errors
ERROR_COUNT=$(tail -100 /opt/network-automation/CLOUD_AVAILABILITY_ZONE/logs/automation.log | grep -c "ERROR")
if [ $ERROR_COUNT -eq 0 ]; then
    echo "✅ No recent errors in logs"
else
    echo "⚠️  Found $ERROR_COUNT recent errors in logs"
fi

echo "=================================================="
echo "Run this script regularly to monitor system health"
```

## 🚨 **Common Issues & Solutions**

### **1. MCP Server Not Starting**

#### **Symptoms**
- Claude can't connect to network tools
- "Tool not available" errors
- Empty tool list in Claude interface

#### **Diagnosis**
```bash
# Check if server is running
ps aux | grep enhanced_mcp_server

# Check server logs
tail -f logs/automation.log

# Test server startup manually
cd /opt/network-automation/CLOUD_AVAILABILITY_ZONE
python3 mcp/enhanced_mcp_server.py
```

#### **Common Causes & Solutions**

**🔧 Missing Dependencies**
```bash
# Install missing packages
pip install -r requirements.txt

# Check for specific import errors
python3 -c "
try:
    import yaml, asyncio, jwt
    print('✅ Core dependencies available')
except ImportError as e:
    print(f'❌ Missing dependency: {e}')
"
```

**🔧 Configuration File Issues**
```bash
# Verify configuration files exist
ls -la config/
cat config/auth_config.yaml

# Check YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config/auth_config.yaml'))"
```

**🔧 Port Already in Use**
```bash
# Check what's using port 8080
sudo netstat -tlnp | grep :8080
sudo lsof -i :8080

# Kill conflicting process
sudo kill -9 <PID>
```

**🔧 Permission Issues**
```bash
# Fix file permissions
sudo chown -R $USER:$USER /opt/network-automation/CLOUD_AVAILABILITY_ZONE
chmod +x mcp/enhanced_mcp_server.py
```

### **2. Device Connectivity Issues**

#### **Symptoms**
- "Device unreachable" errors
- Timeout errors when accessing devices
- Authentication failures

#### **Diagnosis**
```bash
# Test basic connectivity
ping <device_ip>
telnet <device_ip> 22
nc -zv <device_ip> 22

# Check device credentials
ssh admin@<device_ip>
```

#### **Solutions**

**🔧 Network Connectivity**
```bash
# Check routing to device
traceroute <device_ip>

# Verify firewall rules
sudo iptables -L | grep <device_ip>

# Test from management network
ip route get <device_ip>
```

**🔧 Authentication Issues**
```bash
# Verify credentials in devices.yaml
cat devices.yaml

# Test SSH key authentication
ssh-copy-id admin@<device_ip>

# Check device access logs
ssh admin@<device_ip> "show logging | include LOGIN"
```

**🔧 Device Configuration Issues**
```cisco
! Enable SSH on Cisco devices
ip domain-name company.com
crypto key generate rsa modulus 2048
ip ssh version 2
line vty 0 15
 transport input ssh
 login local
!
username admin privilege 15 secret password123
```

### **3. Configuration Deployment Failures**

#### **Symptoms**
- Deployments stuck in "pending" status
- Configuration syntax errors
- Rollback failures

#### **Diagnosis**
```bash
# Check deployment logs
tail -f logs/config_collection.log

# List pending deployments
grep "pending" logs/audit.log

# Check device configuration status
python3 -c "
from services.config_deployment_tool import get_deployment_status
status = get_deployment_status('dep_12345')
print(status)
"
```

#### **Solutions**

**🔧 Syntax Errors**
```bash
# Validate configuration before deployment
python3 -c "
from services.config_generation_tool import generate_configuration
config = generate_configuration('SPINE1', 'bgp', 'Configure BGP AS 65001')
print('Generated config:')
print(config)
"

# Test configuration on device
ssh admin@device_ip "configure terminal
show running-config | include bgp"
```

**🔧 Approval Workflow Issues**
```bash
# Check pending approvals
python3 -c "
from services.config_deployment_tool import get_pending_approvals
approvals = get_pending_approvals()
print(f'Pending approvals: {len(approvals)}')
for approval in approvals:
    print(f'- {approval}')
"

# Force approve deployment (emergency)
python3 -c "
from services.config_deployment_tool import approve_deployment
result = approve_deployment('dep_12345', 'emergency_admin')
print(result)
"
```

### **4. Performance Issues**

#### **Symptoms**
- Slow response times from Claude
- High CPU/memory usage
- Database connection timeouts

#### **Diagnosis**
```bash
# Check system resources
top
htop
free -h
df -h

# Monitor database performance
sudo -u postgres psql network_automation -c "
SELECT query, state, query_start 
FROM pg_stat_activity 
WHERE state != 'idle' 
ORDER BY query_start;
"

# Check Redis performance
redis-cli info stats
redis-cli slowlog get 10
```

#### **Solutions**

**🔧 Database Optimization**
```sql
-- Analyze slow queries
EXPLAIN ANALYZE SELECT * FROM devices WHERE status = 'active';

-- Update statistics
ANALYZE;

-- Rebuild indexes
REINDEX DATABASE network_automation;
```

**🔧 Memory Issues**
```bash
# Clear Redis cache
redis-cli FLUSHALL

# Restart services to clear memory leaks
sudo systemctl restart network-automation

# Increase memory limits
echo "vm.swappiness = 10" >> /etc/sysctl.conf
sysctl -p
```

**🔧 CPU Performance**
```bash
# Identify CPU-intensive processes
ps aux --sort=-%cpu | head -10

# Check for I/O wait
iostat -x 1 10

# Optimize Python performance
export PYTHONOPTIMIZE=1
export PYTHONDONTWRITEBYTECODE=1
```

### **5. Authentication & Authorization Issues**

#### **Symptoms**
- "Authentication failed" errors
- "Insufficient permissions" messages
- API key validation failures

#### **Diagnosis**
```bash
# Check API key configuration
cat config/api_keys.yaml

# Verify user permissions
python3 -c "
from mcp.enhanced_mcp_server import EnhancedMCPServer
server = EnhancedMCPServer()
print(server.validate_api_key('your_api_key_here'))
"

# Check audit logs for auth failures
grep "AUTHENTICATION_FAILED" logs/audit.log
```

#### **Solutions**

**🔧 API Key Issues**
```bash
# Generate new API key
python3 -c "
from mcp.enhanced_mcp_server import EnhancedMCPServer
server = EnhancedMCPServer()
key = server.generate_client_api_key('new_client', ['read_status', 'execute_command'])
print(f'New API key: {key}')
"

# Rotate expired keys
python3 scripts/rotate_api_keys.py
```

**🔧 RBAC Configuration**
```yaml
# Fix auth_config.yaml
roles:
  network_admin:
    permissions:
      - read_status
      - execute_command
      - deploy_config
      - admin_functions
  network_operator:
    permissions:
      - read_status
      - execute_command
  network_viewer:
    permissions:
      - read_status

users:
  admin:
    roles: [network_admin]
    api_key: admin_key_here
```

### **6. Monitoring & Alerting Issues**

#### **Symptoms**
- Missing metrics in Grafana
- Prometheus not scraping data
- Alerts not firing

#### **Diagnosis**
```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Verify metrics endpoint
curl http://localhost:8080/metrics

# Check Grafana data sources
curl -u admin:password http://localhost:3000/api/datasources
```

#### **Solutions**

**🔧 Prometheus Configuration**
```yaml
# Fix prometheus.yml
scrape_configs:
  - job_name: 'network-automation'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 30s
    metrics_path: /metrics
    scrape_timeout: 10s
```

**🔧 Grafana Dashboard Issues**
```bash
# Import dashboard
curl -X POST \
  http://localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -u admin:password \
  -d @monitoring/grafana-dashboard.json
```

## 🔍 **Advanced Troubleshooting**

### **Debug Mode**

Enable detailed logging for troubleshooting:

```bash
# Start server in debug mode
export LOG_LEVEL=DEBUG
export PYTHONPATH=/opt/network-automation/CLOUD_AVAILABILITY_ZONE
python3 mcp/enhanced_mcp_server.py

# Enable SQL query logging
export DB_ECHO=true

# Enable network trace logging
export NETWORK_DEBUG=true
```

### **Log Analysis**

#### **Key Log Files**
- `logs/automation.log` - Main application logs
- `logs/audit.log` - All API calls and user actions
- `logs/config_collection.log` - Configuration deployment logs
- `logs/monitoring.log` - System monitoring events

#### **Log Analysis Commands**
```bash
# Find all errors in last hour
find logs/ -name "*.log" -exec grep -l "ERROR" {} \; | xargs grep "ERROR" | grep "$(date '+%Y-%m-%d %H')"

# Monitor logs in real-time
tail -f logs/*.log | grep -E "(ERROR|CRITICAL|FATAL)"

# Analyze API call patterns
awk '{print $1, $4}' logs/audit.log | sort | uniq -c | sort -nr

# Find slow operations
grep "took.*[0-9]\{4,\}ms" logs/automation.log
```

### **Network Debugging**

#### **Packet Capture**
```bash
# Capture traffic to specific device
sudo tcpdump -i eth0 host 192.168.1.10 -w device_traffic.pcap

# Monitor SSH connections
sudo tcpdump -i eth0 port 22

# Analyze SNMP traffic
sudo tcpdump -i eth0 port 161
```

#### **Device-Side Debugging**
```cisco
! Enable debug on Cisco devices
debug ip ssh
debug radius authentication
terminal monitor

! Check interface statistics
show interface ethernet 1/1
show interface counters errors

! Monitor configuration changes
show archive config differences
```

### **Database Troubleshooting**

#### **Connection Issues**
```bash
# Check database connections
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity;"

# Kill hanging connections
sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle in transaction';"

# Check database locks
sudo -u postgres psql -c "SELECT * FROM pg_locks WHERE NOT granted;"
```

#### **Performance Issues**
```sql
-- Find slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Check table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) 
FROM pg_tables 
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Optimize queries
VACUUM ANALYZE;
```

## 📊 **Performance Tuning**

### **System Optimization**

```bash
# Increase file descriptor limits
echo "* soft nofile 65535" >> /etc/security/limits.conf
echo "* hard nofile 65535" >> /etc/security/limits.conf

# Optimize kernel parameters
echo "net.core.somaxconn = 1024" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 5000" >> /etc/sysctl.conf
sysctl -p

# Configure swap
echo "vm.swappiness = 10" >> /etc/sysctl.conf
echo "vm.dirty_ratio = 15" >> /etc/sysctl.conf
```

### **Application Tuning**

```python
# config/performance.yaml
database:
  pool_size: 20
  max_overflow: 30
  pool_timeout: 30
  pool_recycle: 3600

redis:
  max_connections: 100
  socket_timeout: 5
  socket_connect_timeout: 5

api:
  worker_processes: 4
  worker_connections: 1000
  keepalive_timeout: 75
```

## 🆘 **Emergency Procedures**

### **Complete System Recovery**

```bash
#!/bin/bash
# emergency_recovery.sh

echo "🚨 Emergency Recovery Procedure"
echo "==============================="

# 1. Stop all services
sudo systemctl stop network-automation
sudo systemctl stop postgresql
sudo systemctl stop redis-server

# 2. Check system resources
df -h
free -h

# 3. Clear temporary files
rm -rf /tmp/network-automation-*
find /var/log -name "*.log" -size +100M -delete

# 4. Start core services
sudo systemctl start postgresql
sudo systemctl start redis-server

# 5. Restore from backup if needed
if [ "$1" == "restore" ]; then
    echo "Restoring from latest backup..."
    /opt/network-automation/scripts/restore_backup.sh
fi

# 6. Start application
sudo systemctl start network-automation

# 7. Verify functionality
sleep 30
curl -f http://localhost:8080/health || echo "❌ Health check failed"

echo "Recovery procedure completed"
```

### **Rollback Procedure**

```bash
# Quick rollback to previous version
git log --oneline -10
git checkout <previous_commit>
sudo systemctl restart network-automation

# Database rollback (if needed)
pg_restore -d network_automation /backup/pre_upgrade_backup.sql
```

## 📞 **Getting Help**

### **Information to Collect**

Before seeking support, collect:

1. **System Information**
   ```bash
   uname -a
   cat /etc/os-release
   python3 --version
   ```

2. **Error Logs**
   ```bash
   tail -100 logs/automation.log
   tail -100 logs/audit.log
   journalctl -u network-automation --since "1 hour ago"
   ```

3. **Configuration Files**
   ```bash
   # Sanitize sensitive data first!
   cat config/auth_config.yaml | sed 's/password:.*/password: [REDACTED]/'
   ```

4. **System Status**
   ```bash
   systemctl status network-automation
   ps aux | grep -E "(python|postgres|redis)"
   netstat -tlnp | grep -E "(8080|5432|6379)"
   ```

### **Support Channels**

- **Documentation**: Check `/docs/` directory first
- **GitHub Issues**: Submit detailed bug reports
- **Emergency Contact**: Use for production outages only

---

**Troubleshooting Guide Version**: 1.0  
**Last Updated**: August 5, 2025  
**Compatible Versions**: All v1.x releases
