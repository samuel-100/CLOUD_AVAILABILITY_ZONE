# 🚀 Network Automation Platform - Deployment Guide

## 📋 **Deployment Overview**

This guide covers production deployment of the Network Automation MCP platform across different environments and infrastructure setups.

## 🎯 **Deployment Options**

### **1. Docker Containerized Deployment (Recommended)**
- ✅ Isolated environment
- ✅ Easy scaling and updates
- ✅ Consistent across environments
- ✅ Built-in health checks

### **2. Kubernetes Deployment**
- ✅ High availability
- ✅ Auto-scaling
- ✅ Load balancing
- ✅ Rolling updates

### **3. Traditional Server Deployment**
- ✅ Direct hardware control
- ✅ Custom configurations
- ✅ Legacy system integration

## 🐳 **Docker Deployment**

### **Prerequisites**
- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 20GB disk space

### **Quick Start**

```bash
# 1. Clone repository
git clone <repository-url>
cd network-automation/CLOUD_AVAILABILITY_ZONE

# 2. Configure environment
cp .env.example .env
edit .env  # Set your environment variables

# 3. Deploy with Docker Compose
docker-compose up -d

# 4. Verify deployment
docker-compose ps
curl http://localhost:8080/health
```

### **Docker Compose Configuration**

```yaml
# docker-compose.yml
version: '3.8'

services:
  network-automation:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: network-automation-mcp
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - ENVIRONMENT=production
      - LOG_LEVEL=INFO
      - DB_HOST=postgres
      - REDIS_HOST=redis
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
      - network-configs:/app/backup
    depends_on:
      - postgres
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15
    container_name: network-automation-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: network_automation
      POSTGRES_USER: netauto
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    container_name: network-automation-cache
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"

  prometheus:
    image: prom/prometheus:latest
    container_name: network-automation-metrics
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus

  grafana:
    image: grafana/grafana:latest
    container_name: network-automation-dashboard
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana:/etc/grafana/provisioning

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:
  network-configs:

networks:
  default:
    name: network-automation
```

### **Environment Configuration (.env)**

```bash
# Production Environment Configuration
ENVIRONMENT=production
LOG_LEVEL=INFO

# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_NAME=network_automation
DB_USER=netauto
DB_PASSWORD=secure_db_password_here

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=secure_redis_password_here

# API Configuration
API_HOST=0.0.0.0
API_PORT=8080
SECRET_KEY=your_secret_key_here

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_PASSWORD=secure_grafana_password_here

# Network Device Credentials
DEVICE_USERNAME=admin
DEVICE_PASSWORD=secure_device_password_here

# External Integrations
SMTP_HOST=smtp.company.com
SMTP_PORT=587
SMTP_USERNAME=alerts@company.com
SMTP_PASSWORD=smtp_password_here
```

## ☸️ **Kubernetes Deployment**

### **Prerequisites**
- Kubernetes 1.20+
- kubectl configured
- Helm 3.0+ (optional)
- Persistent storage class

### **Namespace Setup**

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: network-automation
  labels:
    name: network-automation
```

### **ConfigMap for Application Configuration**

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: network-automation-config
  namespace: network-automation
data:
  config.yaml: |
    environment: production
    logging:
      level: INFO
      format: json
    database:
      host: postgres-service
      port: "5432"
      name: network_automation
    redis:
      host: redis-service
      port: "6379"
    monitoring:
      prometheus: true
      grafana: true
```

### **Secrets Management**

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: network-automation-secrets
  namespace: network-automation
type: Opaque
data:
  db-password: <base64-encoded-password>
  redis-password: <base64-encoded-password>
  api-secret-key: <base64-encoded-key>
  device-password: <base64-encoded-password>
```

### **Main Application Deployment**

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: network-automation
  namespace: network-automation
spec:
  replicas: 3
  selector:
    matchLabels:
      app: network-automation
  template:
    metadata:
      labels:
        app: network-automation
    spec:
      containers:
      - name: network-automation
        image: network-automation:latest
        ports:
        - containerPort: 8080
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: network-automation-secrets
              key: db-password
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: network-automation-secrets
              key: redis-password
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: logs
          mountPath: /app/logs
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
      volumes:
      - name: config
        configMap:
          name: network-automation-config
      - name: logs
        persistentVolumeClaim:
          claimName: logs-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: network-automation-service
  namespace: network-automation
spec:
  selector:
    app: network-automation
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

### **Persistent Storage**

```yaml
# storage.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: logs-pvc
  namespace: network-automation
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: fast-ssd
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: network-automation
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
  storageClassName: fast-ssd
```

### **Deploy to Kubernetes**

```bash
# 1. Create namespace and secrets
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml

# 2. Deploy storage
kubectl apply -f storage.yaml

# 3. Deploy application components
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml

# 4. Deploy supporting services (PostgreSQL, Redis)
kubectl apply -f postgres-deployment.yaml
kubectl apply -f redis-deployment.yaml

# 5. Verify deployment
kubectl get pods -n network-automation
kubectl get services -n network-automation

# 6. Check application logs
kubectl logs -f deployment/network-automation -n network-automation
```

## 🖥️ **Traditional Server Deployment**

### **System Requirements**

#### **Minimum Requirements**
- **OS**: Ubuntu 20.04 LTS / RHEL 8 / CentOS 8
- **CPU**: 4 cores
- **Memory**: 8GB RAM
- **Storage**: 100GB SSD
- **Network**: 1Gbps connection to management network

#### **Recommended Production**
- **OS**: Ubuntu 22.04 LTS
- **CPU**: 8 cores
- **Memory**: 16GB RAM
- **Storage**: 500GB NVMe SSD
- **Network**: 10Gbps connection with redundancy

### **Installation Steps**

```bash
# 1. System Updates
sudo apt update && sudo apt upgrade -y

# 2. Install Python and dependencies
sudo apt install python3.9 python3.9-venv python3.9-dev -y
sudo apt install postgresql-12 redis-server nginx -y

# 3. Create application user
sudo useradd -m -s /bin/bash netauto
sudo usermod -aG sudo netauto

# 4. Setup application directory
sudo mkdir -p /opt/network-automation
sudo chown netauto:netauto /opt/network-automation

# 5. Switch to application user
sudo su - netauto

# 6. Deploy application
cd /opt/network-automation
git clone <repository-url> .
python3.9 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 7. Configure database
sudo -u postgres createdb network_automation
sudo -u postgres createuser netauto
sudo -u postgres psql -c "ALTER USER netauto PASSWORD 'secure_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE network_automation TO netauto;"

# 8. Configure application
cp config/production.yaml.example config/production.yaml
# Edit configuration files as needed

# 9. Setup systemd service
sudo cp deployment/systemd/network-automation.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable network-automation
sudo systemctl start network-automation

# 10. Configure Nginx reverse proxy
sudo cp deployment/nginx/network-automation.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/network-automation.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### **Systemd Service Configuration**

```ini
# /etc/systemd/system/network-automation.service
[Unit]
Description=Network Automation MCP Server
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User=netauto
Group=netauto
WorkingDirectory=/opt/network-automation
Environment=ENVIRONMENT=production
Environment=PYTHONPATH=/opt/network-automation
ExecStart=/opt/network-automation/venv/bin/python /opt/network-automation/mcp/enhanced_mcp_server.py
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=network-automation

[Install]
WantedBy=multi-user.target
```

### **Nginx Configuration**

```nginx
# /etc/nginx/sites-available/network-automation.conf
upstream network_automation {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name network-automation.company.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name network-automation.company.com;

    ssl_certificate /etc/ssl/certs/network-automation.crt;
    ssl_certificate_key /etc/ssl/private/network-automation.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    location / {
        proxy_pass http://network_automation;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    location /health {
        proxy_pass http://network_automation/health;
        access_log off;
    }
}
```

## 📊 **Monitoring & Observability**

### **Prometheus Configuration**

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'network-automation'
    static_configs:
      - targets: ['network-automation:8080']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### **Grafana Dashboards**

Key metrics to monitor:
- API request latency and throughput
- Device connectivity status
- Configuration deployment success rate
- Error rates by tool/function
- System resource utilization
- Database performance metrics

### **Health Check Endpoints**

- `GET /health` - Basic health check
- `GET /ready` - Readiness probe
- `GET /metrics` - Prometheus metrics
- `GET /status` - Detailed system status

## 🔒 **Security Considerations**

### **Network Security**
- Deploy behind firewall/VPN
- Use HTTPS/TLS for all connections
- Implement network segmentation
- Monitor access logs

### **Application Security**
- Regular security updates
- Strong authentication mechanisms
- Role-based access control
- Audit logging for all actions

### **Data Protection**
- Encrypt sensitive data at rest
- Secure credential storage
- Regular backup procedures
- Data retention policies

## 🔄 **Backup & Recovery**

### **Backup Strategy**

```bash
#!/bin/bash
# backup.sh - Automated backup script

BACKUP_DIR="/backup/network-automation"
DATE=$(date +%Y%m%d_%H%M%S)

# 1. Database backup
pg_dump network_automation > "$BACKUP_DIR/db_backup_$DATE.sql"

# 2. Configuration backup
tar -czf "$BACKUP_DIR/config_backup_$DATE.tar.gz" /opt/network-automation/config

# 3. Application logs
tar -czf "$BACKUP_DIR/logs_backup_$DATE.tar.gz" /opt/network-automation/logs

# 4. Device configurations
tar -czf "$BACKUP_DIR/device_configs_$DATE.tar.gz" /opt/network-automation/configs

# 5. Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.sql" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

### **Recovery Procedures**

```bash
# 1. Stop services
sudo systemctl stop network-automation

# 2. Restore database
psql network_automation < /backup/db_backup_20250805_120000.sql

# 3. Restore configurations
tar -xzf /backup/config_backup_20250805_120000.tar.gz -C /

# 4. Restart services
sudo systemctl start network-automation
```

## 🚀 **Scaling & Performance**

### **Horizontal Scaling**
- Load balancer configuration
- Database read replicas
- Distributed caching with Redis Cluster
- Microservices architecture

### **Performance Tuning**
- Database connection pooling
- Async request processing
- Caching strategies
- Resource optimization

## 📋 **Maintenance**

### **Regular Tasks**
- System updates (monthly)
- Security patches (immediate)
- Log rotation and cleanup
- Performance monitoring
- Backup verification

### **Upgrade Procedures**
1. Backup current system
2. Test upgrade in staging
3. Schedule maintenance window
4. Deploy new version
5. Verify functionality
6. Monitor for issues

---

**Deployment Version**: 1.0  
**Last Updated**: August 5, 2025  
**Supported Platforms**: Docker, Kubernetes, Ubuntu, RHEL
