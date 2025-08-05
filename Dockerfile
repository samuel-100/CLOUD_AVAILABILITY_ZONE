# Network Automation MCP Server - Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    sshpass \
    telnet \
    ping \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt requirements-minimal.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/logs /app/configs /app/data

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 netauto && \
    chown -R netauto:netauto /app

# Switch to non-root user
USER netauto

# Expose ports
EXPOSE 8000 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Environment variables
ENV PYTHONPATH=/app
ENV ENVIRONMENT=production
ENV LOG_LEVEL=INFO

# Default command
CMD ["python3", "start_network_automation.py"]
