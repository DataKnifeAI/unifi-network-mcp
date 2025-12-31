# Deployment Guide

## Prerequisites

- Go 1.23.2+ or Docker
- Unifi API key (X-API-KEY header authentication)
- Unifi base URL with Integration API v1 support
- Network access to Unifi consoles

## Local Deployment

### Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/yourusername/unifi-mcp.git
cd unifi-mcp

# 2. Configure
cp .env.example .env
# Edit .env with your API key and base URL

# 3. Build
make build

# 4. Run
make run
```

## Docker Deployment

### Using Docker Run

```bash
docker build -t unifi-mcp:latest .

docker run -d \
  --name unifi-mcp \
  -e UNIFI_API_KEY="your-api-key-here" \
  -e UNIFI_BASE_URL="https://your-unifi-controller:443" \
  -e LOG_LEVEL="info" \
  unifi-mcp:latest
```

### Using Docker Compose

```bash
# 1. Copy env file
cp .env.example .env

# 2. Edit .env
nano .env

# 3. Start services
docker-compose up -d

# 4. View logs
docker-compose logs -f unifi-mcp

# 5. Stop
docker-compose down
```

## Kubernetes Deployment

### Create ConfigMap and Secret

```bash
kubectl create configmap unifi-mcp-config \
  --from-literal=LOG_LEVEL=info

kubectl create secret generic unifi-mcp-secret \
  --from-literal=UNIFI_API_KEY=your-api-key-here
```

### Deploy

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unifi-mcp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: unifi-mcp
  template:
    metadata:
      labels:
        app: unifi-mcp
    spec:
      containers:
      - name: unifi-mcp
        image: unifi-mcp:latest
        env:
        - name: UNIFI_BASE_URL
          value: "https://your-unifi-controller:443"
        - name: UNIFI_API_KEY
          valueFrom:
            secretKeyRef:
              name: unifi-mcp-secret
              key: UNIFI_API_KEY
        - name: LOG_LEVEL
          valueFrom:
            configMapKeyRef:
              name: unifi-mcp-config
              key: LOG_LEVEL
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
```

## Systemd Service

Create `/etc/systemd/system/unifi-mcp.service`:

```ini
[Unit]
Description=Unifi MCP Server
After=network.target

[Service]
Type=simple
User=unifi
WorkingDirectory=/opt/unifi-mcp
ExecStart=/opt/unifi-mcp/bin/unifi-mcp
Restart=always
RestartSec=10
Environment="UNIFI_API_KEY=your-api-key-here"
Environment="UNIFI_BASE_URL=https://your-unifi-controller:443"
Environment="LOG_LEVEL=info"

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable unifi-mcp
sudo systemctl start unifi-mcp
sudo systemctl status unifi-mcp
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| UNIFI_API_KEY | Yes | Unifi Integration API v1 key (X-API-KEY header) |
| UNIFI_BASE_URL | Yes | Unifi controller base URL (e.g., https://controller:443) |
| LOG_LEVEL | No | Logging level (debug, info, warn, error) |

## Health Checks

### Docker Compose

Add to service definition:

```yaml
healthcheck:
  test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8000/health"]
  interval: 30s
  timeout: 10s
  retries: 3
```

### Kubernetes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10
```

## Monitoring

### Log Files

```bash
# Docker Compose
docker-compose logs -f unifi-mcp

# Systemd
journalctl -u unifi-mcp -f
```

### Metrics

The server outputs structured logs with:
- Request duration
- Error rates
- API response times
- Connection stats

## Troubleshooting

### Connection Issues

```bash
# Test API connectivity
curl -k -H "X-API-KEY: your-api-key" https://your-controller/api/v1/cameras

# Verify API key
curl -k -H "X-API-KEY: your-api-key" https://your-controller/api/v1/cameras?limit=1
```

### Authentication Failures

- Verify API key in .env (must be exact match)
- Confirm API key is active in Unifi console settings
- Check that controller URL is correct (with protocol and port)
- Ensure API key has necessary permissions
- Test API key directly: `curl -k -H "X-API-KEY: key" https://controller/api/v1/status`

### Performance

- Monitor CPU and memory usage
- Check network latency to Unifi consoles
- Verify API rate limits aren't being hit
- Consider caching for frequently accessed data

## Backup & Recovery

### Configuration

```bash
# Backup .env
cp .env .env.backup

# Backup state (if applicable)
docker-compose stop
tar -czf backup.tar.gz .env docker-compose.yml
docker-compose start
```

### Restore

```bash
tar -xzf backup.tar.gz
docker-compose up -d
```

## Updates

### Binary Update

```bash
# Stop service
systemctl stop unifi-mcp

# Update binary
make build
cp bin/unifi-mcp /usr/local/bin/

# Start service
systemctl start unifi-mcp
```

### Docker Update

```bash
# Pull latest
docker pull unifi-mcp:latest

# Stop and remove old container
docker-compose down

# Start new version
docker-compose up -d
```

## Scaling

The server is stateless and can be scaled horizontally:

```yaml
replicas: 3  # Run multiple instances
```

Load balance requests across instances using a reverse proxy.

## Security Best Practices

1. **Use HTTPS** - Always use HTTPS URLs for Unifi consoles
2. **Secure Credentials** - Use environment variables or secrets management
3. **Network Isolation** - Run in isolated network if possible
4. **Firewall Rules** - Restrict access to server
5. **Regular Updates** - Keep Go and dependencies updated
6. **Monitoring** - Log and monitor all access
7. **Audit** - Review logs regularly for suspicious activity

## Available Tools (28 total)

**Protect API** (7 tools):
- GetDevices, GetEvents, GetSystemInfo, GetCameras, GetSensors, GetLights, GetChimes

**Network API** (21 tools):
- Sites, Clients, Devices, Networks, WiFi, Health, Firewall, ACL, Hotspot, GetClientDetailed, GetDeviceDetailed, GetVPNServers, and more

See docs/API_REFERENCE.md for complete tool documentation.

## Support

For issues and questions:
- Check logs with DEBUG logging
- Review README.md for configuration and development setup
- Review docs/API_REFERENCE.md for tool documentation
- Open GitHub issue with logs and configuration (sanitized)
