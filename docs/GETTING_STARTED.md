# UniFi MCP Server - Getting Started

Complete guide to set up and start using UniFi MCP Server.

## Quick Start (5 Minutes)

### Prerequisites
- Go 1.21+ installed
- UniFi Controller 8.0+ running
- API Key (generated below)

### 1. Get API Key (1 minute)
1. Log in to UniFi Web UI (`https://your-controller:8443`)
2. System Settings → Integrations
3. Click "Create API Key"
4. Copy and save the key

### 2. Configure (1 minute)
```bash
cd unifi-mcp
cat > .env << EOF
UNIFI_API_KEY=your-api-key-here
UNIFI_BASE_URL=https://192.168.1.1
LOG_LEVEL=info
EOF
```

### 3. Run (1 minute)
```bash
go run cmd/main.go
```

Expected output:
```
INFO[...] Initializing Unifi MCP Server
INFO[...] Registered 26 MCP tools
INFO[...] Starting Unifi MCP Server on stdio transport
```

### 4. Verify (2 minutes)
```bash
# Test API key in another terminal
curl -H "X-API-KEY: your-api-key" \
  https://192.168.1.1/proxy/network/api/self/sites
```

## Complete Setup Guide

### System Requirements
- **Go 1.21+** - For building
- **UniFi Controller 8.0+** - Newer versions recommended
- **Network Access** - Controller must be accessible

### Installation Options

#### Option 1: Build from Source
```bash
cd unifi-mcp
go mod download
go build -o bin/unifi-mcp cmd/main.go
./bin/unifi-mcp
```

#### Option 2: Run Directly
```bash
cd unifi-mcp
go run cmd/main.go
```

#### Option 3: Docker
```bash
docker build -t unifi-mcp .
docker run -e UNIFI_API_KEY=your-key \
           -e UNIFI_BASE_URL=https://192.168.1.1 \
           unifi-mcp
```

### Configuration

#### Via Environment Variables (Recommended)
```env
# Required
UNIFI_API_KEY=your-api-key-here
UNIFI_BASE_URL=https://192.168.1.1

# Optional
LOG_LEVEL=info              # debug, info, warn, error
UNIFI_SKIP_SSL_VERIFY=false # true for self-signed certs
```

#### Configuration Options
| Variable | Description | Default |
|----------|-------------|---------|
| UNIFI_API_KEY | UniFi API Key | (required) |
| UNIFI_BASE_URL | Controller URL | https://192.168.1.1 |
| LOG_LEVEL | Logging level | info |
| UNIFI_SKIP_SSL_VERIFY | Skip SSL cert verification | false |

### Running the Server

**Basic Start:**
```bash
go run cmd/main.go
```

**With Debug Logging:**
```bash
LOG_LEVEL=debug go run cmd/main.go
```

**Check Logs:**
```bash
# Save logs to file
go run cmd/main.go > server.log 2>&1 &
tail -f server.log
```

### Verification

#### Test API Connectivity
```bash
curl -sk -H "X-API-KEY: your-api-key" \
  https://192.168.1.1/proxy/network/api/self/sites
```

#### Check Server Health
Via MCP client:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list"
}
```

#### Test a Tool
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_network_sites",
    "arguments": {}
  }
}
```

## Integration with Claude

### Claude Desktop (Recommended)

1. **Start the MCP Server**
   ```bash
   go run cmd/main.go
   ```

2. **Configure Claude**
   - Open Claude Desktop
   - Settings → MCP Servers
   - Add new server with settings:
     ```json
     {
       "name": "unifi-mcp",
       "command": "go",
       "args": ["run", "/path/to/unifi-mcp/cmd/main.go"],
       "env": {
         "UNIFI_API_KEY": "your-key",
         "UNIFI_BASE_URL": "https://192.168.1.1"
       }
     }
     ```

3. **Restart Claude** to load the server

4. **Verify in Claude**
   - Start new conversation
   - Click "+" to see available tools
   - Look for UniFi tools in the list

### Docker Compose

```yaml
version: '3.8'
services:
  unifi-mcp:
    build: .
    environment:
      UNIFI_API_KEY: ${UNIFI_API_KEY}
      UNIFI_BASE_URL: ${UNIFI_BASE_URL}
      LOG_LEVEL: info
    stdin_open: true
    tty: true
```

Run with:
```bash
docker compose up
```

## Troubleshooting

### "Authentication Failed"
**Problem:** Cannot connect to UniFi controller

**Solutions:**
1. Verify API key is correct: `echo $UNIFI_API_KEY`
2. Check base URL (format: `https://controller-ip`, not `https://controller-ip:8443/admin`)
3. Test connectivity:
   ```bash
   curl -sk -H "X-API-KEY: your-key" \
     https://192.168.1.1/proxy/network/api/self/sites
   ```
4. Check firewall: `nc -zv 192.168.1.1 8443`

### SSL Certificate Warnings
Normal for self-signed certificates. The server handles this automatically.

To disable verification (not recommended):
```bash
UNIFI_SKIP_SSL_VERIFY=true go run cmd/main.go
```

### "No Tools Found" in Claude
1. Verify server is running: `ps aux | grep unifi-mcp`
2. Check MCP configuration path and environment variables
3. Check server logs: `LOG_LEVEL=debug go run cmd/main.go`
4. Restart Claude completely (quit, don't just close)

### "Request Failed" Errors
1. Check API key permissions (need read access)
2. Verify UniFi version is 8.0+
3. Check for rate limiting (add delays between calls)
4. Review detailed logs: `LOG_LEVEL=debug go run cmd/main.go 2>&1 | tail -f`

### Empty Results
1. Verify site_id is correct
2. Check device/client actually exists in UniFi
3. Verify API key permissions
4. Try a simple tool first: `get_network_sites`

## Next Steps

1. ✅ Install and configure the server
2. ✅ Verify API connectivity
3. ⬜ [Integrate with Claude/Copilot](#integration-with-claude)
4. ⬜ [Explore capabilities](./CAPABILITIES.md)
5. ⬜ [Review examples](./EXAMPLES.md)

## Additional Resources

- **[Capabilities Guide](./CAPABILITIES.md)** - All 26 tools and their capabilities
- **[API Reference](./API_REFERENCE.md)** - Complete API documentation
- **[Examples](./EXAMPLES.md)** - Real-world usage examples
- **[Best Practices](./BEST_PRACTICES.md)** - Tips for optimal use
- **[Troubleshooting](./TROUBLESHOOTING.md)** - Common issues and solutions
- **[API Status](./API_STATUS.md)** - Implementation details and recent fixes

## Getting Help

1. Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for common issues
2. Review [API_STATUS.md](./API_STATUS.md) for implementation details
3. Enable debug logging: `LOG_LEVEL=debug`
4. Check server logs for error messages
