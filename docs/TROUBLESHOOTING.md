# UniFi MCP Server - Troubleshooting Guide

Complete troubleshooting for common issues.

## Quick Diagnosis

### Step 1: Check Server Status

```bash
# Is the server running?
ps aux | grep unifi-mcp

# Check logs
journalctl -u unifi-mcp -n 50  # If running as service
```

### Step 2: Verify Configuration

```bash
# Check environment variables
echo "API Key: $UNIFI_API_KEY"
echo "Base URL: $UNIFI_BASE_URL"

# Check if .env file exists
ls -la .env .env.local 2>/dev/null
```

### Step 3: Test API Connectivity

```bash
# Test basic connectivity (ignore SSL warnings)
curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
  "$UNIFI_BASE_URL/proxy/network/integration/v1/sites"
```

---

## Common Issues & Solutions

### Issue 1: "API Key Not Configured"

**Error Message:**
```
failed to authenticate: API key not configured
```

**Causes:**
- Missing UNIFI_API_KEY environment variable
- Empty API key value
- API key not set in .env file

**Solutions:**

1. **Check environment variable:**
   ```bash
   echo $UNIFI_API_KEY
   ```
   Should output your API key. If empty, continue to step 2.

2. **Create .env file:**
   ```bash
   cat > .env << EOF
   UNIFI_API_KEY=your-actual-api-key-here
   UNIFI_BASE_URL=https://192.168.1.1
   LOG_LEVEL=info
   EOF
   ```

3. **Load environment:**
   ```bash
   source .env
   echo $UNIFI_API_KEY  # Should now show your key
   ```

4. **Restart server:**
   ```bash
   go run cmd/main.go
   ```

---

### Issue 2: "Authentication Failed"

**Error Message:**
```
request failed with status 401: Unauthorized
```

**Causes:**
- Invalid API key
- Expired API key
- API key doesn't have required permissions
- Wrong base URL

**Solutions:**

1. **Verify API Key in UniFi:**
   - Log in to UniFi Web UI
   - System Settings → Integrations
   - Check if your API key still exists
   - If missing, create a new one

2. **Test with curl:**
   ```bash
   curl -v -k -H "X-API-KEY: your-key" \
     https://192.168.1.1/proxy/network/integration/v1/info
   ```
   Should return JSON data, not 401 error.

3. **Check API Key Format:**
   - Should be a long string of characters
   - Should NOT include quotes when setting in shell
   ```bash
   # Wrong
   export UNIFI_API_KEY="abc123"
   # Right
   export UNIFI_API_KEY=abc123
   ```

4. **Verify Base URL:**
   - Should be: `https://your-controller-ip`
   - Should NOT include `/admin`, `/api`, or port numbers
   - Example: `https://192.168.1.1` ✅
   - Wrong: `https://192.168.1.1:8443` ❌

---

### Issue 3: "Connection Refused" or "Timeout"

**Error Message:**
```
dial tcp 192.168.1.1:443: connection refused
request failed: context deadline exceeded
```

**Causes:**
- Controller is offline
- Network connectivity issue
- Firewall blocking access
- Wrong IP address
- Controller port not responding

**Solutions:**

1. **Check UniFi Controller Status:**
   ```bash
   # Can you ping it?
   ping -c 4 192.168.1.1
   
   # Is the port open?
   nc -zv 192.168.1.1 443
   nc -zv 192.168.1.1 8443
   ```

2. **Verify Base URL Is Reachable:**
   ```bash
   curl -v --insecure https://192.168.1.1
   # Should show HTTP headers, not connection refused
   ```

3. **Check Network Connectivity:**
   ```bash
   # From same network?
   route -n | grep default
   
   # DNS resolution working?
   nslookup 192.168.1.1
   ```

4. **Check Firewall Rules:**
   ```bash
   # macOS
   sudo lsof -i :443
   
   # Linux
   sudo netstat -tuln | grep 443
   
   # Check iptables (Linux)
   sudo iptables -L -n | grep 192.168.1.1
   ```

5. **Try Different Port:**
   ```bash
   # If 443 fails, try 8443
   UNIFI_BASE_URL=https://192.168.1.1:8443 go run cmd/main.go
   ```

---

### Issue 4: "No Tools Available in Claude"

**Symptom:**
- Claude doesn't show UniFi tools
- Tools show as unavailable
- "No tools found" message

**Causes:**
- MCP server not running
- Claude configuration incorrect
- Server not registering tools properly
- Transport connection issues

**Solutions:**

1. **Verify Server Is Running:**
   ```bash
   # Check if process exists
   pgrep -f "go.*cmd/main.go"
   
   # Look for the startup message
   go run cmd/main.go | head -5
   ```
   Should see: `Starting Unifi MCP Server on stdio transport`

2. **Check Claude Configuration:**
   - Open Claude Desktop app
   - Settings → Developer → MCP Server
   - Verify the configuration is correct:
     ```json
     {
       "command": "go",
       "args": ["run", "/path/to/unifi-mcp/cmd/main.go"],
       "env": {
         "UNIFI_API_KEY": "your-key",
         "UNIFI_BASE_URL": "https://192.168.1.1"
       }
     }
     ```

3. **Restart Claude:**
   - Completely quit Claude (not just close)
   - Wait 3 seconds
   - Relaunch Claude
   - Try again

4. **Check Server Logs:**
   ```bash
   LOG_LEVEL=debug go run cmd/main.go 2>&1 | head -20
   ```
   Look for:
   - Tool registration messages
   - Authentication messages
   - Any error messages

5. **Verify Tool Registration:**
   The output should include:
   ```
   INFO[...] Registered all MCP tools
   INFO[...] Tool: get_network_sites
   INFO[...] Tool: get_network_devices
   ... (20+ tools total)
   ```

---

### Issue 5: "No Sites Found" or "No Devices"

**Symptom:**
- Tools return empty results
- `get_network_sites` returns count=0
- `get_network_devices` returns no devices

**Causes:**
- No sites configured in UniFi
- API key doesn't have proper permissions
- Site ID is wrong
- UniFi system is not properly set up

**Solutions:**

1. **Verify UniFi Has Sites:**
   - Log in to UniFi Web UI
   - Check Networks → Sites
   - Should see at least "default" site
   - If no sites, create one first

2. **Check API Key Permissions:**
   - In UniFi: System Settings → Integrations
   - Check the API key you're using
   - Should have "Read" permission minimum
   - Consider granting "Admin" for full access

3. **Verify Devices Are Connected:**
   - In UniFi Web UI
   - Navigate to Devices
   - Should see at least the controller itself
   - If no devices, check network connectivity

4. **Test with Correct Site ID:**
   - Get list of sites:
     ```bash
     curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
       "$UNIFI_BASE_URL/proxy/network/integration/v1/sites"
     ```
   - Note the `_id` field
   - Use that ID when querying devices

5. **Check UniFi Version:**
   - Web UI → System → Version
   - Should be 8.0 or later
   - Some endpoints don't work on older versions

---

### Issue 6: "Invalid Site ID"

**Error Message:**
```
request failed with status 404: Not Found
```

**Causes:**
- Site ID is incorrect
- Site was deleted
- Typo in site ID
- Using human-readable name instead of ID

**Solutions:**

1. **Get Correct Site IDs:**
   ```bash
   curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
     "$UNIFI_BASE_URL/proxy/network/integration/v1/sites" | jq '.data[].name, .data[]._id'
   ```

2. **Default Site ID:**
   - Usually the site ID is "default"
   - Check in UniFi Web UI for exact ID

3. **Use in Tools:**
   When calling tools with site_id parameter, use the `_id` value, not the name.

---

### Issue 7: "Permission Denied" Errors

**Error Message:**
```
request failed with status 403: Forbidden
```

**Causes:**
- API key has insufficient permissions
- Trying to access restricted endpoint
- Role-based access control (RBAC) blocking access

**Solutions:**

1. **Check API Key Role:**
   - In UniFi: System Settings → Integrations
   - Check permissions for your API key
   - Should have at least "Read" access

2. **Request Admin Access:**
   - Contact network administrator
   - Ask to elevate API key permissions
   - May need to create new key with admin rights

3. **Check Endpoint Permissions:**
   - Some endpoints require admin
   - Review API documentation
   - If endpoint requires admin, use admin key

---

### Issue 8: High Response Times / Slow Performance

**Symptom:**
- Requests take 10+ seconds
- Timeout errors occur sporadically
- Tools seem to hang

**Causes:**
- Network latency
- UniFi system is busy
- Large dataset being retrieved
- Rate limiting

**Solutions:**

1. **Increase Timeout:**
   ```bash
   REQUEST_TIMEOUT=60 go run cmd/main.go
   ```

2. **Check Network Latency:**
   ```bash
   ping -c 5 192.168.1.1
   # Should be < 50ms typically
   ```

3. **Check UniFi System Load:**
   - In UniFi Web UI
   - System → Dashboard
   - Check CPU and memory usage
   - If high, wait for it to settle

4. **Use Pagination for Large Queries:**
   ```bash
   # Instead of getting all clients at once
   # Request with limit parameter
   "get_network_clients" with "limit": 50
   ```

5. **Reduce Query Frequency:**
   - Don't query every few seconds
   - Cache results
   - Query once per minute instead of continuous

---

### Issue 9: "Certificate Verification Failed"

**Error Message:**
```
x509: certificate signed by unknown authority
certificate verify failed
```

**Causes:**
- UniFi uses self-signed certificate
- System doesn't trust the certificate
- Certificate is invalid

**Solutions:**

1. **This is Expected:**
   - UniFi typically uses self-signed certs
   - The server handles this automatically
   - You should see results despite the warning

2. **If Still Failing:**
   ```bash
   # Test with insecure flag
   curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
     "$UNIFI_BASE_URL/proxy/network/integration/v1/sites"
   ```

3. **To Trust Certificate Permanently:**
   ```bash
   # Export certificate
   echo | openssl s_client -servername 192.168.1.1 \
     -connect 192.168.1.1:443 2>/dev/null | \
     openssl x509 -out unifi-cert.pem
   
   # Add to system trust store (varies by OS)
   # macOS:
   sudo security add-trusted-cert -d -r trustRoot \
     -k /Library/Keychains/System.keychain unifi-cert.pem
   ```

---

### Issue 10: Server Crashes on Startup

**Symptom:**
- Server starts then immediately exits
- No error messages shown
- Crash happens without explanation

**Causes:**
- Invalid configuration
- Go version mismatch
- Missing dependencies

**Solutions:**

1. **Check Go Version:**
   ```bash
   go version  # Should be 1.21 or higher
   ```
   If older, upgrade Go.

2. **Download Dependencies:**
   ```bash
   go mod download
   go mod tidy
   ```

3. **Rebuild from Clean State:**
   ```bash
   rm -rf bin/ build/
   go build -o unifi-mcp cmd/main.go
   ./unifi-mcp
   ```

4. **Check for Syntax Errors:**
   ```bash
   go build -v cmd/main.go
   # Will show any compilation errors
   ```

5. **Review Recent Changes:**
   ```bash
   git diff HEAD~1
   # Check what changed
   git status
   ```

---

## Debugging Techniques

### Enable Debug Logging

```bash
LOG_LEVEL=debug go run cmd/main.go
```

Output will include:
- API request details
- Response times
- Error messages with full context
- Tool registration info

### Save Logs to File

```bash
LOG_LEVEL=debug go run cmd/main.go > server.log 2>&1 &
tail -f server.log
```

### Test Individual Endpoints

```bash
# Test sites endpoint
curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
  "$UNIFI_BASE_URL/proxy/network/integration/v1/sites" | jq

# Test devices endpoint (note: site_id in response may be empty string)
curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
  "$UNIFI_BASE_URL/proxy/network/integration/v1/sites//devices" | jq

# Get device details (if you have a device ID)
DEVICE_ID="<device-id-from-above>"
curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
  "$UNIFI_BASE_URL/proxy/network/integration/v1/sites//devices/$DEVICE_ID" | jq

# Get device statistics
curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
  "$UNIFI_BASE_URL/proxy/network/integration/v1/sites//devices/$DEVICE_ID/statistics/latest" | jq
```

### Check Tool Responses

In Claude/Copilot:
- Right-click on tool output
- Select "View Raw Response" if available
- Check for error codes

### Use strace (Linux)

```bash
strace -e trace=network go run cmd/main.go 2>&1 | grep connect
```

---

## Performance Diagnostics

### Monitor System Resources

```bash
# While server is running
watch -n 1 'ps aux | grep unifi-mcp'
```

### Check Open Connections

```bash
lsof -p $(pgrep -f unifi-mcp)
```

### Profile CPU Usage

```bash
# Using Go's built-in profiling
GODEBUG=cpu go run cmd/main.go
```

---

## Getting Support

### Information to Gather

When asking for help, provide:

1. **Error Message**
   ```bash
   # Include full error text
   ```

2. **Configuration (without secrets)**
   ```bash
   echo "GO_VERSION: $(go version)"
   echo "BASE_URL: $UNIFI_BASE_URL (without key)"
   echo "LOG_LEVEL: $LOG_LEVEL"
   ```

3. **Debug Logs**
   ```bash
   LOG_LEVEL=debug go run cmd/main.go 2>&1 | tail -100 > debug.log
   ```

4. **Test Results**
   ```bash
   curl -k -H "X-API-KEY: [key]" \
     "$UNIFI_BASE_URL/proxy/network/integration/v1/sites" 2>&1
   ```

### Opening an Issue

Include:
- Error messages (full text)
- Steps to reproduce
- Configuration (without API key)
- Debug logs
- Operating system
- Go version

---

## Prevention

### Keep Systems Updated

```bash
# Update Go
go version
# See website for newer versions

# Update UniFi
# Check for updates in UniFi Web UI
```

### Regular Backups

```bash
# Backup configuration
cp -r ~/.unifi-mcp ~/.unifi-mcp.backup.$(date +%Y%m%d)
```

### Monitor Health

```bash
# Periodic check script
#!/bin/bash
curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
  "$UNIFI_BASE_URL/proxy/network/integration/v1/sites" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "$(date): UniFi API OK"
else
  echo "$(date): UniFi API ERROR"
fi
```

---

## Still Stuck?

1. ✅ Read this guide thoroughly
2. ✅ Try the solutions in order
3. ✅ Enable debug logging
4. ✅ Test with curl directly
5. ✅ Check [Setup Guide](./SETUP.md)
6. ✅ Review [API Reference](./API_REFERENCE.md)
7. ⬜ Open an issue with debug logs
8. ⬜ Contact UniFi support for controller issues
