# UniFi MCP Server - Copilot Integration Guide

This guide explains how to use the UniFi MCP Server with GitHub Copilot and other Claude-compatible interfaces.

## Quick Start

### 1. Setup MCP Server

First, ensure the UniFi MCP Server is running on your system:

```bash
# From the unifi-mcp directory
go run cmd/main.go
```

The server should output:
```
Starting Unifi MCP Server on stdio transport
```

### 2. Configure Copilot

Add the following to your Copilot configuration:

```json
{
  "mcp_servers": {
    "unifi": {
      "command": "go",
      "args": ["run", "/path/to/unifi-mcp/cmd/main.go"],
      "env": {
        "UNIFI_API_KEY": "your-api-key",
        "UNIFI_BASE_URL": "https://your-unifi-host.com",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### 3. Configure Environment Variables

Create a `.env` file in the root of the unifi-mcp directory:

```env
UNIFI_API_KEY=your-api-key-here
UNIFI_BASE_URL=https://192.168.1.1
LOG_LEVEL=info
```

## Common Tasks

### Understanding Site IDs

UniFi sites are identified by UUIDs, but the MCP server makes this easier:

- **No site_id parameter**: Automatically uses your first site
- **Site name**: Pass `site_id="My Network"` and it resolves to UUID
- **UUID**: Pass the full UUID if you know it: `site_id="5c47dc5d8e0c7a1a2b3c4d5e"`

You can list all available sites with:
> "Show me all my UniFi sites"

This is useful for multi-site setups where you need to specify which site to query.

### Monitor Network Health

Ask Copilot:
> "Get the health status of my default UniFi site"

Copilot will use `get_site_health` to retrieve:
- Number of connected devices
- Number of clients
- Overall network status

### Check Connected Devices

Ask Copilot:
> "List all WiFi networks and connected clients in my network"

This uses:
- `get_wifi_networks` - to list all WiFi networks
- `get_network_clients` - to list connected clients

### Monitor Specific Device

Ask Copilot:
> "Get statistics for my gateway device"

Copilot will:
1. Use `get_network_devices` to find the device
2. Use `get_network_device_stats` to get detailed statistics

### Security Analysis

Ask Copilot:
> "Show me all firewall zones and ACL rules in my network"

This uses:
- `get_firewall_zones` - to list zones
- `get_acl_rules` - to list rules

### Camera Monitoring

Ask Copilot:
> "Get all Protect devices and recent events"

Copilot will use:
- `get_protect_devices` - to list cameras
- `get_protect_events` - to get recent events
- `get_protect_info` - to get system info

### Network Planning

Ask Copilot:
> "Show me pending devices and available DPI categories"

This uses:
- `get_pending_devices` - to see devices waiting for adoption
- `get_dpi_categories` - to understand traffic categories

## Advanced Queries

### Network Analysis

> "Analyze my network health and identify any devices that might be offline"

Copilot will:
1. Get all sites
2. Check health for each site
3. Get device list and filter for offline devices

### Client Statistics

> "Show me client statistics and highlight the top bandwidth consumers"

Copilot will:
1. Get all clients from the site
2. Retrieve detailed statistics
3. Sort by bandwidth usage

### Security Audit

> "Generate a security report showing all firewall rules and access controls"

Copilot will:
1. Get firewall zones
2. Get ACL rules
3. Get hotspot voucher status
4. Generate a summary report

## Troubleshooting

### Authentication Fails

**Error:** `AUTHENTICATION_FAILED`

**Solution:**
1. Verify your API key is correct
2. Check that UNIFI_BASE_URL is properly formatted
3. Ensure the API key has proper permissions

### Invalid Site ID

**Error:** `INVALID_SITE_ID` or site not found

**Solution:**
The `site_id` parameter is optional for most tools:
1. If not provided, the server automatically uses your first configured site
2. You can also use the site name (the server resolves it to UUID automatically)
3. Or provide the UUID directly

Examples:
- No site specified: Uses first site automatically
- `site_id="My Network"`: Resolves the name to UUID
- `site_id="5c47dc5d8e0c7a1a2b3c4d5e"`: Uses the UUID directly

To see all available sites, ask:
> "List all my UniFi sites"

This calls `get_network_sites` to show site names and UUIDs.

### Request Timeout

**Error:** `REQUEST_FAILED` or timeout

**Solution:**
1. Check network connectivity to UniFi controller
2. Verify the base URL is correct
3. Check for firewall rules blocking the connection

### No Data Returned

**Issue:** Tools return empty results

**Solution:**
1. Verify you have devices/clients connected
2. Check site permissions
3. Ensure the controller is running properly

## Best Practices

### 1. Use Descriptive Requests

❌ Bad: "Get data"
✅ Good: "Get WiFi networks and connected clients from my default site"

### 2. Ask for Specific Information

❌ Bad: "Show me everything"
✅ Good: "Show me all ACL rules and firewall zones"

### 3. Use Pagination for Large Datasets

For large client lists, ask:
> "Get the first 50 clients from my network"

Copilot will use the limit parameter appropriately.

### 4. Combine Related Queries

Ask for related data together:
> "Get site health, list all devices, and show connected clients"

This is more efficient than separate requests.

### 5. Cache Results

For frequently accessed data:
> "Get and save the list of WiFi networks"

This reduces unnecessary API calls.

## Tool Reference by Use Case

### Network Monitoring
- `get_network_sites` - List all sites
- `get_network_devices` - List devices in a site
- `get_network_device_stats` - Device statistics
- `get_site_health` - Site health status

### WiFi Management
- `get_wifi_networks` - List WiFi networks
- `get_wifi_broadcasts` - WiFi broadcast details
- `get_network_clients` - Connected clients
- `get_dpi_categories` - Traffic categories

### Security
- `get_firewall_zones` - Firewall zones
- `get_acl_rules` - Access control rules
- `get_hotspot_vouchers` - Guest access vouchers

### Camera/Protect
- `get_protect_devices` - List cameras
- `get_protect_events` - Camera events
- `get_protect_info` - System information

### Maintenance
- `get_network_info` - UniFi version and info
- `get_pending_devices` - Devices pending adoption
- `get_client_stats` - Client statistics

## Prompting Strategies

### Strategy 1: Hierarchical Exploration

> "First, list all my sites, then for the default site, get the health status and list all devices"

This guides Copilot through a logical flow.

### Strategy 2: Comparison Requests

> "Compare the health status across all my sites - which one has the most clients?"

Copilot will make multiple calls and provide analysis.

### Strategy 3: Problem-Solving

> "I'm experiencing slow WiFi. Show me connected clients, current WiFi networks, and device load statistics"

Copilot will gather relevant data to help diagnose the issue.

### Strategy 4: Reporting

> "Generate a network status report including sites, devices, clients, and security settings"

Copilot will create a comprehensive summary.

## Integration Examples

### Example 1: Daily Status Check

```
Get the health status of each site and list any offline devices
```

Copilot Response:
- Site status for all sites
- List of all devices
- Filter for offline devices
- Summary report

### Example 2: Security Audit

```
List all firewall zones, ACL rules, and hotspot vouchers to verify security settings
```

Copilot Response:
- Firewall zone configuration
- All ACL rules with descriptions
- Active hotspot vouchers
- Security assessment

### Example 3: New Client Onboarding

```
Show me pending devices and available WiFi networks so we can set up a new device
```

Copilot Response:
- Devices waiting for adoption
- Available WiFi networks and their security settings
- Instructions for device setup

## Support

For issues or questions:
1. Check the [API Reference](./API_REFERENCE.md)
2. Review [troubleshooting section](#troubleshooting)
3. Check server logs: `LOG_LEVEL=debug`
4. Open an issue on GitHub
