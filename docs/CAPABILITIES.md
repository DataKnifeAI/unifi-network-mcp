# UniFi MCP Server - Capabilities & Skills

Complete reference for all 51 available UniFi MCP tools and their capabilities.

## Overview

The UniFi MCP Server provides access to two major UniFi systems:
1. **UniFi Protect** - Camera and surveillance system (14 tools: 6 GET, 4 PATCH, 4 POST)
2. **UniFi Network** - Network management system (37 tools: 20 GET, 7 PATCH, 10 POST)

**Total available tools: 51 ✅**
- **GET Tools**: 26 (data retrieval)
- **PATCH Tools**: 11 (resource updates)
- **POST Tools**: 14 (resource creation)

---

## Network Management Tools (18 tools)

### Site & Device Management

#### `get_network_sites`
List all configured UniFi Network sites
- **Parameters:** None
- **Returns:** List of sites with names, descriptions, and IDs
- **Use Case:** View all managed sites at a glance
- **Example:** "List all my UniFi sites"

#### `get_network_devices`
Get all devices in a site (switches, APs, gateways, etc.)
- **Parameters:** site_id (optional, defaults to first site)
- **Returns:** Device list with status, IP, model, uptime
- **Use Case:** Inventory management, device monitoring
- **Example:** "Show me all network devices"

#### `get_network_device_detailed`
Get comprehensive details for a specific device
- **Parameters:** device_id (required)
- **Returns:** Full device specification and configuration
- **Use Case:** Device-specific troubleshooting
- **Example:** "Get details for device X"

#### `get_network_device_stats`
Get performance statistics for a specific device
- **Parameters:** device_id (required)
- **Returns:** CPU, memory, network statistics
- **Use Case:** Performance monitoring, diagnostics
- **Example:** "Show stats for my gateway"

#### `get_network_info`
Get UniFi Network application version and system info
- **Parameters:** None
- **Returns:** Version, system status, configuration
- **Use Case:** Version tracking, system health
- **Example:** "What UniFi version am I running?"

#### `get_pending_devices`
Find devices pending adoption/setup
- **Parameters:** None
- **Returns:** Unadopted devices with MAC addresses
- **Use Case:** New device onboarding
- **Example:** "Show me devices waiting to be set up"

### WiFi Management (4 tools)

#### `get_wifi_networks`
List all configured WiFi networks
- **Parameters:** site_id (optional)
- **Returns:** SSID list with security, enabled status
- **Use Case:** WiFi configuration review
- **Example:** "List all WiFi networks"

#### `get_wifi_broadcasts`
View active WiFi SSID broadcasts
- **Parameters:** site_id (optional)
- **Returns:** Active broadcasts with configuration
- **Use Case:** WiFi visibility and broadcast management
- **Example:** "Which WiFi networks are being broadcast?"

#### `get_network_clients`
List all connected clients/devices on the network
- **Parameters:** site_id (optional), limit, offset
- **Returns:** Connected devices with IP, MAC, network info
- **Use Case:** Client inventory, connection monitoring
- **Example:** "Show me all connected devices"

#### `get_client_stats`
Get statistics for network clients
- **Parameters:** site_id (optional)
- **Returns:** Client-level traffic and performance stats
- **Use Case:** Bandwidth analysis, performance tracking
- **Example:** "Show me client statistics"

### Firewall & Security (3 tools)

#### `get_firewall_zones`
View firewall zones and segmentation
- **Parameters:** site_id (optional)
- **Returns:** Configured zones and rules
- **Use Case:** Network segmentation review, security auditing
- **Example:** "Show my firewall zones"

#### `get_acl_rules`
List access control rules
- **Parameters:** site_id (optional)
- **Returns:** ACL rules with source/destination/action
- **Use Case:** Security policy verification
- **Example:** "What are my access control rules?"

#### `get_hotspot_vouchers`
Manage guest WiFi access vouchers
- **Parameters:** site_id (optional)
- **Returns:** Voucher status and configuration
- **Use Case:** Guest network access management
- **Example:** "Show guest access vouchers"

### Advanced Network Features (3 tools)

#### `get_vpn_servers`
View VPN server configurations
- **Parameters:** site_id (optional)
- **Returns:** VPN settings and status
- **Use Case:** Remote access configuration review
- **Example:** "Show my VPN servers"

#### `get_dpi_categories`
Get DPI (Deep Packet Inspection) application categories
- **Parameters:** None
- **Returns:** Available traffic analysis categories
- **Use Case:** Traffic categorization, QoS setup
- **Example:** "What application categories can I filter?"

#### `get_site_health`
Get overall site health and status
- **Parameters:** site_id (optional)
- **Returns:** Health status, issues, performance metrics
- **Use Case:** Quick health check, monitoring
- **Example:** "Is my network healthy?"

---

## Protect (Surveillance) Tools (8 tools)

### Camera Management

#### `get_protect_cameras`
List all UniFi Protect cameras
- **Parameters:** None
- **Returns:** Camera list with status, model, firmware
- **Use Case:** Camera inventory, status monitoring
- **Example:** "Show me all cameras"

#### `get_protect_devices`
Get all Protect devices (cameras, sensors, etc.)
- **Parameters:** None
- **Returns:** All device types with status
- **Use Case:** Full Protect system inventory
- **Example:** "List all Protect devices"

### Sensors & Accessories

#### `get_protect_sensors`
List all door/window sensors
- **Parameters:** None
- **Returns:** Sensor list with status and location
- **Use Case:** Security sensor monitoring
- **Example:** "Show all door sensors"

#### `get_protect_lights`
List UniFi Protect lights
- **Parameters:** None
- **Returns:** Smart light status and configuration
- **Use Case:** Lighting system control and monitoring
- **Example:** "Show my Protect lights"

#### `get_protect_chimes`
List UniFi Protect chimes/doorbells
- **Parameters:** None
- **Returns:** Chime status and configuration
- **Use Case:** Audio device monitoring
- **Example:** "Show doorbell chimes"

### System Information

#### `get_protect_info`
Get Protect system information
- **Parameters:** None
- **Returns:** Version, system type, unique ID
- **Use Case:** System version tracking, health check
- **Example:** "What's my Protect version?"

#### `get_protect_events`
Get Protect events and alerts
- **Parameters:** limit (optional), offset (optional)
- **Returns:** Recent events with timestamps and details
- **Use Case:** Event review, alert monitoring
- **Example:** "Show recent camera events"

---

## Skill Categories & Use Cases

### 1. Quick Health Check
**Tools Needed:** 
- `get_site_health`
- `get_network_sites`
- `get_protect_info`

**Capability:** Rapid network and system status overview
**Complexity:** ⭐ Easy

### 2. Device Inventory
**Tools Needed:**
- `get_network_devices`
- `get_protect_cameras`
- `get_protect_devices`
- `get_pending_devices`

**Capability:** Complete device inventory and status
**Complexity:** ⭐ Easy

### 3. WiFi Network Review
**Tools Needed:**
- `get_wifi_networks`
- `get_wifi_broadcasts`
- `get_network_clients`

**Capability:** WiFi configuration and coverage analysis
**Complexity:** ⭐⭐ Moderate

### 4. Performance Analysis
**Tools Needed:**
- `get_network_device_stats`
- `get_client_stats`
- `get_dpi_categories`
- `get_site_health`

**Capability:** Detailed performance monitoring and analysis
**Complexity:** ⭐⭐ Moderate

### 5. Security Audit
**Tools Needed:**
- `get_firewall_zones`
- `get_acl_rules`
- `get_hotspot_vouchers`
- `get_protect_devices`
- `get_protect_sensors`

**Capability:** Comprehensive security configuration review
**Complexity:** ⭐⭐⭐ Complex

### 6. Complete Network Audit
**Tools Needed:**
- All 26 tools

**Capability:** Full system audit with all details
**Complexity:** ⭐⭐⭐⭐ Very Complex

---

## Tool Response Examples

### Network Device
```json
{
  "_id": "64db0dda3013df5cc4a8618c",
  "name": "UDMP - Chapman Residence",
  "type": "udm",
  "model": "UDMPRO",
  "mac": "70:a7:41:78:b7:5a",
  "ip": "156.47.246.183",
  "connected": false,
  "uptime": 495
}
```

### WiFi Network
```json
{
  "_id": "64db15633013df5cc4a862ff",
  "name": "Home",
  "enabled": true,
  "security": "wpa2"
}
```

### Connected Client
```json
{
  "mac": "50:de:06:5e:10:75",
  "hostname": "Master-Bedroom",
  "ip": "192.168.3.65",
  "network": "Home",
  "is_wired": false,
  "uptime": 184
}
```

### Camera
```json
{
  "id": "69191ec802f88b03e43b8ca0",
  "name": "Driveway",
  "model": "G6 Bullet",
  "mac": "A89C6C48025F",
  "status": "online"
}
```

---

## Prompting Best Practices

### ✅ Effective Requests
- "Show me all WiFi networks and their connected devices"
- "List cameras and recent events from the last 24 hours"
- "Perform a security audit of my firewall rules"
- "Analyze bandwidth usage by client"
- "Find offline devices in my network"

### ❌ Vague Requests
- "Show me stuff"
- "Get network info"
- "List things"
- "Check status"

### 🎯 Context is Key
- Specify which site if multi-site: "For my default site..."
- Mention device type if specific: "For my gateway..."
- Include time periods if relevant: "Events from today..."
- Request analysis not just data: "Identify issues..." vs "Show data..."

---

## Common Workflows

### Workflow: New Device Setup
1. `get_pending_devices` - Find devices waiting for adoption
2. `get_network_sites` - Select target site
3. Adopt device through UI
4. `get_network_devices` - Confirm adoption

### Workflow: Troubleshooting Slow WiFi
1. `get_wifi_networks` - Check all networks
2. `get_network_clients` - Find connected devices
3. `get_client_stats` - Check bandwidth usage
4. `get_network_device_stats` - Check AP performance
5. `get_dpi_categories` - Identify traffic type

### Workflow: Security Check
1. `get_firewall_zones` - Review zones
2. `get_acl_rules` - Check rules
3. `get_hotspot_vouchers` - Verify guest access
4. `get_protect_sensors` - Check intrusion detection
5. `get_protect_cameras` - Verify surveillance

### Workflow: Network Health Report
1. `get_network_sites` - List sites
2. `get_site_health` - Check each site
3. `get_network_devices` - Find issues
4. `get_network_clients` - Check connectivity
5. Generate summary report

---

## Performance Characteristics

| Tool | Response Time | Data Size | Frequency |
|------|---------------|-----------|-----------|
| get_network_sites | <100ms | Small | Can call frequently |
| get_network_devices | 100-500ms | Medium | Can call frequently |
| get_network_clients | 200-1000ms | Large | Limit to hourly |
| get_client_stats | 1-5s | Very Large | Limit to hourly |
| get_protect_events | 500-2000ms | Large | Can call frequently |
| get_site_health | <100ms | Small | Can call frequently |
| get_network_device_stats | 100-200ms | Small | Can call frequently |

---

## API Key Permissions

Most tools require read permissions. The API key should have:
- ✅ Read access to network/protect data
- ⚠️ Admin level recommended for all features
- ❌ Write operations not currently supported

---

## Limitations & Considerations

1. **Data Freshness**
   - Some data cached by UniFi system
   - Real-time updates have slight latency (1-5 seconds)

2. **Rate Limiting**
   - UniFi API enforces request limits
   - Avoid calling expensive tools too frequently
   - Batch requests where possible

3. **Network Dependence**
   - Requires connectivity to UniFi controller
   - SSL certificate verification (can be disabled)

4. **Data Retention**
   - Event history depends on controller settings
   - Statistics aggregated over time periods
   - Old data may be purged

---

## Troubleshooting

### Tool Returns Empty Results
1. Verify site_id is correct
2. Check device/client actually exists
3. Verify API key permissions

### Request Times Out
1. Check network connectivity
2. Try a simpler tool first
3. Check UniFi controller status

### Authentication Error
1. Verify API key is set in .env
2. Check key hasn't expired
3. Regenerate key if needed

---

## Getting Help

For issues or feature requests:
1. Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)
2. Review [API_REFERENCE.md](./API_REFERENCE.md)
3. Check server logs with `LOG_LEVEL=debug`
