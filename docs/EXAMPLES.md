# UniFi MCP Server - Usage Examples

Real-world examples of using UniFi MCP Server with Claude/Copilot.

## Table of Contents

- [Network Monitoring](#network-monitoring)
- [Device Management](#device-management)
- [Security Operations](#security-operations)
- [WiFi Management](#wifi-management)
- [Surveillance Monitoring](#surveillance-monitoring)
- [Troubleshooting & Diagnostics](#troubleshooting--diagnostics)
- [Automation & Reporting](#automation--reporting)

---

## Network Monitoring

### Example 1: Daily Health Check

**Ask Claude:**
```
Get the health status of my network and list any devices that might be offline
```

**What Claude Does:**
1. Calls `get_network_sites` - Gets all sites
2. For each site, calls `get_site_health` - Checks health
3. Calls `get_network_devices` - Gets device list
4. Filters for offline devices
5. Provides summary

**Claude Response:**
```
Network Health Summary:
- Default Site: Healthy ✓
- Connected Devices: 12/12
- Connected Clients: 25
- Gateway: Online (uptime: 45 days)
- Access Points: 2/2 Online
- Switches: 1/1 Online
- Cameras: 4/4 Online

Status: All systems operational
```

---

### Example 2: Device Performance Check

**Ask Claude:**
```
Get detailed statistics for my gateway device (UDM-Pro) including CPU and memory usage
```

**What Claude Does:**
1. Calls `get_network_devices` - Gets all devices
2. Finds device matching "UDM-Pro"
3. Calls `get_network_device_stats` - Gets statistics
4. Formats and analyzes results

**Claude Response:**
```
Gateway Statistics (UDM-Pro):
- CPU Usage: 15.2%
- Memory: 3.2GB / 8GB (40%)
- Uptime: 45 days
- Model: UDM-Pro
- IP Address: 192.168.1.1
- Last Seen: Now

Performance: Good ✓
Recommendations: No action needed
```

---

### Example 3: Compare Sites

**Ask Claude:**
```
Compare health and device counts across all my UniFi sites
```

**What Claude Does:**
1. Calls `get_network_sites` - Lists all sites
2. For each site, calls `get_site_health`
3. Calls `get_network_devices` for each
4. Compares and ranks by health

**Claude Response:**
```
Site Comparison:

Office (default):
- Health: Excellent
- Devices: 15
- Clients: 45
- Status: Production

Warehouse:
- Health: Good
- Devices: 8
- Clients: 12
- Status: Production

Remote Office:
- Health: Fair
- Devices: 5
- Clients: 3
- Status: Monitoring needed
```

---

## Device Management

### Example 4: Pending Device Adoption

**Ask Claude:**
```
Show me all devices pending adoption and their network details
```

**What Claude Does:**
1. Calls `get_pending_devices` - Gets devices waiting for setup
2. Calls `get_network_info` - Gets site info
3. Formats device details for onboarding

**Claude Response:**
```
Pending Devices (2 found):

Device 1:
- Model: UniFi Access Point AC (UAC-AC-Pro)
- MAC: 78:45:c0:xx:xx:xx
- IP: 192.168.1.100
- Status: Ready for Adoption
- Action: Connect to network and adopt in UniFi

Device 2:
- Model: UniFi Switch (USW-24-PoE)
- MAC: 78:45:c2:xx:xx:xx
- IP: 192.168.1.101
- Status: Ready for Adoption
- Action: Connect to network and adopt in UniFi

Adoption Steps:
1. Access http://192.168.1.1 (controller IP)
2. Go to Devices → Pending
3. Click "Adopt" on each device
4. Wait for provisioning to complete
```

---

### Example 5: Device Inventory

**Ask Claude:**
```
Create a complete inventory of all my network devices
```

**What Claude Does:**
1. Calls `get_network_sites` - Gets all sites
2. For each site, calls `get_network_devices`
3. Organizes by type (Gateway, AP, Switch, etc.)
4. Generates formatted inventory

**Claude Response:**
```
Network Inventory:

GATEWAYS (1):
- UDM-Pro (192.168.1.1) - Online - Uptime: 45d

ACCESS POINTS (2):
- UAP-AC-PRO (192.168.1.10) - Online - Uptime: 45d
- UAP-AC-PRO (192.168.1.11) - Online - Uptime: 45d

SWITCHES (2):
- USW-24-PoE (192.168.1.20) - Online - Uptime: 45d
- USW-8 (192.168.1.21) - Online - Uptime: 45d

CAMERAS (4):
- UVC G4 Doorbell (192.168.1.50) - Online
- UVC G4 Turret (192.168.1.51) - Online
- UVC G4 Bullet (192.168.1.52) - Online
- UVC Dome (192.168.1.53) - Online

Total Devices: 9
All Online: ✓
```

---

## Security Operations

### Example 6: Security Audit

**Ask Claude:**
```
Perform a complete security audit of my network including firewall rules and access controls
```

**What Claude Does:**
1. Calls `get_firewall_zones` - Gets firewall zones
2. Calls `get_acl_rules` - Gets access control rules
3. Calls `get_hotspot_vouchers` - Checks guest access
4. Analyzes security posture

**Claude Response:**
```
SECURITY AUDIT REPORT
Generated: 2024-01-10

FIREWALL ZONES:
- LAN (Internal network)
- WAN (Internet)
- Guest (Public WiFi)
- IoT (Smart devices)
- Status: 4 zones configured ✓

ACL RULES (12 rules):
- Block YouTube: ENABLED (LAN to Internet)
- Allow DNS: ENABLED (All to 8.8.8.8:53)
- Block P2P: ENABLED (LAN to All)
- Allow Office Hours: ENABLED (9AM-5PM)
- ...more rules...
Status: All rules active ✓

GUEST ACCESS:
- Active Vouchers: 5
- Expiration: Within 30 days
- Status: Active ✓

OVERALL SECURITY SCORE: 8.5/10
Recommendations:
- Consider adding more granular rules
- Review voucher expiration dates
- Check for unused rules
```

---

### Example 7: WiFi Security Review

**Ask Claude:**
```
Check WiFi networks and their security settings
```

**What Claude Does:**
1. Calls `get_wifi_networks` - Gets configured networks
2. Calls `get_wifi_broadcasts` - Gets broadcast details
3. Reviews security settings

**Claude Response:**
```
WiFi Networks Security Review:

Network 1: "MainNetwork"
- SSID: MainNetwork
- Security: WPA2/WPA3
- Band: 2.4G & 5G
- Channel Width: 80MHz (5G)
- Status: Secure ✓

Network 2: "GuestNetwork"
- SSID: GuestNetwork
- Security: WPA2
- Band: 2.4G only
- Status: Acceptable

Network 3: "IoTDevices"
- SSID: Hidden
- Security: WPA2
- Band: 5G only
- Status: Secure ✓

Recommendations:
- Upgrade GuestNetwork to WPA3 when possible
- Consider 5G for faster speeds
- Password change recommended in 30 days
```

---

## WiFi Management

### Example 8: Connected Clients Analysis

**Ask Claude:**
```
Show me all connected clients and identify any unusual connections
```

**What Claude Does:**
1. Calls `get_network_clients` - Gets connected devices
2. Calls `get_client_stats` - Gets traffic stats
3. Analyzes connection patterns

**Claude Response:**
```
Connected Clients Analysis:
Total Connected: 18 devices

COMPUTERS (5):
- MacBook Pro (192.168.1.50) - WiFi 5G - Signal: -45dBm ✓
- Windows Desktop (192.168.1.51) - Wired - Excellent ✓
- Ubuntu Laptop (192.168.1.52) - WiFi 5G - Signal: -50dBm
- iPad (192.168.1.53) - WiFi 2.4G - Signal: -60dBm
- MacBook Air (192.168.1.54) - WiFi 5G - Signal: -48dBm ✓

MOBILE DEVICES (8):
- iPhone 14 Pro (192.168.1.60) - WiFi 5G - Signal: -42dBm ✓
- iPhone 12 (192.168.1.61) - WiFi 2.4G - Signal: -58dBm
- Android Phone (192.168.1.62) - WiFi 2.4G - Signal: -65dBm
...more devices...

SMART HOME (5):
- Nest Thermostat (192.168.1.80) - WiFi 2.4G ✓
- Philips Hue Bridge (192.168.1.81) - WiFi 2.4G ✓
- Apple TV (192.168.1.82) - WiFi 5G ✓
...more devices...

UNUSUAL CONNECTIONS: None detected
CONNECTION QUALITY: Good
Recommendations:
- Move IoT devices to dedicated network
- Encourage mobile users to 5G band
- Update older devices' WiFi drivers
```

---

### Example 9: WiFi Optimization

**Ask Claude:**
```
Analyze WiFi performance and suggest optimizations
```

**What Claude Does:**
1. Calls `get_wifi_networks` - Gets network config
2. Calls `get_network_clients` - Gets client distribution
3. Calls `get_client_stats` - Gets usage patterns
4. Analyzes and recommends optimizations

**Claude Response:**
```
WiFi Performance Analysis:

Current Configuration:
- Channel 6 (2.4G): 12 clients - 60% utilization
- Channel 36 (5G): 6 clients - 30% utilization

Issues Detected:
- 2.4G band overloaded
- Some devices could migrate to 5G
- Channel 6 has interference

Optimization Recommendations:
1. HIGH PRIORITY:
   - Migrate 5+ clients from 2.4G to 5G
   - Use DFS channel 144 for 5G (less crowded)
   
2. MEDIUM PRIORITY:
   - Adjust transmit power to reduce interference
   - Use band steering to prefer 5G
   
3. LOW PRIORITY:
   - Update AP firmware
   - Reposition APs for better coverage

Expected Benefits:
- 30% throughput improvement
- Better latency for streaming
- Reduced interference

Estimated Impact: High
Difficulty: Medium
Time to implement: 30 minutes
```

---

## Surveillance Monitoring

### Example 10: Camera Status

**Ask Claude:**
```
Show me all cameras and their status
```

**What Claude Does:**
1. Calls `get_protect_devices` - Gets all cameras
2. Calls `get_protect_info` - Gets system status
3. Formats camera details

**Claude Response:**
```
Protect System Status:
System Version: 2.8.5
Storage Used: 45GB / 100GB (45%)
Uptime: 28 days

CAMERAS (4):

1. Front Door:
   - Model: UVC G4 Doorbell
   - Status: Recording ✓
   - Uptime: 28 days
   - Last Frame: Just now
   - Status Light: All good

2. Back Yard:
   - Model: UVC G4 Turret
   - Status: Recording ✓
   - Uptime: 28 days
   - Last Frame: Just now
   - Status Light: All good

3. Garage:
   - Model: UVC G4 Bullet
   - Status: Recording ✓
   - Uptime: 28 days
   - Last Frame: Just now

4. Entrance:
   - Model: UVC Dome
   - Status: Recording ✓
   - Uptime: 28 days
   - Last Frame: Just now

System Health: Excellent ✓
All Cameras Online: Yes
Recording Status: All Active
Storage Sufficient: Yes (45% used)
```

---

### Example 11: Recent Events

**Ask Claude:**
```
Show me events from the last 24 hours
```

**What Claude Does:**
1. Calls `get_protect_events` with limit and offset
2. Filters for recent events
3. Organizes by type and time

**Claude Response:**
```
Recent Events (Last 24 Hours):

MOTION DETECTED (12):
- 2024-01-10 14:32 - Front Door (Person) - Action: Recorded
- 2024-01-10 14:25 - Back Yard (Car) - Action: Recorded
- 2024-01-10 13:15 - Garage (Person) - Action: Recorded
...more events...

SYSTEM EVENTS (3):
- 2024-01-10 10:00 - Back Yard Camera: Connection restored
- 2024-01-10 09:55 - Back Yard Camera: Connection lost
- 2024-01-09 20:30 - Storage backup completed

ALERTS (0):
- No alerts

SUMMARY:
- Total Events: 15
- Motion Events: 12
- System Events: 3
- Alerts: 0
- Status: Normal operation ✓
```

---

## Troubleshooting & Diagnostics

### Example 12: Network Connectivity Issues

**Ask Claude:**
```
I'm having slow WiFi. Diagnose the issue and recommend fixes
```

**What Claude Does:**
1. Calls `get_wifi_networks` - Checks WiFi config
2. Calls `get_network_clients` - Gets connected devices
3. Calls `get_network_device_stats` - Gets AP performance
4. Calls `get_dpi_categories` - Checks for heavy apps
5. Analyzes root causes

**Claude Response:**
```
WiFi Performance Diagnosis:

ISSUES FOUND:

1. HIGH UTILIZATION (CRITICAL):
   - 2.4G band at 85% capacity
   - 12 devices on congested channel
   - Multiple devices need upgrading

2. INTERFERENCE DETECTED (HIGH):
   - Adjacent WiFi networks on same channel
   - Microwave/phone interference possible
   - Signal strength degraded

3. APPLICATION LOAD (MEDIUM):
   - Video streaming: 45% of bandwidth
   - File downloads: 30% of bandwidth
   - Other traffic: 25% of bandwidth

ROOT CAUSES (in order):
1. Too many devices on 2.4G band
2. Channel interference from neighbors
3. Heavy streaming/downloads active

RECOMMENDED FIXES:

IMMEDIATE (Do now):
1. Reduce 2.4G usage:
   - Move 5+ devices to 5G band
   - Stagger large downloads
   
2. Change WiFi channel:
   - Use channel 11 instead of 6 (less crowded)
   - Or use DFS channel 144 for 5G

MEDIUM-TERM (This week):
1. Enable band steering to prefer 5G
2. Update device WiFi drivers
3. Reposition access points

LONG-TERM (This month):
1. Add additional access point
2. Upgrade to WiFi 6 APs
3. Separate IoT devices to dedicated network

EXPECTED IMPROVEMENTS:
- 40-50% speed increase with immediate fixes
- Additional 20% with medium-term changes

Time to implement: Immediate fixes take 15 minutes
```

---

### Example 13: Device Offline Troubleshooting

**Ask Claude:**
```
One of my access points went offline. What could be the issue?
```

**What Claude Does:**
1. Calls `get_network_devices` - Gets all devices
2. Identifies offline device
3. Calls `get_network_device_stats` - Checks last stats
4. Provides troubleshooting steps

**Claude Response:**
```
Offline Device Analysis:

DEVICE: UAP-AC-PRO (192.168.1.11)
Status: OFFLINE ❌
Last Seen: 2024-01-10 08:30 (3 hours ago)
Typical Uptime: 45+ days

LIKELY CAUSES (in order of probability):

1. POWER ISSUE (Most Likely):
   - Device lost power
   - PoE injector failed
   - Power cable disconnected
   - Check: Is LED off?

2. NETWORK CONNECTIVITY:
   - Ethernet cable unplugged
   - Network port failed
   - PoE port failed
   - Check: Can you ping device IP?

3. CONTROLLER COMMUNICATION:
   - Firewall rule blocking communication
   - DNS issue
   - Controller software issue

4. HARDWARE FAILURE (Least Likely):
   - Device hardware failed
   - Requires replacement

TROUBLESHOOTING STEPS:

Step 1: Check Physical Connection (2 minutes)
□ Verify device has power (look for LED)
□ Check Ethernet cable is connected
□ Check PoE injector (if used)
□ Try power cycling the device

Step 2: Check Network Connectivity (3 minutes)
□ Ping the device: ping 192.168.1.11
□ Check if device responds
□ Verify network is working

Step 3: Check Controller (2 minutes)
□ Log in to UniFi Web UI
□ Check Devices → Manage → Offline
□ Look for error messages
□ Check controller logs

Step 4: Recovery (5 minutes)
□ Restart the access point
□ Wait 2-3 minutes for reconnection
□ Check if it comes back online

If still offline:
□ Reset to factory settings
□ Re-adopt the device
□ Contact manufacturer support

ESTIMATED RESOLUTION TIME:
- Quick fix (power): 5 minutes
- Reconnection: 20 minutes total
- Replacement: 1-2 hours
```

---

## Automation & Reporting

### Example 14: Weekly Status Report

**Ask Claude:**
```
Generate a weekly network status report
```

**What Claude Does:**
1. Calls multiple tools to gather data
2. Compiles comprehensive report
3. Includes metrics, trends, and recommendations

**Claude Response:**
```
WEEKLY NETWORK STATUS REPORT
Week of January 1-7, 2024

EXECUTIVE SUMMARY:
- Network Status: Healthy
- Uptime: 99.8%
- Performance: Good
- Security: Maintained
- Issues: 1 minor (resolved)

SITE METRICS:
┌─────────────┬──────────┬─────────┬──────────┐
│ Metric      │ Current  │ Last Wk │ Trend    │
├─────────────┼──────────┼─────────┼──────────┤
│ Devices     │ 15       │ 15      │ Stable   │
│ Clients     │ 28       │ 25      │ +12%     │
│ Uptime      │ 99.8%    │ 99.9%   │ Stable   │
│ Avg Latency │ 12ms     │ 10ms    │ +2ms     │
└─────────────┴──────────┴─────────┴──────────┘

DEVICE HEALTH:
✓ All core devices online
✓ All APs responding normally
✓ Storage at 45% capacity
✓ No critical errors

NETWORK TRAFFIC:
- Peak usage: Monday 2PM (450Mbps)
- Average usage: 280Mbps
- Most used service: Video streaming (60%)
- Bandwidth: Adequate

SECURITY:
✓ All firewall rules active
✓ Access controls enforced
✓ No security incidents
✓ Guest network active

ISSUES & RESOLUTIONS:
1. RESOLVED: Garage camera offline (Jan 4)
   - Cause: Power loss
   - Resolution: Restarted device
   - Impact: None (self-healing)

RECOMMENDATIONS:
1. Monitor latency increase (+2ms)
2. Schedule WiFi optimization
3. Plan AP firmware update
4. Review capacity for Q1

OUTLOOK:
- No critical issues expected
- Plan maintenance for quiet period
- Monitor device ages for refresh cycle

Report Generated: 2024-01-08
Next Report: 2024-01-15
```

---

### Example 15: Alert Setup

**Ask Claude:**
```
What should I monitor to ensure my network stays healthy?
```

**Claude Response:**
```
Network Health Monitoring Checklist:

CRITICAL ALERTS (Should trigger immediately):
□ Any device offline for > 5 minutes
□ Gateway device offline
□ All access points offline
□ > 50% packet loss on any link
□ Controller unreachable
□ Storage > 90% full

HIGH PRIORITY ALERTS (Check daily):
□ Any device offline for > 30 minutes
□ AP signal strength degraded
□ More than 1 device with errors
□ Unusual bandwidth spike
□ Firewall rules not active

MEDIUM PRIORITY (Check weekly):
□ Device uptime < 7 days
□ Storage > 75% full
□ New unknown devices connecting
□ Firewall rule count changing
□ DPI seeing unusual applications

MONITORING FREQUENCY:
- Critical: Real-time alerts
- High: Daily (automated checks)
- Medium: Weekly reviews

AUTOMATED CHECKS:
Every 5 minutes:
- Device status
- Controller availability
- Uptime metrics

Every hour:
- Network statistics
- Bandwidth usage
- Error counts

Daily:
- Full health check
- Generate report
- Email summary

Weekly:
- Trend analysis
- Capacity planning
- Security audit

RECOMMENDED SETUP:
1. Use Copilot for scheduled checks
2. Set up daily "health check" task
3. Weekly "status report" generation
4. Monthly "security audit"
```

---

## Advanced Scenarios

### Example 16: Multi-Site Management

**Ask Claude:**
```
Summarize the status across all my UniFi sites
```

**What Claude Does:**
1. Calls `get_network_sites` - Gets all sites
2. For each site: calls `get_site_health`, `get_network_devices`, `get_network_clients`
3. Compares and ranks sites
4. Provides centralized view

**Claude Response:**
```
MULTI-SITE SUMMARY

Total Sites: 3
Total Devices: 28
Total Clients: 87
Overall Status: Healthy ✓

┌──────────────┬────────┬────────┬───────┬──────────┐
│ Site         │ Health │ Devices│Clients│Status    │
├──────────────┼────────┼────────┼───────┼──────────┤
│ HQ (default) │ 100%   │ 15     │ 45    │ Excellent│
│ Branch 1     │ 95%    │ 8      │ 28    │ Good     │
│ Branch 2     │ 88%    │ 5      │ 14    │ Fair     │
└──────────────┴────────┴────────┴───────┴──────────┘

DETAILED STATUS:

HQ (default):
- Status: Excellent ✓
- Gateway: Online (45d uptime)
- APs: 3/3 online, excellent signal
- Devices: 15 total, 0 offline
- Clients: 45 connected
- Performance: Optimal

Branch 1:
- Status: Good ✓
- Gateway: Online (30d uptime)
- APs: 2/2 online, good signal
- Devices: 8 total, 0 offline
- Clients: 28 connected
- Performance: Good
- Note: Slightly high latency

Branch 2:
- Status: Fair ⚠️
- Gateway: Online (5d uptime)
- APs: 1/1 online, weak signal
- Devices: 5 total, 0 offline
- Clients: 14 connected
- Performance: Acceptable
- Issues: Needs AP reposition

RECOMMENDATIONS:
1. Reposition AP at Branch 2
2. Upgrade internet link at Branch 1
3. Add second AP at Branch 2
4. Plan HQ upgrades for next quarter
```

---

These examples demonstrate the power of UniFi MCP Server with Claude/Copilot for comprehensive network management!

---

## Direct API Testing with curl

### Testing API Endpoints

If you need to test the UniFi API directly or debug connectivity issues, use curl with your API key:

**Setup:**
```bash
# Set your environment variables
export UNIFI_API_KEY="your-api-key-here"
export UNIFI_BASE_URL="https://192.168.1.1"

# Test basic connectivity
curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
  "$UNIFI_BASE_URL/proxy/network/integration/v1/sites" | jq
```

**Common API Queries:**

1. **List all sites:**
   ```bash
   curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
     "$UNIFI_BASE_URL/proxy/network/integration/v1/sites" | jq '.data[] | {name, _id}'
   ```

2. **List all network devices:**
   ```bash
   # Note: Site ID may be an empty string, resulting in /sites//devices
   curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
     "$UNIFI_BASE_URL/proxy/network/integration/v1/sites//devices" | jq '.data[] | {name, mac, ip, type, model}'
   ```

3. **Get device details:**
   ```bash
   DEVICE_ID="<device-id-from-list>"
   curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
     "$UNIFI_BASE_URL/proxy/network/integration/v1/sites//devices/$DEVICE_ID" | jq
   ```

4. **Get device statistics:**
   ```bash
   DEVICE_ID="<device-id-from-list>"
   curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
     "$UNIFI_BASE_URL/proxy/network/integration/v1/sites//devices/$DEVICE_ID/statistics/latest" | jq
   ```

5. **List WiFi networks:**
   ```bash
   curl -k -H "X-API-KEY: $UNIFI_API_KEY" \
     "$UNIFI_BASE_URL/proxy/network/integration/v1/sites//wifi" | jq '.data[] | {name, ssid, security, enabled}'
   ```

**Important Notes:**
- The `-k` flag ignores SSL certificate warnings (useful for self-signed certs)
- Site IDs may appear as empty strings in your UniFi setup - this is normal
- Use `jq` to parse and filter JSON responses
- The MCP server automatically handles empty site IDs for you
