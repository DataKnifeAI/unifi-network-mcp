# UniFi Network MCP

![UniFi Network MCP server](docs/assets/unifi-network-mcp-hero.jpg)


Model Context Protocol (MCP) server for Ubiquiti UniFi Network management. Control and monitor your UniFi network infrastructure through an AI-powered interface.

**Focused on:** WiFi networks, clients, firewall, VPN, DPI, ACL rules, traffic shaping, and hotspot management.

⚠️ **Early Development Warning**: This project is in early development and may contain bugs that could cause unexpected behavior. Use with caution in production environments.

⚠️ **Prompt Injection Risk**: You are responsible for guarding against prompt injection when using these tools. Exercise extreme caution or use MCP tools only on systems and data you trust.

## Features

- **27 management tools** for complete network control
- **WiFi Network Management**: Create, update, and monitor WiFi networks with detailed queries
- **Firewall & Security**: Manage firewall zones, ACL rules with detailed access control
- **Traffic Control**: Configure traffic rules and rate limiting
- **VPN Management**: Establish site-to-site tunnels with server management
- **Hotspot Services**: Manage guest WiFi vouchers with detailed tracking
- **Deep Packet Inspection**: Analyze DPI applications and categories
- **Device Management**: Monitor sites, devices, and client connections with health checks
- **Network Configuration**: Manage WAN config, device tags, and RADIUS profiles
- **Stdio Transport**: MCP protocol over standard input/output for seamless integration
- **HTTP Transport**: Optional HTTP API for remote connections and integration

## Quick Start

### Installation

```bash
# Clone and build
git clone https://github.com/surrealwolf/unifi-network-mcp.git
cd unifi-network-mcp
go build -o bin/unifi-network-mcp ./cmd
```

### Configuration

Create a `.env` file:

```bash
UNIFI_BASE_URL=https://your-unifi-controller.com:8443
UNIFI_API_KEY=your-api-key-here
UNIFI_SKIP_SSL_VERIFY=false
LOG_LEVEL=info
```

### Running the Server

```bash
### Running the Server

**Stdio Transport (Default):**
```bash
./bin/unifi-network-mcp
```

**HTTP Transport:**
```bash
MCP_TRANSPORT=http MCP_HTTP_ADDR=:8000 ./bin/unifi-network-mcp
```

Then access the endpoints:
```bash
# Health check
curl http://localhost:8000/health

# MCP endpoint
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/list"}'
```

**Environment Variables:**
- `MCP_TRANSPORT`: Set to `"http"` for HTTP transport (default: `"stdio"`)
- `MCP_HTTP_ADDR`: HTTP server address (default: `:8000`)

## Available Tools (27 Total)

### Network Site & Device Management (5 tools)
- `get_network_sites` - List all network sites
- `get_site_details` - Get detailed site information
- `get_site_devices` - List devices in a specific site
- `get_device_details` - Get detailed device information
- `get_connected_clients` - List connected clients in a site

### WiFi Networks (5 tools)
- `create_wifi_network` - Create a new WiFi network
- `get_wifi_networks` - List all WiFi networks
- `get_wifi_network_detailed` - Get detailed WiFi network information
- `update_wifi_network` - Update WiFi network settings
- `patch_wifi_network` - Patch specific WiFi network properties

### Firewall & Security (6 tools)
- `get_firewall_zones` - List firewall zones
- `create_firewall_zone` - Create a new firewall zone
- `patch_firewall_zone` - Update firewall zone settings
- `get_acl_rules` - List ACL rules
- `create_acl_rule` - Create an ACL rule
- `patch_acl_rule` - Update ACL rule settings

### Traffic & Performance (3 tools)
- `get_traffic_rules` - List traffic matching rules
- `create_traffic_rule` - Create a traffic rule
- `patch_traffic_rule` - Update traffic rule settings

### Guest WiFi & Hotspot (2 tools)
- `get_hotspot_vouchers` - List hotspot vouchers
- `create_hotspot_voucher` - Generate guest access vouchers
- `patch_hotspot_voucher` - Update voucher settings

### VPN & Remote Access (2 tools)
- `get_vpn_servers` - List VPN servers
- `get_vpn_tunnels` - List site-to-site tunnels

### Deep Packet Inspection (2 tools)
- `get_dpi_categories` - List DPI categories
- `get_dpi_applications` - List monitored applications

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `UNIFI_BASE_URL` | UniFi controller URL | Required |
| `UNIFI_API_KEY` | API key from UniFi controller | Required |
| `UNIFI_SKIP_SSL_VERIFY` | Skip SSL certificate verification | false |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | info |

## Usage with Claude/Copilot

When using this MCP with Claude or GitHub Copilot:

```
<mcp_server>
  <name>unifi-network-mcp</name>
  <command>./path/to/bin/unifi-network-mcp</command>
</mcp_server>
```

Then request network management tasks:
- "Create a guest WiFi network with 24-hour vouchers"
- "List all clients connected to the main WiFi network"
- "Set up a firewall rule blocking port 8080"
- "Get traffic statistics for my network"

For detailed AI assistant guidance, see [.github/copilot-instructions.md](.github/copilot-instructions.md).

## Docker Support

This project uses Harbor (`harbor.dataknife.net`) as the container registry.

### Build Docker Image

```bash
# Build image for Harbor
make docker-build

# Or manually
docker build -t harbor.dataknife.net/library/unifi-network-mcp:latest .
```

### Push to Harbor

```bash
# Login to Harbor (robot account)
docker login harbor.dataknife.net \
  -u '<HARBOR_USERNAME>' \
  -p '<HARBOR_PASSWORD>'

# Push image
make docker-push

# Or manually
docker push harbor.dataknife.net/library/unifi-network-mcp:latest
```

### Run with Docker

```bash
# Pull from Harbor first
docker pull harbor.dataknife.net/library/unifi-network-mcp:latest

# Run container
docker run -e UNIFI_API_KEY=your-key -e UNIFI_BASE_URL=https://your-url \
  harbor.dataknife.net/library/unifi-network-mcp:latest
```

### Docker Compose

```bash
# Create .env file with your configuration
cp .env.example .env
# Edit .env with your UniFi credentials

# Login to Harbor (if not already logged in)
# Replace <HARBOR_USERNAME> and <HARBOR_PASSWORD> with your actual credentials
docker login harbor.dataknife.net \
  -u '<HARBOR_USERNAME>' \
  -p '<HARBOR_PASSWORD>'

# Start the service (pulls from Harbor)
docker-compose up -d

# View logs
docker-compose logs -f
```

## GitHub Actions & CI/CD

This project includes automated workflows:

- **Tests**: Runs on every push and pull request
- **Docker Build**: Validates Dockerfile builds
- **Release**: Creates multi-platform binaries (Linux, macOS, Windows)
- **Auto-assign**: Assigns PRs to authors

See [.github/workflows](.github/workflows) for details.

## Skills & Capabilities

This MCP implements the following domain-specific skills:

- **Device Management**: Device adoption, inventory, and monitoring
- **Infrastructure Reporting**: Health reports, performance analysis, capacity planning
- **Network Monitoring**: Site health, device status, diagnostics
- **Security Management**: Firewall zones, ACL rules, hotspot management
- **Traffic Analysis**: DPI classification, bandwidth analysis, QoS optimization
- **WiFi Management**: Network optimization, client analysis, band distribution

See [.github/skills](.github/skills) for detailed skill documentation.

## Development

### Building from Source

```bash
make build
```

### Running Tests

```bash
make test
```

### Cleaning Build Artifacts

```bash
make clean
```

## API Reference

For detailed API documentation, see [docs/API_REFERENCE.md](docs/API_REFERENCE.md).

## Project Structure

```
unifi-network-mcp/
├── cmd/
│   └── main.go              # Entry point and signal handling
├── internal/
│   ├── mcp/
│   │   └── server.go        # 27 MCP tool definitions and handlers
│   └── unifi/
│       ├── network.go       # Network API client
│       ├── protect.go       # Protect API client (shared package)
│       ├── doc.go           # Package documentation
│       └── client_test.go   # Integration tests
├── docs/
│   ├── API_REFERENCE.md     # Detailed API documentation
│   ├── GETTING_STARTED.md   # Setup guide
│   └── EXAMPLES.md          # Tool usage examples
├── bin/
│   └── unifi-network-mcp    # Compiled binary
├── go.mod                   # Go module definition
├── go.sum                   # Dependency lock file
├── Makefile                 # Build and development tasks
└── .env.example             # Configuration template
```

## Development

### Building from Source

```bash
make build
```

### Running Tests

```bash
make test
```

### Cleaning Build Artifacts

```bash
make clean
```

## API Reference

For detailed API documentation, see [docs/API_REFERENCE.md](docs/API_REFERENCE.md).

For usage examples with specific tools, see [docs/EXAMPLES.md](docs/EXAMPLES.md).

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues and solutions.

## Requirements

- Go 1.23.2 or later
- UniFi Controller 7.x or later with API access enabled

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please ensure:
- Code follows Go conventions
- All tests pass (`make test`)
- Changes are documented

## Related Projects

- **unifi-protect-mcp**: MCP server for UniFi Protect (cameras, sensors, events)
- **UniFi Controller**: Official UniFi management software

---

**Built with Claude Haiku 4.5** - Crafted by AI to extend your infrastructure possibilities. 🤖✨

---

**Version:** 0.1.0 | **Last Updated:** December 2025
