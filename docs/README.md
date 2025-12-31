# UniFi MCP Server Documentation

Complete documentation for the UniFi Model Context Protocol (MCP) Server.

## Documentation Index

### Getting Started
- **[Getting Started Guide](./GETTING_STARTED.md)** - Complete setup and initial configuration
- **[Capabilities Guide](./CAPABILITIES.md)** - What the server can do

### Learning
- **[Copilot Integration](./COPILOT_GUIDE.md)** - How to use with Claude/Copilot
- **[API Reference](./API_REFERENCE.md)** - Complete API documentation with all 26 tools, status, and implementation details
- **[Best Practices](./BEST_PRACTICES.md)** - Tips and recommendations

### Using the Server
- **[Usage Examples](./EXAMPLES.md)** - Real-world examples
- **[Troubleshooting](./TROUBLESHOOTING.md)** - Common issues and solutions
- **[VS Code Integration](./VS_CODE_INTEGRATION.md)** - Using with VS Code

### Maintenance
- **[Deployment](./DEPLOYMENT.md)** - Production deployment guide
- **[GitHub Actions](./GITHUB_ACTIONS.md)** - CI/CD workflows

---

## Quick Navigation

### I want to...

**...get started quickly**
→ Start with [Getting Started Guide](./GETTING_STARTED.md)

**...understand what tools are available**
→ See [Capabilities Guide](./CAPABILITIES.md) or [API Reference](./API_REFERENCE.md)

**...use it with Claude/Copilot**
→ Read [Copilot Integration](./COPILOT_GUIDE.md)

**...see complete API documentation and implementation status**
→ Check [API Reference](./API_REFERENCE.md)

**...fix an issue**
→ Try [Troubleshooting](./TROUBLESHOOTING.md)

**...see examples**
→ Browse [Usage Examples](./EXAMPLES.md)

**...deploy to production**
→ Follow [Deployment Guide](./DEPLOYMENT.md)

---

## Features Overview

### Protect API (Surveillance)
- 🎥 List all cameras and their status
- 📹 View recent events and recordings
- 📊 Monitor storage and system health
- 🔔 Get alert information

### Network API (Management)
- 🌐 Monitor sites and devices
- 📡 Manage WiFi networks
- 👥 Track connected clients
- 🔐 Control firewall and access rules
- 📊 Analyze network traffic
- 🔧 Manage devices and adoption

### Total: 26 Tools
All designed to work seamlessly with Claude/Copilot

---

## Key Concepts

### What is MCP?

The Model Context Protocol (MCP) allows Claude to:
- Access your UniFi network information
- Call UniFi API endpoints
- Get real-time network status
- Manage and monitor your infrastructure

### How It Works

```
You ↔ Claude/Copilot ↔ MCP Server ↔ UniFi Controller
         (asks)            (tools)       (API calls)
```

### Authentication

- Uses API Keys from your UniFi controller
- Secure stdio-based communication
- No external servers or cloud connectivity

---

## System Requirements

### Minimum
- **Go** 1.21+
- **UniFi Controller** 8.0+
- **Python** 3.8+ (for some utilities)

### Network
- Access to UniFi controller (HTTP/HTTPS)
- Port 443 or 8443 (typical UniFi ports)

### Credentials
- UniFi API Key (generated in controller)
- Controller base URL

---

## Table of Contents

### Setup & Installation
1. [System Requirements](#system-requirements)
2. [Installation Options](./SETUP.md#installation)
3. [Configuration Guide](./SETUP.md#configuration)
4. [Verification Steps](./SETUP.md#verification)

### Learning & Understanding
1. [Understanding MCP](#what-is-mcp)
2. [Feature Overview](#features-overview)
3. [Available Tools](./CAPABILITIES.md)
4. [API Endpoints](./API_REFERENCE.md)

### Using the Server
1. [Copilot Integration](./COPILOT_GUIDE.md)
2. [Common Tasks](./COPILOT_GUIDE.md#common-tasks)
3. [Advanced Queries](./COPILOT_GUIDE.md#advanced-queries)
4. [Examples](./EXAMPLES.md)

### Troubleshooting
1. [Quick Diagnosis](./TROUBLESHOOTING.md#quick-diagnosis)
2. [Common Issues](./TROUBLESHOOTING.md#common-issues--solutions)
3. [Debug Techniques](./TROUBLESHOOTING.md#debugging-techniques)

### Operations
1. [Deployment Options](./DEPLOYMENT.md)
2. [Production Setup](./DEPLOYMENT.md)
3. [Monitoring](./DEPLOYMENT.md)
4. [Architecture](./ARCHITECTURE.md)

---

## Quick Links

### Important Files
- Main Server: [`cmd/main.go`](../cmd/main.go)
- MCP Implementation: [`internal/mcp/server.go`](../internal/mcp/server.go)
- Network Client: [`internal/unifi/network.go`](../internal/unifi/network.go)
- Protect Client: [`internal/unifi/protect.go`](../internal/unifi/protect.go)

### Configuration
- Environment: `.env` (see [Setup](./SETUP.md))
- Docker: `docker-compose.yml`
- Build: `Makefile`

### Testing
- Unit Tests: `tests/` directory
- Integration Tests: Check individual test files
- Manual Testing: Use curl examples in docs

---

## Common Commands

### Start Server
```bash
go run cmd/main.go
```

### Debug Mode
```bash
LOG_LEVEL=debug go run cmd/main.go
```

### Build Binary
```bash
go build -o unifi-mcp cmd/main.go
```

### Run Tests
```bash
go test ./...
```

### Docker
```bash
docker build -t unifi-mcp .
docker run -e UNIFI_API_KEY=key -e UNIFI_BASE_URL=url unifi-mcp
```

---

## Documentation Standards

All documentation follows these conventions:

### Code Examples
- Bash: Unix/Linux shell syntax
- Go: Latest Go conventions
- JSON: Pretty-printed with comments
- URLs: Use example domains

### Icons
- 🌐 Network/Web related
- 📡 Wireless/Connectivity
- 🔐 Security/Access control
- 📊 Monitoring/Stats
- 🔧 Configuration/Setup
- ❌ Errors/Problems
- ✅ Success/Working
- ⚠️ Warnings
- 💡 Tips/Best practices

### Sections
Each guide follows this structure:
1. Quick overview
2. Prerequisites
3. Step-by-step instructions
4. Verification
5. Troubleshooting
6. Next steps

---

## Getting Help

### Before asking for help:

1. ✅ Read the relevant documentation section
2. ✅ Check [Troubleshooting Guide](./TROUBLESHOOTING.md)
3. ✅ Enable debug logging
4. ✅ Test with curl directly
5. ✅ Review error messages carefully

### When asking for help, provide:

1. Error message (full text)
2. Your configuration (without secrets)
3. Debug logs (5-10 lines of context)
4. What you were trying to do
5. What you expected to happen

### Resources

- UniFi Documentation: https://help.ubnt.com
- Go Documentation: https://golang.org/doc
- MCP Specification: Check official docs
- GitHub Issues: Open an issue with details

---

## Document Index

| Document | Purpose | Audience |
|----------|---------|----------|
| [SETUP.md](./SETUP.md) | Installation & configuration | New users, DevOps |
| [QUICK_START.md](./QUICK_START.md) | Fast 5-min setup | Experienced users |
| [CAPABILITIES.md](./CAPABILITIES.md) | Feature overview & skills | All users |
| [COPILOT_GUIDE.md](./COPILOT_GUIDE.md) | Using with Claude | End users |
| [API_REFERENCE.md](./API_REFERENCE.md) | API endpoint details | Developers |
| [EXAMPLES.md](./EXAMPLES.md) | Real-world usage | All users |
| [BEST_PRACTICES.md](./BEST_PRACTICES.md) | Tips & recommendations | Experienced users |
| [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) | Problem solving | All users |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Production deployment | DevOps, operators |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System design | Developers, maintainers |

---

## Contribution Guidelines

Want to improve documentation?

1. **Fix typos**: Just submit the correction
2. **Add examples**: Include code and explanation
3. **Improve clarity**: Reorganize for better flow
4. **Add sections**: Cover gaps in documentation
5. **Update API docs**: Keep in sync with code changes

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for details.

---

## Document Updates

Documentation is maintained for:
- **Latest Release**: Current stable version
- **Main Branch**: Latest development version
- **Breaking Changes**: Clearly marked with ⚠️

Check the git history for older versions:
```bash
git log --follow docs/
```

---

## License

All documentation is provided under the same license as the code.
See [`LICENSE`](../LICENSE) for details.

---

## Quick Reference

### Essential URLs/Ports
- UniFi Web UI: `https://controller-ip:8443`
- API Endpoint: `https://controller-ip/proxy/network/integration/v1`

### Default Values
- Base URL: `https://192.168.1.1`
- Log Level: `info`
- Request Timeout: `30` seconds
- Default Site: `default`

### Common Tools (Quick Access)
- Sites: `get_network_sites`
- Devices: `get_network_devices`
- Clients: `get_network_clients`
- Health: `get_site_health`
- WiFi: `get_wifi_networks`
- Security: `get_firewall_zones`, `get_acl_rules`
- Cameras: `get_protect_devices`

---

**Last Updated**: 2024
**Version**: 1.0
**Status**: Complete ✅
