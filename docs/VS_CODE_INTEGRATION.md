# VS Code & Chat Tool Integration Guide

This guide shows how to connect the Unifi MCP Server to VS Code, Claude, ChatGPT, and other tools.

## Overview

The Unifi MCP Server uses the Model Context Protocol (MCP) to expose 28 tools for managing Unifi infrastructure. Once configured, you can use these tools through:

- **VS Code with Copilot** - Direct integration via MCP server configuration
- **Claude (Claude.ai & API)** - Via Codebase Context or direct MCP server setup
- **ChatGPT** - Via OpenAI's custom GPT with API integration
- **Other LLMs** - Any tool supporting MCP protocol

---

## Part 1: Running the MCP Server

Before connecting to any tool, ensure the server is running:

### Prerequisites
- Go 1.23.2 or Docker
- Unifi API key (X-API-KEY header)
- Unifi controller base URL

### Setup

```bash
# Clone and setup
git clone https://github.com/yourusername/unifi-mcp.git
cd unifi-mcp

# Configure
cp .env.example .env
# Edit .env with your API key and base URL
# UNIFI_API_KEY=your-api-key-here
# UNIFI_BASE_URL=https://your-controller:443

# Build
go build -o bin/unifi-mcp ./cmd

# Run the server
./bin/unifi-mcp
```

The server will start on **stdio transport** (reads from stdin, writes to stdout), which is ideal for tool integrations.

### Docker Alternative

```bash
docker build -t unifi-mcp:latest .

docker run -it \
  -e UNIFI_API_KEY="your-api-key" \
  -e UNIFI_BASE_URL="https://your-controller:443" \
  unifi-mcp:latest
```

---

## Part 2: VS Code & GitHub Copilot

### Step 1: Install Copilot Extension
1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "GitHub Copilot"
4. Install the official extension
5. Sign in with your GitHub account

### Step 2: Configure MCP Server

Create or edit `.vscode/settings.json` in your workspace:

```json
{
  "claude.mcpServers": {
    "unifi-mcp": {
      "command": "/home/lee/git/unifi-mcp/bin/unifi-mcp",
      "args": [],
      "env": {
        "UNIFI_API_KEY": "your-api-key-here",
        "UNIFI_BASE_URL": "https://your-controller:443",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

Or for global VS Code settings (`~/.config/Code/User/settings.json` on Linux):

```json
{
  "claude.mcpServers": {
    "unifi-mcp": {
      "command": "/absolute/path/to/unifi-mcp/bin/unifi-mcp",
      "env": {
        "UNIFI_API_KEY": "your-api-key",
        "UNIFI_BASE_URL": "https://your-controller:443"
      }
    }
  }
}
```

### Step 3: Use in VS Code

1. Open Copilot Chat (Ctrl+Shift+I / Cmd+Shift+I)
2. In the chat prompt, type `@unifi` to reference Unifi context
3. Ask questions about your Unifi infrastructure:

```
@unifi What devices are connected to my network?
@unifi Show me all cameras in my Protect system
@unifi List clients connected to WiFi networks
```

### Example Queries

```
@unifi Get all sites and their health status
@unifi What is the current storage usage on Protect?
@unifi List all pending devices waiting for adoption
@unifi Get VPN server configurations for my default site
```

---

## Part 3: Claude.ai / Claude API

### Option A: Claude.ai (Browser)

1. Visit [claude.ai](https://claude.ai)
2. Start a new conversation
3. Click **Attach** button or use `@` symbol
4. If your organization has MCP configured, you can reference external tools
5. Ask Claude about your Unifi infrastructure

**Note:** Individual claude.ai users cannot add custom MCP servers. This feature is available for Claude.ai Plus with workspace configurations.

### Option B: Claude API with MCP

Use the [Claude Python SDK](https://github.com/anthropic-ai/anthropic-sdk-python) with MCP:

```python
import anthropic
import subprocess
import json

# Start the MCP server as a subprocess
server = subprocess.Popen(
    ["/path/to/unifi-mcp/bin/unifi-mcp"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env={
        "UNIFI_API_KEY": "your-api-key",
        "UNIFI_BASE_URL": "https://your-controller:443"
    }
)

# Initialize Anthropic client
client = anthropic.Anthropic(api_key="your-claude-api-key")

# Send a message with MCP tools
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    tools=[
        {
            "type": "mcp",
            "name": "unifi-mcp",
            "description": "Unifi Network and Protect management tools",
            "server": {
                "command": "/path/to/unifi-mcp/bin/unifi-mcp",
                "env": {
                    "UNIFI_API_KEY": "your-api-key",
                    "UNIFI_BASE_URL": "https://your-controller:443"
                }
            }
        }
    ],
    messages=[
        {
            "role": "user",
            "content": "What devices are currently connected to my network?"
        }
    ]
)

print(response.content)
```

### Option C: Claude Codebase Context

For VS Code with Claude extension:

1. Install [Claude for VS Code](https://marketplace.visualstudio.com/items?itemName=anthropic-labs.claude-vsx)
2. Configure MCP server same as Step 2 above
3. Open Claude's chat panel
4. Reference your codebase context with `@workspace`

---

## Part 4: ChatGPT / Custom GPT

### Using OpenAI Custom GPT with API

**Note:** OpenAI's Custom GPT doesn't natively support MCP protocol. Instead, create an API wrapper.

### Step 1: Create an API Wrapper

Create a simple HTTP server that wraps the MCP server:

```bash
# Example using Node.js with Express
npm install express axios dotenv

cat > api-wrapper.js << 'EOF'
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.json());

app.post('/tools/:toolName', async (req, res) => {
  const { toolName } = req.params;
  const args = req.body;
  
  // Call the MCP server tool
  // Implementation depends on your tool requirements
  
  res.json({
    tool: toolName,
    result: "Tool execution result"
  });
});

app.listen(3000, () => {
  console.log('API wrapper running on port 3000');
});
EOF
```

### Step 2: Deploy API

Deploy your wrapper to a public URL:

- **Heroku**: `heroku create && git push heroku main`
- **Vercel**: `vercel deploy`
- **AWS Lambda**: Create a function and API Gateway
- **Self-hosted**: Use Docker on your server

### Step 3: Create Custom GPT

1. Go to [ChatGPT](https://chat.openai.com)
2. Click **Explore** > **Create a GPT**
3. Name: "Unifi Network Manager"
4. Description: "Manages Unifi Network and Protect systems"
5. In **Actions**, add your API:
   - **Authentication**: API Key (from your wrapper)
   - **Schema**: OpenAPI 3.0 spec describing your tools

6. Save and use the custom GPT

### Example API Schema for ChatGPT

```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "Unifi MCP API",
    "version": "1.0.0"
  },
  "paths": {
    "/api/tools/get_network_sites": {
      "post": {
        "summary": "Get all sites from Unifi Network",
        "operationId": "getNetworkSites",
        "responses": {
          "200": {
            "description": "List of sites"
          }
        }
      }
    },
    "/api/tools/get_network_devices": {
      "post": {
        "summary": "Get devices from a site",
        "operationId": "getNetworkDevices",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "site_id": { "type": "string" }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

---

## Part 5: Other LLMs and Tools

### Ollama (Local LLM)

```bash
# Install Ollama and pull a model
ollama pull mistral

# Run MCP server in one terminal
./bin/unifi-mcp

# In another terminal, create a Python script
cat > ollama-client.py << 'EOF'
import ollama
import json
import subprocess

def get_tool_result(tool_name, args):
    # Call MCP server tool
    # Implementation details...
    pass

response = ollama.chat(
  model='mistral',
  messages=[
    {
      'role': 'user',
      'content': 'List the devices on my network'
    }
  ]
)

print(response['message']['content'])
EOF

python3 ollama-client.py
```

### LangChain Integration

```python
from langchain.tools import Tool
from langchain_community.tools import OpenWeatherMapQueryRun
from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI

# Define Unifi tools
def get_network_sites():
    # Call MCP server
    pass

tools = [
    Tool(
        name="get_network_sites",
        func=get_network_sites,
        description="Get all Unifi Network sites"
    ),
    # Add more tools...
]

llm = ChatOpenAI(model="gpt-4")
agent = create_react_agent(llm, tools)
executor = AgentExecutor.run_tool(agent, tools)

# Execute
result = executor.invoke({
    "input": "Show me all connected devices"
})
print(result)
```

### Zapier/Make.com Integration

1. Create a webhook endpoint for your MCP server
2. Add as a custom action in Zapier
3. Use in automation workflows

---

## Troubleshooting

### MCP Server Not Connecting

**Problem**: "Server not found" or "Connection refused"

**Solutions**:
1. Verify server is running: `./bin/unifi-mcp`
2. Check environment variables are set
3. Verify API key has permissions
4. Check logs: `LOG_LEVEL=debug ./bin/unifi-mcp`

### Tools Not Appearing in Chat

**Problem**: Tools available but not showing in chat

**Solutions**:
1. Restart the tool/editor
2. Check MCP server is logging "Registered N tools"
3. Verify tool names and descriptions in code
4. Check for firewall/antivirus blocking

### API Authentication Failures

**Problem**: "401 Unauthorized" or "Authentication failed"

**Solutions**:
1. Verify API key is correct
2. Confirm API key is active in Unifi console
3. Check controller URL includes protocol and port
4. Test directly: `curl -k -H "X-API-KEY: your-key" https://controller/api/v1/cameras`

### Performance Issues

**Problem**: Tools are slow to respond

**Solutions**:
1. Check network latency to controller
2. Monitor API rate limits
3. Reduce default pagination limits
4. Check controller CPU/memory usage

---

## Security Best Practices

1. **Never commit credentials**: Use `.env` files and `.gitignore`
2. **Use HTTPS only**: Always verify controller certificates
3. **Secure your API key**: Rotate regularly, use strong values
4. **Network isolation**: Run MCP server in isolated network when possible
5. **Monitor access**: Enable controller audit logging
6. **Limit scope**: Create read-only API keys when possible

---

## Next Steps

- Read [API_REFERENCE.md](./API_REFERENCE.md) for complete tool documentation
- Check [BEST_PRACTICES.md](./BEST_PRACTICES.md) for usage patterns
- See [EXAMPLES.md](./EXAMPLES.md) for real-world scenarios
- Review [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for common issues

