# Network Tools MCP

A Model Context Protocol implementation providing network diagnostics and scanning tools.

## Tools Provided

- **nmap_scan**: Network scanning with port and service detection
- **dns_lookup**: Basic DNS queries for various record types
- **dns_enum**: Comprehensive DNS enumeration including subdomains
- **whois_info**: Basic domain registration information
- **traceroute**: Path tracing to a target host
- **port_check**: Check if a specific port is open on a host
- **ssl_scan**: SSL/TLS configuration and vulnerability analysis
- **network_scan**: Scan IP ranges for active hosts
- **ip_geolocation**: Get geographical information for an IP address
- **http_headers**: Analyze security headers of a website
- **my_public_ip**: Check your own public IP address and get detailed information

## Installation

### Standard Installation

```bash
# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Docker Installation

You can also run the application using Docker:

```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

## Running the MCP Server

### Using stdio transport (default)

```bash
python nettools_mcp.py
```

### Using SSE transport

```bash
python nettools_mcp.py --transport sse --port 8000
```

## Example Client Usage

Here's a basic client example using stdio transport:

```python
import asyncio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def main():
    async with stdio_client(
        StdioServerParameters(command="python", args=["nettools_mcp.py"])
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Available tools:", tools)

            # Run a DNS lookup
            result = await session.call_tool("dns_lookup", {"domain": "example.com", "record_type": "A"})
            print("DNS Lookup result:", result)

            # Check if port 80 is open
            result = await session.call_tool("port_check", {"host": "example.com", "port": 80})
            print("Port check result:", result)

asyncio.run(main())
```

## Setup with Claude

This MCP server is designed to be used with Claude or other AI assistants that support the Model Context Protocol.

## Docker Notes

- The Docker setup includes all necessary system dependencies
- Docker container runs with privileged mode to allow full network scanning capabilities
- Using Docker is the recommended way to run the server, as it ensures all dependencies are properly installed

## Security Notes

- Ensure you have proper authorization to scan networks and hosts
- Some tools may require root/administrator privileges to function correctly
- The nmap_scan and network_scan tools are wrappers around python-nmap, which itself requires the nmap executable to be installed
- The Docker container runs in privileged mode, which gives it extensive access to the host system - only use in trusted environments
- For production use, consider limiting the network capabilities in the docker-compose.yml file

## Troubleshooting

- If network tools don't work in Docker, try uncommenting the `network_mode: "host"` line in docker-compose.yml
- Some network scanning features may be limited based on your network environment and permissions
- For geolocation features, ensure your container has internet access