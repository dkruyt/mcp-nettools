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

## 📦 Installation

### Installing Manually

Install using uv:

```bash
uv tool install https://github.com/dkruyt/mcp-nettools.git
```

For development:

```bash
# Clone and set up development environment
git clone https://github.com/dkruyt/mcp-nettools.git
cd mcp-nettools

# Create and activate virtual environment
uv venv
source .venv/bin/activate

# Install with test dependencies
uv pip install -e ".[dev]"
```

## 🔌 MCP Integration

Add this configuration to your MCP client config file:

```json
{
    "mcpServers": {
        "mcp-nettools": {
            "command": "uv",
            "args": [
                "tool",
                "run",
                "mcp-nettools"
            ]
        }
    }
}
```

For Development:

```json
{
    "mcpServers": {
        "mcp-nettools": {
            "command": "uv",
            "args": [
                "--directory",
                "path/to/cloned/mcp-nettools",
                "run",
                "mcp-nettools"
            ]
        }
    }
}
```

## Running the Server

### Using stdio transport (default)

```bash
# Using uv
uv run mcp-nettools

# Using Python directly
python -m mcp_nettools.cli
```

### Using SSE transport

```bash
# Using uv
uv run mcp-nettools --transport sse --port 8000

# Using Python directly
python -m mcp_nettools.cli --transport sse --port 8000
```

You should see output similar to:
```
INFO:     Started server process [28048]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

## 🔧 Usage Examples

### Network Scanning

```python
# Basic scan
result = await session.call_tool("nmap_scan", {"host": "example.com"})

# Port-specific scan
result = await session.call_tool("nmap_scan", {
    "host": "example.com",
    "ports": "80,443,8080"
})

# Scan with specific arguments
result = await session.call_tool("nmap_scan", {
    "host": "example.com",
    "arguments": "-sV -sS -T4"
})
```

### DNS Queries

```python
# Basic A record lookup
result = await session.call_tool("dns_lookup", {
    "domain": "example.com",
    "record_type": "A"
})

# MX record lookup
result = await session.call_tool("dns_lookup", {
    "domain": "example.com",
    "record_type": "MX"
})

# Comprehensive DNS enumeration
result = await session.call_tool("dns_enum", {
    "domain": "example.com",
    "record_types": ["A", "AAAA", "MX", "TXT", "NS"]
})
```

### Security Analysis

```python
# Check HTTP headers
result = await session.call_tool("http_headers", {
    "url": "https://example.com"
})

# SSL/TLS scan
result = await session.call_tool("ssl_scan", {
    "target": "example.com"
})

# Customized SSL scan
result = await session.call_tool("ssl_scan", {
    "target": "example.com",
    "port": 443,
    "check_vulnerabilities": True,
    "check_certificate": True
})
```

## ⚠️ Security Notes

- Ensure you have proper authorization to scan networks and hosts
- Some tools may require root/administrator privileges to function correctly
- The nmap_scan and network_scan tools require the nmap executable to be installed
- For production use, consider limiting the network capabilities

## 🛠️ Development

### Running Tests

```bash
# Install development dependencies
pip install ".[dev]"

# Run tests
pytest
```

### Building the Package

```bash
# Install build tools
pip install build

# Build the package
python -m build
```

## ❓ Troubleshooting

- Some network scanning features may be limited based on your network environment and permissions
- For geolocation features, ensure your system has internet access
- If you encounter "Permission denied" errors with nmap or other tools, make sure you're running with appropriate privileges
- SSL scanning can be slow; if you need only certificate information, set `check_vulnerabilities=False` in the options
- If you encounter import errors, make sure all dependencies are installed