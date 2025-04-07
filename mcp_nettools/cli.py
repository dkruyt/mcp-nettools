#!/usr/bin/env python3
"""
CLI entry point for MCP Network Tools server.
"""
import sys
from .server import mcp


def main():
    """Run the MCP server with the specified transport."""
    # Default to stdio transport
    transport = "stdio"
    port = 8000
    
    # Parse command line args
    for i, arg in enumerate(sys.argv[1:]):
        if arg == "--transport" and i+2 <= len(sys.argv[1:]):
            transport = sys.argv[i+2]
        elif arg == "--port" and i+2 <= len(sys.argv[1:]):
            port = int(sys.argv[i+2])
    
    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "sse":
        # Set port in settings before running
        mcp.settings.port = port
        mcp.run(transport="sse")
    else:
        print(f"Unknown transport: {transport}")
        sys.exit(1)


if __name__ == "__main__":
    main()