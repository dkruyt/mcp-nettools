#!/usr/bin/env python3
import asyncio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def main():
    async with stdio_client(
        StdioServerParameters(command="python", args=["-m", "mcp_nettools.cli"])
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("\nAvailable tools:")
            for tool in tools:
                print(f"- {tool}")

            # Example: DNS lookup
            print("\n--- DNS Lookup Example ---")
            result = await session.call_tool("dns_lookup", {"domain": "example.com", "record_type": "A"})
            print(f"DNS Lookup result for example.com (A record):")
            print(result)
            
            # Example: Invalid DNS lookup
            print("\n--- Invalid DNS Lookup Example ---")
            result = await session.call_tool("dns_lookup", {"domain": "192.168.1.1", "record_type": "A"})
            print(f"Invalid DNS Lookup result for 192.168.1.1 (A record):")
            print(result)

            # Example: Check if port 80 is open
            print("\n--- Port Check Example ---")
            result = await session.call_tool("port_check", {"host": "example.com", "port": 80})
            print(f"Port check result for example.com:80:")
            print(result)
            
            # Example: Invalid port check
            print("\n--- Invalid Port Check Example ---")
            result = await session.call_tool("port_check", {"host": "example.com", "port": 99999})
            print(f"Invalid port check result for example.com:99999:")
            print(result)

            # Example: WHOIS lookup
            print("\n--- WHOIS Info Example ---")
            result = await session.call_tool("whois_info", {"domain": "example.com"})
            print(f"WHOIS information for example.com (partial):")
            # Print a subset of the results to keep output manageable
            for key in ['domain_name', 'registrar', 'creation_date', 'expiration_date']:
                if key in result:
                    print(f"  {key}: {result[key]}")
                    
            # Example: DNS enumeration 
            print("\n--- DNS Enumeration Example ---")
            result = await session.call_tool("dns_enum", {"domain": "example.com", "record_types": ["A", "MX", "TXT"]})
            print(f"DNS enumeration for example.com:")
            if "error" in result:
                print(f"  Error: {result['error']}")
            else:
                print("  DNS Records:")
                for record_type, records in result.get("records", {}).items():
                    print(f"    {record_type}: {len(records)} records found")
                print(f"  Nameservers: {', '.join(result.get('nameservers', []))}")
                if result.get("subdomains"):
                    print(f"  Subdomains found: {', '.join(result.get('subdomains', []))}")
            
            # Example: Network scan (commented out for safety)
            # print("\n--- Network Scan Example ---")
            # result = await session.call_tool("network_scan", {"network": "192.168.1.0/24", "timeout": 1})
            # print(f"Network scan results:")
            # if "error" in result:
            #     print(f"  Error: {result['error']}")
            # else:
            #     print(f"  Network: {result.get('network')}")
            #     print(f"  Active hosts: {result.get('active_hosts')} out of {result.get('total_hosts')}")
            #     print("  Host list:")
            #     for host in result.get("hosts", [])[:5]:  # Show only first 5 hosts
            #         print(f"    {host.get('ip')} {host.get('hostname', '')}")
            #     if len(result.get("hosts", [])) > 5:
            #         print(f"    ... and {len(result.get('hosts', [])) - 5} more")
            
            # Example: IP Geolocation
            print("\n--- IP Geolocation Example ---")
            result = await session.call_tool("ip_geolocation", {"ip": "8.8.8.8"})  # Google's public DNS
            print(f"Geolocation for 8.8.8.8:")
            if "error" in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Country: {result.get('country')} ({result.get('country_code')})")
                print(f"  City: {result.get('city')}, {result.get('region')}")
                print(f"  ISP: {result.get('isp')}")
                print(f"  Latitude/Longitude: {result.get('latitude')}, {result.get('longitude')}")
            
            # Example: HTTP Headers Analyzer
            print("\n--- HTTP Headers Analysis Example ---")
            result = await session.call_tool("http_headers", {"url": "example.com"})
            print(f"HTTP headers for example.com:")
            if "error" in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  Status code: {result.get('status_code')}")
                print(f"  HTTPS: {'Yes' if result.get('https') else 'No'}")
                print("  Security headers present:")
                for header, details in result.get('security_headers', {}).items():
                    if details.get('present'):
                        print(f"    {header}")
            
            # Example: Check My Public IP
            print("\n--- My Public IP Example ---")
            result = await session.call_tool("my_public_ip", {})
            print("Your public IP information:")
            if "error" in result:
                print(f"  Error: {result['error']}")
            else:
                print(f"  IP: {result.get('ip')} ({result.get('type')})")
                print(f"  Location: {result.get('city')}, {result.get('region')}, {result.get('country', {}).get('name')} ({result.get('country', {}).get('code')})")
                print(f"  Coordinates: {result.get('location', {}).get('latitude')}, {result.get('location', {}).get('longitude')}")
                print(f"  Network: {result.get('asn', {}).get('name')} (AS{result.get('asn', {}).get('number')})")
            
            # Example: SSL scan (disabled by default - can be slow)
            # print("\n--- SSL Scan Example ---")
            # # Basic scan with all checks
            # result = await session.call_tool("ssl_scan", {"target": "example.com"})
            # print(f"SSL scan result for example.com:443 (partial):")
            # if "error" in result:
            #     print(f"  Error: {result['error']}")
            # else:
            #     print(f"  Scan time: {result.get('scan_time', 'N/A')}")
            #     print(f"  Certificate subject: {result.get('certificate', {}).get('subject', 'N/A')}")
            #     print(f"  Protocol information:")
            #     for protocol, details in result.get("protocols", {}).items():
            #         print(f"    {protocol}: {details.get('supported', False)}")
            #     print(f"  Vulnerabilities:")
            #     for vuln, details in result.get("vulnerabilities", {}).items():
            #         print(f"    {vuln}: {details}")
            
            # # Custom scan with only certificate check
            # result = await session.call_tool("ssl_scan", {
            #     "target": "example.com", 
            #     "port": 443, 
            #     "check_certificate": True,
            #     "check_vulnerabilities": False
            # })

if __name__ == "__main__":
    asyncio.run(main())