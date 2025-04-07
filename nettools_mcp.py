#!/usr/bin/env python3
from typing import Dict, List, Optional, Union, Any
import datetime
from pydantic import BaseModel, Field
import nmap
import dns.resolver
import whois
import socket
import subprocess
import sslyze
import re
import ipaddress
import requests
import concurrent.futures
from urllib.parse import urlparse
from sslyze.scanner.scanner import Scanner
from sslyze.scanner.models import ServerScanRequest
from sslyze.server_setting import ServerNetworkLocation
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.errors import ConnectionToServerFailed
from mcp.server.fastmcp import FastMCP

# Define Pydantic models for tool options
class SSLScanOptions(BaseModel):
    target: str = Field(..., description="Target hostname or IP address to scan")
    port: int = Field(443, description="Port to connect to for the SSL scan")
    check_vulnerabilities: bool = Field(True, description="Check for common SSL/TLS vulnerabilities")
    check_certificate: bool = Field(True, description="Analyze SSL certificate information")

# Initialize the MCP server
mcp = FastMCP("Network Tools MCP")

# Helper functions for target validation
def is_valid_hostname(hostname):
    """Check if the provided string is a valid hostname."""
    hostname_pattern = re.compile(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
    return bool(hostname_pattern.match(hostname))

def is_valid_ip(ip):
    """Check if the provided string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_target(target):
    """Check if the target is a valid hostname, IP address, or network."""
    if is_valid_hostname(target) or is_valid_ip(target):
        return True
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    return False

@mcp.tool()
def nmap_scan(host: str, ports: Optional[str] = None, arguments: Optional[str] = "-sV") -> Dict:
    """
    Perform a network scan using nmap.
    
    Args:
        host: Target host to scan (IP or hostname)
        ports: Port range to scan (e.g. "22-25,80,443" or "1-1000")
        arguments: Additional nmap arguments (default: "-sV" for service detection)
    
    Returns:
        Dict containing scan results
    """
    # Validate host
    if not is_valid_target(host):
        return {"error": f"Invalid target: {host}"}
        
    nm = nmap.PortScanner()
    
    # Build scan arguments
    args = arguments or "-sV"
    if ports:
        args = f"{args} -p {ports}"
    
    # Run scan
    result = nm.scan(hosts=host, arguments=args)
    
    # Format the output to be more readable
    return {
        "scan_info": result.get("nmap", {}),
        "hosts": result.get("scan", {})
    }

@mcp.tool()
def dns_lookup(domain: str, record_type: str = "A") -> List[Dict]:
    """
    Perform DNS lookups for various record types.
    
    Args:
        domain: Domain name to query
        record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, etc.)
    
    Returns:
        List of records found
    """
    # Validate domain (should be a hostname, not an IP)
    if not is_valid_hostname(domain):
        return [{"error": f"Invalid domain name: {domain}"}]
        
    try:
        answers = dns.resolver.resolve(domain, record_type)
        results = []
        
        for answer in answers:
            if record_type == "MX":
                results.append({
                    "type": record_type,
                    "exchange": str(answer.exchange),
                    "preference": answer.preference
                })
            elif record_type == "SOA":
                results.append({
                    "type": record_type,
                    "mname": str(answer.mname),
                    "rname": str(answer.rname),
                    "serial": answer.serial,
                    "refresh": answer.refresh,
                    "retry": answer.retry,
                    "expire": answer.expire,
                    "minimum": answer.minimum
                })
            else:
                results.append({
                    "type": record_type,
                    "value": str(answer)
                })
        
        return results
    except Exception as e:
        return [{"error": str(e)}]

@mcp.tool()
def whois_info(domain: str) -> Dict:
    """
    Retrieve WHOIS information for a domain.
    
    Args:
        domain: Domain name to query
    
    Returns:
        Dict containing WHOIS information
    """
    # Validate domain (should be a hostname, not an IP)
    if not is_valid_hostname(domain):
        return {"error": f"Invalid domain name: {domain}"}
        
    try:
        w = whois.whois(domain)
        # Convert any datetime objects to strings for JSON serialization
        result = {}
        for key, value in w.items():
            if isinstance(value, list):
                result[key] = [str(item) if hasattr(item, 'strftime') else item for item in value]
            else:
                result[key] = str(value) if hasattr(value, 'strftime') else value
        
        return result
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def traceroute(host: str, max_hops: int = 30, timeout: int = 2) -> List[Dict]:
    """
    Perform a traceroute to a target host.
    
    Args:
        host: Target host (IP or hostname)
        max_hops: Maximum number of hops to trace
        timeout: Timeout in seconds for each probe
    
    Returns:
        List of hops with timing information
    """
    # Validate host
    if not is_valid_target(host):
        return [{"error": f"Invalid target: {host}"}]
        
    # Use different commands based on platform
    import platform
    
    results = []
    
    try:
        if platform.system() == "Windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), host]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), host]
        
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, err = proc.communicate()
        
        # Basic parsing of the output - this is a simplified version
        lines = output.strip().split('\n')
        for line in lines[1:]:  # Skip header line
            if not line.strip():
                continue
                
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    hop_num = int(parts[0].strip())
                    if "*" in line:
                        results.append({
                            "hop": hop_num,
                            "ip": "*",
                            "rtt_ms": None
                        })
                    else:
                        # Extract IP and RTT - this is a simplification that may need adjusting
                        ip = None
                        rtt = None
                        
                        for part in parts:
                            if part.replace(".", "").isdigit() and part.count(".") == 3:
                                ip = part
                            elif part.replace(".", "").isdigit() and "ms" in parts[parts.index(part)+1]:
                                rtt = float(part)
                        
                        results.append({
                            "hop": hop_num,
                            "ip": ip or "*",
                            "rtt_ms": rtt
                        })
                except (ValueError, IndexError):
                    continue
        
        return results
    except Exception as e:
        return [{"error": str(e)}]

@mcp.tool()
def port_check(host: str, port: int, timeout: int = 2) -> Dict:
    """
    Check if a specific port is open on a host.
    
    Args:
        host: Target host (IP or hostname)
        port: Port number to check
        timeout: Connection timeout in seconds
    
    Returns:
        Dict with port status information
    """
    # Validate host
    if not is_valid_target(host):
        return {"error": f"Invalid target: {host}"}
        
    # Validate port range
    if not (1 <= port <= 65535):
        return {"error": f"Invalid port number: {port}. Must be between 1 and 65535"}
        
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_result = s.connect_ex((host, port))
        
        is_open = conn_result == 0
        
        if is_open:
            try:
                # Try to get service name
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
                
            # Basic banner grabbing - not all services will return a banner
            banner = None
            try:
                if port in [21, 22, 25, 80, 110, 143]:  # FTP, SSH, SMTP, HTTP, POP3, IMAP
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n" if port == 80 else b"\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass
                
            result = {
                "host": host,
                "port": port,
                "status": "open",
                "service": service
            }
            if banner:
                result["banner"] = banner
                
            return result
        else:
            return {
                "host": host,
                "port": port,
                "status": "closed"
            }
    except socket.gaierror:
        return {
            "host": host,
            "port": port,
            "status": "error",
            "error": "Could not resolve hostname"
        }
    except socket.error as e:
        return {
            "host": host,
            "port": port,
            "status": "error",
            "error": str(e)
        }
    finally:
        try:
            s.close()
        except:
            pass

@mcp.tool()
def ssl_scan(options: SSLScanOptions) -> Dict[str, Any]:
    """
    Perform an SSL/TLS scan on a server.
    
    This tool analyzes SSL/TLS configuration, certificates, and vulnerabilities
    using the sslyze library.
    
    Examples:
    - Basic scan: {"target": "example.com"}
    - Custom port: {"target": "example.com", "port": 8443}
    - Focused scan: {"target": "example.com", "check_vulnerabilities": true, "check_certificate": false}
    """
    target = options.target
    port = options.port
    
    # Validate target
    if not is_valid_hostname(target) and not is_valid_ip(target):
        return {"error": f"Invalid target: {target}. Must be a valid hostname or IP address."}
    
    try:
        # Set up the server location
        server_location = ServerNetworkLocation(hostname=target, port=port)
        
        # Create the scan request
        scan_commands = []
        
        # Add certificate and configuration checks
        if options.check_certificate:
            scan_commands.append(ScanCommand.CERTIFICATE_INFO)
        
        # Add vulnerability checks
        if options.check_vulnerabilities:
            scan_commands.extend([
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.TLS_COMPRESSION,
                ScanCommand.SESSION_RENEGOTIATION
            ])
        
        # Create the scan request
        server_scan_req = ServerScanRequest(
            server_location=server_location,
            scan_commands=scan_commands
        )
        
        # Create the scanner and queue the scan
        scanner = Scanner()
        scanner.queue_scans([server_scan_req])  # Note: queue_scans takes a list
        
        # Process the results
        result = {
            "target": target,
            "port": port,
            "scan_time": str(datetime.datetime.now().replace(microsecond=0)),
            "certificate": {},
            "vulnerabilities": {},
            "protocols": {}
        }
        
        # Start the scan and retrieve the results
        for server_scan_result in scanner.get_results():
            # Check if the scan was successful
            if server_scan_result.scan_status.name != "COMPLETED":
                result["status"] = f"Scan status: {server_scan_result.scan_status.name}"
                continue
                
            if server_scan_result.scan_result:
                scan_result = server_scan_result.scan_result
                
                # Process certificate info if available
                if options.check_certificate and hasattr(scan_result, "certificate_info"):
                    cert_info = scan_result.certificate_info
                    if cert_info.status.name == "COMPLETED" and cert_info.result:
                        try:
                            cert_res = cert_info.result
                            main_cert = cert_res.certificate_deployments[0].received_certificate_chain[0]
                            
                            result["certificate"] = {
                                "subject": str(main_cert.subject),
                                "issuer": str(main_cert.issuer),
                                "not_valid_before": str(main_cert.not_valid_before_utc),
                                "not_valid_after": str(main_cert.not_valid_after_utc),
                                "serial_number": hex(main_cert.serial_number)[2:]
                            }
                            
                            # Handle public key info safely
                            try:
                                result["certificate"]["public_key_type"] = main_cert.public_key.__class__.__name__
                                if hasattr(main_cert, "public_key_size_in_bits"):
                                    result["certificate"]["public_key_size"] = main_cert.public_key_size_in_bits
                            except Exception:
                                pass
                            
                            # Check trust validation when available
                            try:
                                if cert_res.certificate_deployments[0].path_validation_results:
                                    # API seems to have changed; check for is_valid attribute instead
                                    trust_result = cert_res.certificate_deployments[0].path_validation_results[0]
                                    if hasattr(trust_result, "is_certificate_trusted"):
                                        result["certificate"]["has_trusted_path"] = bool(trust_result.is_certificate_trusted)
                                    elif hasattr(trust_result, "is_valid"):
                                        result["certificate"]["has_trusted_path"] = bool(trust_result.is_valid)
                                    else:
                                        result["certificate"]["trust_validated"] = "Unknown"
                            except (AttributeError, IndexError):
                                pass
                        except (AttributeError, IndexError) as e:
                            result["certificate"]["error"] = f"Error parsing certificate: {str(e)}"
                
                # Check for protocol support
                if options.check_vulnerabilities:
                    # Create a mapping of protocol scan attributes to friendly names
                    protocols = {
                        "ssl_2_0_cipher_suites": "SSL 2.0",
                        "ssl_3_0_cipher_suites": "SSL 3.0",
                        "tls_1_0_cipher_suites": "TLS 1.0",
                        "tls_1_1_cipher_suites": "TLS 1.1",
                        "tls_1_2_cipher_suites": "TLS 1.2",
                        "tls_1_3_cipher_suites": "TLS 1.3"
                    }
                    
                    for protocol_attr, protocol_name in protocols.items():
                        if hasattr(scan_result, protocol_attr):
                            protocol_scan = getattr(scan_result, protocol_attr)
                            if protocol_scan.status.name == "COMPLETED" and protocol_scan.result:
                                cipher_count = len(protocol_scan.result.accepted_cipher_suites)
                                result["protocols"][protocol_name] = {
                                    "supported": cipher_count > 0,
                                    "accepted_cipher_count": cipher_count
                                }
                            else:
                                result["protocols"][protocol_name] = {"supported": False}
                    
                    # Check for vulnerabilities
                    vulnerabilities = {
                        "heartbleed": "heartbleed",
                        "robot": "robot",
                        "tls_compression": "tls_compression",
                        "session_renegotiation": "session_renegotiation"
                    }
                    
                    for vuln_attr, vuln_name in vulnerabilities.items():
                        if hasattr(scan_result, vuln_attr):
                            vuln_scan = getattr(scan_result, vuln_attr)
                            if vuln_scan.status.name == "COMPLETED" and vuln_scan.result:
                                vuln_res = vuln_scan.result
                                
                                # Different vulnerability checks return different result objects
                                if vuln_attr == "heartbleed":
                                    result["vulnerabilities"][vuln_name] = {
                                        "vulnerable": vuln_res.is_vulnerable_to_heartbleed
                                    }
                                elif vuln_attr == "robot":
                                    result["vulnerabilities"][vuln_name] = {
                                        "vulnerable": vuln_res.robot_result.value != 0 
                                    }
                                elif vuln_attr == "tls_compression":
                                    result["vulnerabilities"][vuln_name] = {
                                        "vulnerable": vuln_res.supports_compression
                                    }
                                elif vuln_attr == "session_renegotiation":
                                    renegotiation_info = {
                                        "secure_renegotiation": vuln_res.supports_secure_renegotiation
                                    }
                                    if hasattr(vuln_res, "accepts_client_renegotiation"):
                                        renegotiation_info["client_renegotiation"] = vuln_res.accepts_client_renegotiation
                                    result["vulnerabilities"][vuln_name] = renegotiation_info
            
        return result
    
    except ConnectionToServerFailed as e:
        return {"error": f"Connection to server failed: {str(e)}"}
    except Exception as e:
        return {"error": f"SSL scan failed: {str(e)}"}

@mcp.tool()
def network_scan(network: str, timeout: int = 2) -> Dict:
    """
    Scan a network for active hosts using ICMP echo.
    
    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        timeout: Timeout in seconds for each host scan
    
    Returns:
        Dict containing scan results
    """
    # Validate network format
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return {"error": f"Invalid network format: {network}. Expected CIDR notation (e.g., 192.168.1.0/24)"}
    
    # Limit scan to reasonable size for a network tool
    if net.num_addresses > 1024:
        return {"error": f"Network too large: {network} contains {net.num_addresses} addresses. Maximum allowed is 1024."}
    
    results = {
        "network": str(net),
        "hosts": [],
        "total_hosts": net.num_addresses,
        "active_hosts": 0
    }
    
    nm = nmap.PortScanner()
    
    try:
        # Use nmap for ping scan (-sn) with given timeout
        scan_args = f"-sn -T4 --host-timeout {timeout}s"
        scan_result = nm.scan(hosts=str(net), arguments=scan_args)
        
        # Process results
        if 'scan' in scan_result:
            for host, host_data in scan_result['scan'].items():
                if 'status' in host_data and host_data['status']['state'] == 'up':
                    host_info = {
                        "ip": host,
                        "status": "up"
                    }
                    
                    # Add hostname if available
                    if 'hostnames' in host_data and len(host_data['hostnames']) > 0:
                        hostname = host_data['hostnames'][0]['name']
                        if hostname and hostname != host:
                            host_info["hostname"] = hostname
                    
                    results["hosts"].append(host_info)
                    results["active_hosts"] += 1
        
        return results
    except Exception as e:
        return {"error": str(e), "network": str(net)}


@mcp.tool()
def ip_geolocation(ip: str) -> Dict:
    """
    Geolocate an IP address using a public database.
    
    Args:
        ip: IP address to geolocate
    
    Returns:
        Dict containing geolocation information
    """
    # Validate IP format
    if not is_valid_ip(ip):
        return {"error": f"Invalid IP address: {ip}"}
    
    # Private IP check
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return {
                "ip": ip,
                "error": "This is a private IP address. Geolocation only works for public IP addresses."
            }
    except ValueError:
        pass
    
    try:
        # Use ip-api.com free API (does not require API key)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        
        if data.get("status") == "success":
            result = {
                "ip": ip,
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "timezone": data.get("timezone")
            }
            return result
        else:
            return {"error": data.get("message", "Unknown error"), "ip": ip}
            
    except requests.RequestException as e:
        return {"error": f"Request error: {str(e)}", "ip": ip}
    except ValueError as e:
        return {"error": f"Error parsing response: {str(e)}", "ip": ip}
    except Exception as e:
        return {"error": str(e), "ip": ip}


@mcp.tool()
def http_headers(url: str) -> Dict:
    """
    Analyze HTTP headers for security configurations.
    
    Args:
        url: URL to analyze
    
    Returns:
        Dict containing HTTP header analysis
    """
    # Validate and normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return {"error": f"Invalid URL: {url}"}
    except Exception:
        return {"error": f"Invalid URL format: {url}"}
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=True, allow_redirects=True)
        
        # Get headers as dictionary
        response_headers = dict(response.headers)
        
        # Security headers to check
        security_headers = {
            "Strict-Transport-Security": {"present": False, "value": None, "description": "HTTP Strict Transport Security (HSTS)"},
            "Content-Security-Policy": {"present": False, "value": None, "description": "Content Security Policy (CSP)"},
            "X-Content-Type-Options": {"present": False, "value": None, "description": "X-Content-Type-Options"},
            "X-Frame-Options": {"present": False, "value": None, "description": "X-Frame-Options"},
            "X-XSS-Protection": {"present": False, "value": None, "description": "Cross-site scripting protection"},
            "Referrer-Policy": {"present": False, "value": None, "description": "Referrer Policy"},
            "Permissions-Policy": {"present": False, "value": None, "description": "Permissions Policy (Feature Policy)"},
            "Cache-Control": {"present": False, "value": None, "description": "Cache Control"},
            "Set-Cookie": {"present": False, "value": None, "description": "Cookies"},
            "Access-Control-Allow-Origin": {"present": False, "value": None, "description": "CORS Allow-Origin"},
            "Server": {"present": False, "value": None, "description": "Server information"}
        }
        
        # Check for security headers
        for header, details in security_headers.items():
            if header in response_headers:
                security_headers[header]["present"] = True
                security_headers[header]["value"] = response_headers[header]
        
        # Process cookies if present
        cookies = []
        if response.cookies:
            for cookie in response.cookies:
                cookie_info = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                    "samesite": cookie.get_nonstandard_attr("SameSite", None)
                }
                cookies.append(cookie_info)
        
        # Check for TLS/SSL
        is_https = parsed_url.scheme == "https"
        
        result = {
            "url": url,
            "status_code": response.status_code,
            "https": is_https,
            "security_headers": security_headers,
            "all_headers": response_headers,
            "cookies": cookies
        }
        
        return result
        
    except requests.exceptions.SSLError:
        return {"error": "SSL certificate verification failed", "url": url}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection error", "url": url}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out", "url": url}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request error: {str(e)}", "url": url}
    except Exception as e:
        return {"error": str(e), "url": url}


@mcp.tool()
def my_public_ip() -> Dict:
    """
    Check your own public IP address and get geographic information.
    
    Returns:
        Dict containing IP address and geographic information
    """
    try:
        response = requests.get("https://api.my-ip.io/v2/ip.json", timeout=5)
        response.raise_for_status()  # Raise an exception for 4XX/5XX responses
        
        data = response.json()
        
        if data.get("success"):
            result = {
                "ip": data.get("ip"),
                "type": data.get("type"),
                "country": {
                    "code": data.get("country", {}).get("code"),
                    "name": data.get("country", {}).get("name")
                },
                "region": data.get("region"),
                "city": data.get("city"),
                "location": {
                    "latitude": data.get("location", {}).get("lat"),
                    "longitude": data.get("location", {}).get("lon")
                },
                "timezone": data.get("timeZone"),
                "asn": {
                    "number": data.get("asn", {}).get("number"),
                    "name": data.get("asn", {}).get("name"),
                    "network": data.get("asn", {}).get("network")
                }
            }
            return result
        else:
            return {"error": "API request was not successful"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except ValueError as e:
        return {"error": f"Error parsing response: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def dns_enum(domain: str, record_types: List[str] = None) -> Dict:
    """
    Perform comprehensive DNS enumeration.
    
    Args:
        domain: Domain name to query
        record_types: List of DNS record types to query (default: A, AAAA, MX, NS, SOA, TXT, CAA, CNAME, SRV)
    
    Returns:
        Dict containing DNS enumeration results
    """
    # Validate domain format
    if not is_valid_hostname(domain):
        return {"error": f"Invalid domain name: {domain}"}
    
    # Set default record types if not provided
    if not record_types:
        record_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA", "CNAME", "SRV"]
    
    # Normalize record types
    record_types = [r.upper() for r in record_types]
    
    # Initialize results structure
    results = {
        "domain": domain,
        "records": {},
        "nameservers": [],
        "subdomains": []
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    
    # Function to query a specific record type
    def query_record(record_type):
        try:
            answers = resolver.resolve(domain, record_type)
            records = []
            
            for answer in answers:
                if record_type == "MX":
                    records.append({
                        "type": record_type,
                        "exchange": str(answer.exchange),
                        "preference": answer.preference
                    })
                elif record_type == "SOA":
                    records.append({
                        "type": record_type,
                        "mname": str(answer.mname),
                        "rname": str(answer.rname),
                        "serial": answer.serial,
                        "refresh": answer.refresh,
                        "retry": answer.retry,
                        "expire": answer.expire,
                        "minimum": answer.minimum
                    })
                elif record_type == "SRV":
                    records.append({
                        "type": record_type,
                        "target": str(answer.target),
                        "port": answer.port,
                        "priority": answer.priority,
                        "weight": answer.weight
                    })
                else:
                    records.append({
                        "type": record_type,
                        "value": str(answer)
                    })
            
            return record_type, records
        except dns.resolver.NoAnswer:
            return record_type, []
        except dns.resolver.NXDOMAIN:
            return record_type, [{"error": "Domain does not exist"}]
        except dns.resolver.Timeout:
            return record_type, [{"error": "Query timed out"}]
        except dns.exception.DNSException as e:
            return record_type, [{"error": str(e)}]
    
    # Query all record types in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_record = {executor.submit(query_record, rt): rt for rt in record_types}
        for future in concurrent.futures.as_completed(future_to_record):
            record_type, records = future.result()
            if records:
                results["records"][record_type] = records
    
    # Try to find nameservers
    try:
        ns_records = resolver.resolve(domain, 'NS')
        results["nameservers"] = [str(ns) for ns in ns_records]
    except Exception:
        pass
    
    # Try to find common subdomains (if A records are requested)
    if "A" in record_types:
        common_subdomains = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "api"]
        
        def check_subdomain(subdomain):
            try:
                fqdn = f"{subdomain}.{domain}"
                resolver.resolve(fqdn, 'A')
                return fqdn
            except Exception:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            subdomain_futures = {executor.submit(check_subdomain, sd): sd for sd in common_subdomains}
            for future in concurrent.futures.as_completed(subdomain_futures):
                fqdn = future.result()
                if fqdn:
                    results["subdomains"].append(fqdn)
    
    return results


if __name__ == "__main__":
    import sys
    
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
