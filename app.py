import sys
import subprocess
import ipaddress
import os
import shutil
import xml.etree.ElementTree as ET
import json
import requests
from urllib.parse import urlparse
import threading

# Utility Functions

def validate_ip(ip):
    """Validate the provided IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_tool(tool):
    """Check if a tool is installed."""
    if shutil.which(tool) is None:
        print(f"{tool} is not installed. Please install it before proceeding.")
        sys.exit(1)

def get_seclists_path():
    """Find or verify the path to Seclists."""
    seclists_path = "/usr/share/seclists"
    if os.path.exists(seclists_path):
        return seclists_path
    else:
        print("Seclists not found in /usr/share/seclists. Please install it manually.")
        sys.exit(1)

def check_hosts_file(ip):
    """Check if the IP is present in /etc/hosts and return the associated hostname if exists."""
    hosts_file = "/etc/hosts"
    try:
        with open(hosts_file, "r") as f:
            lines = f.readlines()
            for line in lines:
                if ip in line:
                    parts = line.strip().split()
                    if len(parts) > 1 and parts[0] == ip:
                        return parts[1]  # Return the first hostname associated
    except PermissionError:
        print("Insufficient permissions to read /etc/hosts. Run with sudo.")
        sys.exit(1)
    except FileNotFoundError:
        print("File /etc/hosts not found.")
        sys.exit(1)
    return None

def add_to_hosts(ip, hostname):
    """Add a line <IP> <hostname> to /etc/hosts."""
    hosts_file = "/etc/hosts"
    entry = f"{ip} {hostname}\n"
    try:
        with open(hosts_file, "a") as f:
            f.write(entry)
        print(f"Added to /etc/hosts: {entry.strip()}")
    except PermissionError:
        print("Insufficient permissions to modify /etc/hosts. Run with sudo.")
        sys.exit(1)
    except IOError as e:
        print(f"Error writing to /etc/hosts: {e}")
        sys.exit(1)

def get_redirect_hostname(ip):
    """Try to get the hostname from an HTTP redirect."""
    try:
        response = requests.get(f"http://{ip}/", allow_redirects=False, timeout=10)
        if response.status_code in (301, 302):
            location = response.headers.get("Location")
            if location:
                parsed = urlparse(location)
                if parsed.hostname:
                    return parsed.hostname
    except requests.RequestException:
        pass
    return None

# Main Functions

def run_nmap(ip):
    """Run a detailed Nmap scan."""
    output_file = "nmap_output.xml"
    cmd = ["nmap", "-sC", "-sV", "-p-", ip, "-oX", output_file]
    try:
        subprocess.run(cmd, check=True, timeout=600)  # 10-minute timeout
        return output_file
    except subprocess.TimeoutExpired:
        print("Nmap scan timed out.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error during Nmap scan: {e}")
        return None

def get_open_services(xml_file):
    """Extract all open ports and services from Nmap XML output."""
    if not xml_file or not os.path.exists(xml_file):
        return []
    tree = ET.parse(xml_file)
    root = tree.getroot()
    services = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            portid = port.get("portid")
            service = port.find("service")
            if service is not None:
                service_name = service.get("name", "")
                product = service.get("product", "")
                version = service.get("version", "")
                services.append({
                    "port": portid,
                    "service": service_name,
                    "product": product,
                    "version": version
                })
    return services

def get_http_ports(xml_file):
    """Extract HTTP/HTTPS ports from Nmap XML output."""
    if not xml_file or not os.path.exists(xml_file):
        return []
    tree = ET.parse(xml_file)
    root = tree.getroot()
    http_ports = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            service = port.find("service")
            if service is not None:
                service_name = service.get("name", "").lower()
                portid = port.get("portid")
                if "http" in service_name:
                    protocol = "https" if "ssl" in service_name or "https" in service_name or portid == "443" else "http"
                    http_ports.append((portid, protocol))
    return http_ports

def run_ffuf_directory(hostname, port, protocol, seclists_path, results):
    """Run FFUF for directory enumeration and save results to a dictionary."""
    wordlist = os.path.join(seclists_path, "Discovery", "Web-Content", "common.txt")
    output_file = f"ffuf_directory_{port}.json"
    url = f"{protocol}://{hostname}:{port}/FUZZ"
    cmd = ["ffuf", "-w", wordlist, "-u", url, "-o", output_file, "-of", "json", "-mc", "200"]
    try:
        subprocess.run(cmd, check=True, timeout=3600)  # 1-hour timeout
        results[port] = parse_ffuf_json(output_file)
    except subprocess.TimeoutExpired:
        print(f"FFUF directory on port {port} timed out.")
        results[port] = []
    except subprocess.CalledProcessError as e:
        print(f"Error during FFUF directory on port {port}: {e}")
        results[port] = []

def run_gobuster_subdomains(hostname, seclists_path, results):
    """Run Gobuster for subdomain enumeration and save results to a list."""
    wordlist = os.path.join(seclists_path, "Discovery", "DNS", "subdomains-top1million-5000.txt")
    output_file = "gobuster_subdomains.txt"
    cmd = ["gobuster", "dns", "-d", hostname, "-w", wordlist, "-o", output_file, "--no-color"]
    try:
        subprocess.run(cmd, check=True, timeout=3600)  # 1-hour timeout
        results.extend(parse_gobuster_output(output_file))
    except subprocess.TimeoutExpired:
        print("Gobuster subdomains timed out.")
    except subprocess.CalledProcessError as e:
        print(f"Error during Gobuster subdomains: {e}")

def parse_gobuster_output(output_file):
    """Parse Gobuster output file and return found subdomains."""
    if not output_file or not os.path.exists(output_file):
        return []
    try:
        with open(output_file, "r") as f:
            lines = f.readlines()
            subdomains = []
            for line in lines:
                if "Found: " in line:
                    subdomain = line.split("Found: ")[1].strip()
                    subdomains.append(subdomain)
            return subdomains
    except IOError as e:
        print(f"Error reading Gobuster file: {e}")
        return []

def run_ffuf_vhosts(ip, port, protocol, seclists_path, results):
    """Run FFUF for virtual host enumeration and save results to a dictionary."""
    wordlist = os.path.join(seclists_path, "Discovery", "Web-Content", "common.txt")
    output_file = f"ffuf_vhosts_{port}.json"
    url = f"{protocol}://{ip}:{port}/"
    cmd = ["ffuf", "-w", wordlist, "-u", url, "-H", "Host: FUZZ", "-o", output_file, "-of", "json", "-mc", "200"]
    try:
        subprocess.run(cmd, check=True, timeout=3600)  # 1-hour timeout
        results[port] = parse_ffuf_json(output_file)
    except subprocess.TimeoutExpired:
        print(f"FFUF vhosts on port {port} timed out.")
        results[port] = []
    except subprocess.CalledProcessError as e:
        print(f"Error during FFUF vhosts on port {port}: {e}")
        results[port] = []

def parse_ffuf_json(json_file):
    """Parse FFUF JSON file and return found results."""
    if not json_file or not os.path.exists(json_file):
        return []
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
            return [result["input"]["FUZZ"] for result in data["results"]]
    except (json.JSONDecodeError, KeyError, IOError) as e:
        print(f"Error parsing FFUF file: {e}")
        return []

def generate_report(ip, hostname, open_services, ffuf_directory_results, gobuster_subdomains_results, ffuf_vhosts_results):
    """Generate a detailed HTML report."""
    html_content = f"""
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>Report Enumerazione Web - {ip}</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 p-8">
    <div class="bg-white p-6 rounded-lg shadow-lg">
        <h1 class="text-3xl font-bold mb-4">Report Enumerazione Web per {ip}</h1>
        {f'<p class="mb-4 text-lg">Hostname: {hostname}</p>' if hostname else '<p class="mb-4 text-lg">Nessun hostname trovato.</p>'}
        <h2 class="text-2xl font-semibold mb-2">Porte Aperte</h2>
        <ul class="list-disc pl-5 mb-6">
    """
    for service in open_services:
        html_content += f'<li class="mb-1">Porta {service["port"]}: {service["service"]} {service["product"]} {service["version"]}</li>'
    html_content += """
        </ul>
        <h2 class="text-2xl font-semibold mb-2">Enumerazione Directory</h2>
    """
    for port, discovered in ffuf_directory_results.items():
        html_content += f'<h3 class="text-xl font-medium mb-2">Porta {port}</h3>'
        if discovered:
            html_content += '<ul class="list-disc pl-5 mb-4">'
            for item in discovered:
                html_content += f'<li>{item}</li>'
            html_content += '</ul>'
        else:
            html_content += '<p class="mb-4">Nessuna directory trovata.</p>'
    html_content += """
        <h2 class="text-2xl font-semibold mb-2">Enumerazione Sottodomini</h2>
    """
    if gobuster_subdomains_results:
        html_content += '<ul class="list-disc pl-5 mb-4">'
        for subdomain in gobuster_subdomains_results:
            html_content += f'<li>{subdomain}</li>'
        html_content += '</ul>'
    else:
        html_content += '<p class="mb-4">Nessun sottodominio trovato.</p>'
    html_content += """
        <h2 class="text-2xl font-semibold mb-2">Enumerazione Virtual Host</h2>
    """
    for port, vhosts in ffuf_vhosts_results.items():
        html_content += f'<h3 class="text-xl font-medium mb-2">Porta {port}</h3>'
        if vhosts:
            html_content += '<ul class="list-disc pl-5 mb-4">'
            for vhost in vhosts:
                html_content += f'<li>{vhost}</li>'
            html_content += '</ul>'
        else:
            html_content += '<p class="mb-4">Nessun virtual host trovato.</p>'
    html_content += """
    </div>
</body>
</html>
    """
    with open("report.html", "w") as f:
        f.write(html_content)
    print(f"Report generated at: {os.path.abspath('report.html')}")

# Main Function

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <ip-address>")
        sys.exit(1)

    ip = sys.argv[1]
    if not validate_ip(ip):
        print("Invalid IP address.")
        sys.exit(1)

    # Check for required tools
    check_tool("nmap")
    check_tool("ffuf")
    check_tool("gobuster")
    seclists_path = get_seclists_path()

    # Check /etc/hosts for IP
    hostname = check_hosts_file(ip)
    if not hostname:
        # If not present, try to find hostname via HTTP redirect
        hostname = get_redirect_hostname(ip)
        if hostname:
            add_to_hosts(ip, hostname)
        else:
            print("No hostname found via redirect. Proceeding without hostname.")

    # Run Nmap scan
    nmap_file = run_nmap(ip)
    if not nmap_file:
        print("Error in Nmap scan. Exiting.")
        sys.exit(1)

    # Get open services and HTTP ports
    open_services = get_open_services(nmap_file)
    http_ports = get_http_ports(nmap_file)

    # Dictionaries and lists for results
    ffuf_directory_results = {}
    gobuster_subdomains_results = []
    ffuf_vhosts_results = {}

    # List for threads
    threads = []

    # Create threads for FFUF directory enumeration
    for port, protocol in http_ports:
        if hostname:
            thread = threading.Thread(target=run_ffuf_directory, args=(hostname, port, protocol, seclists_path, ffuf_directory_results))
            threads.append(thread)
            thread.start()

    # Create thread for Gobuster subdomain enumeration
    if hostname:
        thread = threading.Thread(target=run_gobuster_subdomains, args=(hostname, seclists_path, gobuster_subdomains_results))
        threads.append(thread)
        thread.start()

    # Create threads for FFUF vhost enumeration
    for port, protocol in http_ports:
        thread = threading.Thread(target=run_ffuf_vhosts, args=(ip, port, protocol, seclists_path, ffuf_vhosts_results))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Generate the report
    generate_report(ip, hostname, open_services, ffuf_directory_results, gobuster_subdomains_results, ffuf_vhosts_results)

if __name__ == "__main__":
    main()
