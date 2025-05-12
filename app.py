from flask import Flask, request, render_template, send_from_directory, Response
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
import time

app = Flask(__name__)

scan_status = {
    'nmap': 'idle',
    'ffuf_dir': 'idle',
    'gobuster': 'idle',
    'ffuf_vhost': 'idle',
    'status': 'idle'
}


def validate_ip(ip):
    """Validate the provided IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_tool(tool):
    """Check if a tool is installed."""
    return shutil.which(tool) is not None

def get_seclists_path():
    """Find or verify the path to Seclists."""
    seclists_path = "/usr/share/seclists"
    return seclists_path if os.path.exists(seclists_path) else None

def check_hosts_file(ip):
    """Check if the IP is present in /etc/hosts and return the associated hostname if exists."""
    hosts_file = "/etc/hosts"
    try:
        with open(hosts_file, "r") as f:
            for line in f:
                if ip in line:
                    parts = line.strip().split()
                    if len(parts) > 1 and parts[0] == ip:
                        return parts[1]
    except:
        return None
    return None

def add_to_hosts(ip, hostname):
    """Add a line <IP> <hostname> to /etc/hosts or inform user if not possible."""
    hosts_file = "/etc/hosts"
    entry = f"{ip} {hostname}\n"
    try:
        with open(hosts_file, "a") as f:
            f.write(entry)
        print(f"Added to /etc/hosts: {entry.strip()}")
    except PermissionError:
        print("Insufficient permissions to modify /etc/hosts. Please add manually:")
        print(entry.strip())
    except IOError as e:
        print(f"Error writing to /etc/hosts: {e}")

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


def run_nmap(ip):
    """Run a detailed Nmap scan."""
    output_file = "nmap_output.xml"
    cmd = ["nmap", "-sC", "-sV", "-p-", ip, "-oX", output_file]
    try:
        subprocess.run(cmd, check=True, timeout=600)
        return output_file
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        print(f"Nmap error: {e}")
        scan_status['nmap'] = 'error'
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
            service_name = service.get("name", "") if service else ""
            product = service.get("product", "") if service else ""
            version = service.get("version", "") if service else ""
            services.append({"port": portid, "service": service_name, "product": product, "version": version})
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
            if service is not None and "http" in service.get("name", "").lower():
                portid = port.get("portid")
                protocol = "https" if "ssl" in service.get("name", "").lower() or portid == "443" else "http"
                http_ports.append((portid, protocol))
    return http_ports

def run_ffuf_directory(hostname, port, protocol, seclists_path, results):
    """Run FFUF for directory enumeration."""
    if not seclists_path:
        results[port] = []
        return
    wordlist = os.path.join(seclists_path, "Discovery", "Web-Content", "common.txt")
    output_file = f"ffuf_directory_{port}.json"
    url = f"{protocol}://{hostname}:{port}/FUZZ"
    cmd = ["ffuf", "-w", wordlist, "-u", url, "-o", output_file, "-of", "json", "-mc", "200"]
    try:
        subprocess.run(cmd, check=True, timeout=3600)
        results[port] = parse_ffuf_json(output_file)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        print(f"FFUF directory error on port {port}: {e}")
        results[port] = []

def run_gobuster_subdomains(hostname, seclists_path, results):
    """Run Gobuster for subdomain enumeration."""
    if not seclists_path:
        return
    wordlist = os.path.join(seclists_path, "Discovery", "DNS", "subdomains-top1million-5000.txt")
    output_file = "gobuster_subdomains.txt"
    cmd = ["gobuster", "dns", "-d", hostname, "-w", wordlist, "-o", output_file, "--no-color"]
    try:
        subprocess.run(cmd, check=True, timeout=3600)
        results.extend(parse_gobuster_output(output_file))
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        print(f"Gobuster error: {e}")

def parse_gobuster_output(output_file):
    """Parse Gobuster output file."""
    if not os.path.exists(output_file):
        return []
    with open(output_file, "r") as f:
        return [line.split("Found: ")[1].strip() for line in f if "Found: " in line]

def run_ffuf_vhosts(ip, port, protocol, seclists_path, results):
    """Run FFUF for virtual host enumeration."""
    if not seclists_path:
        results[port] = []
        return
    wordlist = os.path.join(seclists_path, "Discovery", "Web-Content", "common.txt")
    output_file = f"ffuf_vhosts_{port}.json"
    url = f"{protocol}://{ip}:{port}/"
    cmd = ["ffuf", "-w", wordlist, "-u", url, "-H", "Host: FUZZ", "-o", output_file, "-of", "json", "-mc", "200"]
    try:
        subprocess.run(cmd, check=True, timeout=3600)
        results[port] = parse_ffuf_json(output_file)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        print(f"FFUF vhosts error on port {port}: {e}")
        results[port] = []

def parse_ffuf_json(json_file):
    """Parse FFUF JSON file."""
    if not os.path.exists(json_file):
        return []
    with open(json_file, "r") as f:
        data = json.load(f)
        return [result["input"]["FUZZ"] for result in data["results"]]

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
<body class="bg-gray-900 text-white min-h-screen flex items-center justify-center">
    <div class="max-w-4xl w-full p-6 bg-gray-800 rounded-lg shadow-lg">
        <h1 class="text-3xl font-bold mb-6 text-center">Report Enumerazione Web per {ip}</h1>
        {f'<p class="mb-4 text-lg text-center">Hostname: {hostname}</p>' if hostname else '<p class="mb-4 text-lg text-center">Nessun hostname trovato.</p>'}
        <h2 class="text-2xl font-semibold mb-4">Porte Aperte</h2>
        <ul class="list-disc pl-5 mb-6">
            {"".join([f'<li class="mb-2">Porta {s["port"]}: {s["service"]} {s["product"]} {s["version"]}</li>' for s in open_services])}
        </ul>
        <h2 class="text-2xl font-semibold mb-4">Enumerazione Directory</h2>
        {"".join([f'<h3 class="text-xl font-medium mb-2">Porta {port}</h3><ul class="list-disc pl-5 mb-4">' + "".join([f'<li>{item}</li>' for item in discovered]) + '</ul>' if discovered else f'<h3 class="text-xl font-medium mb-2">Porta {port}</h3><p class="mb-4">Nessuna directory trovata.</p>' for port, discovered in ffuf_directory_results.items()])}
        <h2 class="text-2xl font-semibold mb-4">Enumerazione Sottodomini</h2>
        {f'<ul class="list-disc pl-5 mb-4">' + "".join([f'<li>{sub}</li>' for sub in gobuster_subdomains_results]) + '</ul>' if gobuster_subdomains_results else '<p class="mb-4">Nessun sottodominio trovato.</p>'}
        <h2 class="text-2xl font-semibold mb-4">Enumerazione Virtual Host</h2>
        {"".join([f'<h3 class="text-xl font-medium mb-2">Porta {port}</h3><ul class="list-disc pl-5 mb-4">' + "".join([f'<li>{vhost}</li>' for vhost in vhosts]) + '</ul>' if vhosts else f'<h3 class="text-xl font-medium mb-2">Porta {port}</h3><p class="mb-4">Nessun virtual host trovato.</p>' for port, vhosts in ffuf_vhosts_results.items()])}
    </div>
</body>
</html>
    """
    with open("report.html", "w") as f:
        f.write(html_content)
    print(f"Report generated at: {os.path.abspath('report.html')}")

def run_scan(ip):
    """Run the full scan process."""
    global scan_status
    scan_status = {k: 'idle' for k in scan_status}
    scan_status['status'] = 'running'

    if not all(check_tool(t) for t in ["nmap", "ffuf", "gobuster"]):
        scan_status['status'] = 'error'
        return
    seclists_path = get_seclists_path()

    hostname = check_hosts_file(ip) or get_redirect_hostname(ip)
    if hostname:
        add_to_hosts(ip, hostname)

    scan_status['nmap'] = 'running'
    nmap_file = run_nmap(ip)
    scan_status['nmap'] = 'done' if nmap_file else 'error'
    if not nmap_file:
        scan_status['status'] = 'error'
        return

    open_services = get_open_services(nmap_file)
    http_ports = get_http_ports(nmap_file)

    ffuf_directory_results = {}
    gobuster_subdomains_results = []
    ffuf_vhosts_results = {}
    threads = []

    scan_status['ffuf_dir'] = 'running'
    for port, protocol in http_ports:
        if hostname:
            thread = threading.Thread(target=run_ffuf_directory, args=(hostname, port, protocol, seclists_path, ffuf_directory_results))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()
    scan_status['ffuf_dir'] = 'done'

    scan_status['gobuster'] = 'running'
    if hostname:
        thread = threading.Thread(target=run_gobuster_subdomains, args=(hostname, seclists_path, gobuster_subdomains_results))
        threads.append(thread)
        thread.start()
        thread.join()
    scan_status['gobuster'] = 'done'

    scan_status['ffuf_vhost'] = 'running'
    threads = []
    for port, protocol in http_ports:
        thread = threading.Thread(target=run_ffuf_vhosts, args=(ip, port, protocol, seclists_path, ffuf_vhosts_results))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    scan_status['ffuf_vhost'] = 'done'

    generate_report(ip, hostname, open_services, ffuf_directory_results, gobuster_subdomains_results, ffuf_vhosts_results)
    scan_status['status'] = 'done'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_scan():
    ip = request.form.get('ip')
    if not validate_ip(ip):
        return "Invalid IP address.", 400
    threading.Thread(target=run_scan, args=(ip,)).start()
    return "Scan started.", 200

@app.route('/progress')
def progress():
    def generate():
        while scan_status['status'] not in ['done', 'error']:
            yield f"data: {','.join([scan_status[k] for k in ['nmap', 'ffuf_dir', 'gobuster', 'ffuf_vhost', 'status']])}\n\n"
            time.sleep(1)
        yield f"data: {','.join([scan_status[k] for k in ['nmap', 'ffuf_dir', 'gobuster', 'ffuf_vhost', 'status']])}\n\n"
    return Response(generate(), mimetype='text/event-stream')

@app.route('/report')
def report():
    return send_from_directory('.', 'report.html')

if __name__ == "__main__":
    app.run(debug=True)
