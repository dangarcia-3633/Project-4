import nmap
import datetime

# Scan ports and services
def scan_ports(target, f):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV -Pn')

    header = f"\n{'='*20} Basic Port Scan {'='*20}\n"
    print(header)
    f.write(header)

    for host in nm.all_hosts():
        host_info = f"Host: {host}\n"
        print(host_info, end='')
        f.write(host_info)

        if 'tcp' in nm[host]:
            ports_header = "  Ports:\n"
            print(ports_header, end='')
            f.write(ports_header)

    for port, info in nm[host]['tcp'].items():
        service = info.get('name', 'unknown')
        version = info.get('version', '')
        product = info.get('product', '')
        extrainfo = info.get('extrainfo', '')
        full_service = f"{product} {version} {extrainfo}".strip()

        line = f"    {port}/tcp: {info['state']} - {service}"
        if full_service:
            line += f" ({full_service})"
        line += "\n"

        print(line, end='')
        f.write(line)

# Scan for OS detection
def os_detection(target, f):
    nm = nmap.PortScanner()
    print(f"[+] Scanning {target} for OS detection...\n")
    nm.scan(hosts=target, arguments='-O -Pn -T4')

    header = f"\n{'='*20} OS Detection {'='*20}\n"
    print(header)
    f.write(header)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f.write(f"Time: {timestamp}\n")

    if target in nm.all_hosts():
        host_state = nm[target].state()
        f.write(f"Host State: {host_state}\n")

        os_matches = nm[target].get('osmatch', [])
        if os_matches:
            f.write("[+] Possible Operating Systems:\n")
            for i, match in enumerate(os_matches, start=1):
                os_line = f"  {i}. {match['name']} (Accuracy: {match['accuracy']}%)"
                print(os_line)
                f.write(os_line + "\n")

                if 'osclass' in match and match['osclass']:
                    for os_class in match['osclass']:
                        details = (
                            f"     Type: {os_class.get('type', 'N/A')}, Vendor: {os_class.get('vendor', 'N/A')}, "
                            f"OS Family: {os_class.get('osfamily', 'N/A')}, Gen: {os_class.get('osgen', 'N/A')}"
                        )
                        print(details)
                        f.write(details + "\n")
        else:
            f.write("[-] No OS match found.\n")
    else:
        f.write("[-] Host not found or not responding.\n")

#Scan for vulnerabilities 
def vuln_scan(target, f):
    scanner = nmap.PortScanner()
    print(f"\n[+] Starting vulnerability scan on {target}...\n")
    scanner.scan(hosts=target, arguments='--script vuln -Pn')

    header = f"\n{'='*20} Vulnerability Scan {'='*20}\n"
    print(header)
    f.write(header)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f.write(f"Time: {timestamp}\n\n")

    for host in scanner.all_hosts():
        host_info = f"Host: {host}\nState: {scanner[host].state()}\n"
        print(host_info)
        f.write(host_info)

        for proto in scanner[host].all_protocols():
            lports = scanner[host][proto].keys()
            for port in sorted(lports):
                port_info = f"\nPort: {port}/{proto}\nState: {scanner[host][proto][port]['state']}\n"
                print(port_info)
                f.write(port_info)

                if 'script' in scanner[host][proto][port]:
                    for script, output in scanner[host][proto][port]['script'].items():
                        vuln_output = f"[{script}]\n{output}\n"
                        print(vuln_output)
                        f.write(vuln_output)

# -----------------------
# Main combined execution
# -----------------------
if __name__ == "__main__":
    target_ip = "scanme.nmap.org"  
    output_filename = "nmap_scan_final.txt"

    with open(output_filename, 'w') as f:
        scan_ports(target_ip, f)
        os_detection(target_ip, f)
        vuln_scan(target_ip, f)

    print(f"\n[+] All results saved to {output_filename}")
