import nmap
import datetime

def vuln_scan(target, output_file):
    scanner = nmap.PortScanner()
    print(f"\n[+] Starting vulnerability scan on {target}...\n")

    # Run Nmap vuln scan (takes time!)
    scanner.scan(hosts=target, arguments='--script vuln -Pn')

    with open(output_file, 'w') as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = f"Nmap Vulnerability Scan Report\nTarget: {target}\nTime: {timestamp}\n\n"
        print(header)
        f.write(header)

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

                    # Vulnerability script output
                    if 'script' in scanner[host][proto][port]:
                        for script, output in scanner[host][proto][port]['script'].items():
                            vuln_output = f"[{script}]\n{output}\n"
                            print(vuln_output)
                            f.write(vuln_output)

            print("="*60 + "\n")
            f.write("="*60 + "\n\n")

# --- Example Usage ---
target_site = "scanme.nmap.org"  # Replace with your own authorized target
output_filename = "vuln_scan_results.txt"

vuln_scan(target_site, output_filename)
