import nmap
import datetime

def run_nmap_scan(target, output_file):
    nm = nmap.PortScanner()

    print(f"\n[+] Scanning target: {target}")
    print(f"[+] Results will be saved to: {output_file}\n")

    # Run an aggressive scan (-A does OS, version, traceroute, scripts, etc.)
    nm.scan(hosts=target, arguments='-A -T4')

    with open(output_file, 'w') as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = f"Nmap Full Network Report - {timestamp}\nTarget: {target}\n\n"
        print(header)
        f.write(header)

        for host in nm.all_hosts():
            ip = host
            mac = nm[host]['addresses'].get('mac', 'N/A')
            hostname = nm[host].hostname() or 'N/A'
            os_guess = nm[host].get('osmatch', [{}])[0].get('name', 'Unknown OS')
            device_type = nm[host].get('osclass', [{}])[0].get('type', 'Unknown Device')

            host_info = f"""
Host: {hostname}
IP Address: {ip}
MAC Address: {mac}
OS Guess: {os_guess}
Device Type: {device_type}
----------------------------------------
"""
            print(host_info)
            f.write(host_info)

            if 'tcp' in nm[host]:
                print("Open TCP Ports and Services:")
                f.write("Open TCP Ports and Services:\n")
                for port in sorted(nm[host]['tcp'].keys()):
                    port_info = nm[host]['tcp'][port]
                    line = f"  Port {port}/{port_info['name']} - {port_info['state']} - {port_info.get('product', '')} {port_info.get('version', '')}".strip()
                    print(line)
                    f.write(line + "\n")
                print()
                f.write("\n")

            # Traceroute output (if available)
            if 'traceroute' in nm[host]:
                print("Traceroute:")
                f.write("Traceroute:\n")
                for hop in nm[host]['traceroute']['hops']:
                    hop_line = f"  {hop['ttl']}: {hop['ipaddr']} ({hop['rtt']} ms)"
                    print(hop_line)
                    f.write(hop_line + "\n")
                print()
                f.write("\n")

            print("="*60)
            f.write("="*60 + "\n")

# --- Example Usage ---
target_network = '45.33.32.156'  # Smaller CIDR block to keep scan quick
output_filename = 'nmap_full_report.txt'

run_nmap_scan(target_network, output_filename)

#Researched through nmap.org
