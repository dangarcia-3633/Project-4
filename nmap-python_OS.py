#Python script for OS detection
import nmap
import datetime

# Target IP (must be a string)
target_ip = '45.33.32.156'

# Create a scanner instance
nm = nmap.PortScanner()

# Perform OS detection
print(f"[+] Scanning {target_ip} for OS detection...\n")
nm.scan(hosts=target_ip, arguments='-O -Pn -T4')

# Prepare output file
output_file = 'nmap-python_OS.txt'
with open(output_file, 'w') as f:
    # Write header
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"Nmap OS Detection Report\nTarget: {target_ip}\nTime: {timestamp}\n\n"
    print(header)
    f.write(header)

    if target_ip in nm.all_hosts():
        host_state = nm[target_ip].state()
        print(f"Host State: {host_state}\n")
        f.write(f"Host State: {host_state}\n\n")

        os_matches = nm[target_ip].get('osmatch', [])
        if os_matches:
            print(f"[+] Possible Operating Systems:")
            f.write("[+] Possible Operating Systems:\n")

            for i, match in enumerate(os_matches, start=1):
                os_line = f"  {i}. {match['name']} (Accuracy: {match['accuracy']}%)"
                print(os_line)
                f.write(os_line + "\n")

                # Include OS class if available
                if 'osclass' in match and match['osclass']:
                    for os_class in match['osclass']:
                        details = f"     Type: {os_class.get('type', 'N/A')}, Vendor: {os_class.get('vendor', 'N/A')}, OS Family: {os_class.get('osfamily', 'N/A')}, Gen: {os_class.get('osgen', 'N/A')}"
                        print(details)
                        f.write(details + "\n")

        else:
            print("[-] No OS match found.")
            f.write("[-] No OS match found.\n")
    else:
        print("[-] Host not found or not responding.")
        f.write("[-] Host not found or not responding.\n")

print(f"\n[+] Results saved to '{output_file}'")
