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