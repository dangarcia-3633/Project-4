#Script for NMAP
import nmap

scanner = nmap.PortScanner()
scanner.scan('scanme.nmap.org', '22-80')

for host in scanner.all_hosts():
    print(f"Host: {host}")
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()
        for port in sorted(ports):
            state = scanner[host][proto][port]['state']
            print(f"Port {port}/{proto} is {state}")
