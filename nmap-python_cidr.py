#Nmap using CIDR notation scanme.nmap.org 45.33.32.0/19

import nmap
ips = '45.33.32.156'
port = 22
nmap = nmap.PortScanner()
nmap.scan(ips, str(port))

with open('nmap_results.txt','w') as file:
    for host in nmap.all_hosts():
        port_state = nmap[host]['tcp'][port]['state']
        print(f"Port {port} is {port_state} on {host}")
        file.write(f"Port {port} is {port_state} on {host}")