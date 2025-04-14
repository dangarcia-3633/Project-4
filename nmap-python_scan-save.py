#Nmap scan and save to text
import nmap

def scan_and_save(target, output_file):
    nm = nmap.PortScanner()
    nm.scan(target)

    with open(output_file, 'w') as f:
        for host in nm.all_hosts():
            host_info = f"Host: {host}\n"
            print(host_info, end='')      
            f.write(host_info)            

            if 'tcp' in nm[host]:
                ports_header = "  Ports:\n"
                print(ports_header, end='')
                f.write(ports_header)

                for port, state in nm[host]['tcp'].items():
                    line = f"    {port}: {state['state']}\n"
                    print(line, end='')   
                    f.write(line)

            print()   # Blank line for terminal
            f.write("\n")  # Blank line for file

# Example usage
target_ip = "45.33.32.156"
output_filename = "nmap_scan_result.txt"
scan_and_save(target_ip, output_filename)
