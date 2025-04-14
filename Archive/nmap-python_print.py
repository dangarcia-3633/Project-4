#Improved Version  (no good for what we need)
import nmap
import json

# Synchronous version (recommended for now)
def run_scan(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, '22-80')
    return nm[ip_address]

if __name__ == "__main__":
    ip_addresses = ["45.33.32.156"]  # scanme.nmap.org
    results = {}

    for ip in ip_addresses:
        results[ip] = run_scan(ip).all_protocols()

    # Print to terminal
    print(json.dumps(results, indent=2))

    # Save to file
    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=2)
