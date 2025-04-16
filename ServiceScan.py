import nmap

def list_services(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV -Pn')  # Service scan

    services = []

    for host in nm.all_hosts():
        if 'tcp' in nm[host]:
            for port, info in nm[host]['tcp'].items():
                service_name = info.get('name', 'unknown')
                product = info.get('product', '')
                version = info.get('version', '')
                full_service = f"{service_name} ({product} {version})".strip()
                services.append((port, full_service))

    return services