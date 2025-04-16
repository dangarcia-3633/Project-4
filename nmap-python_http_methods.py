import nmap

def get_http_methods(ip_address):
    """
    Scans the target IP address for open HTTP ports (80, 443) and attempts
    to identify supported HTTP methods using the 'http-methods' Nmap script.

    Args:
        ip_address (str): The IP address to scan.

    Returns:
        dict: A dictionary containing the scan results or an error message.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, arguments='-p 80,443 --script http-methods')
        if ip_address in nm.all_hosts():
            if 'tcp' in nm[ip_address]:
                for port, data in nm[ip_address]['tcp'].items():
                    if port in (80, 443) and data['state'] == 'open':
                        if 'script' in data and 'http-methods' in data['script']:
                            return {
                                'status': 'success',
                                'ip_address': ip_address,
                                'port': port,
                                'allowed_methods': data['script']['http-methods'].strip()
                            }
                        else:
                             return {
                                'status': 'success',
                                'ip_address': ip_address,
                                'port': port,
                                'message': 'HTTP methods not identified.'
                            }
            return {'status': 'error', 'message': 'No open HTTP ports found.'}
        else:
            return {'status': 'error', 'message': 'Host not found.'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

if __name__ == "__main__":
    ip_address = input("Enter the IP address to scan: ")
    result = get_http_methods(ip_address)

    if result['status'] == 'success':
        print(f"Scan results for {result['ip_address']}:")
        if 'allowed_methods' in result:
            print(f"Port {result['port']}: Allowed HTTP Methods: {result['allowed_methods']}")
        else:
            print(f"Port {result['port']}: {result['message']}")
    else:
        print(f"Error: {result['message']}")