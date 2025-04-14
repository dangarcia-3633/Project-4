#python script for asynchronous scan

import nmap
import asyncio

async def nmap_scan(ip_address):
    nm = nmap.PortScannerAsync()
    await nm.scan(ip_address)
    return nm.scan_result

async def run_scans(ip_addresses):
    tasks = [nmap_scan(ip) for ip in ip_addresses]
    results = await asyncio.gather(*tasks)
    return results

if __name__ == "__main__":
    ip_addresses = ["45.33.32.156"]
    results = asyncio.run(run_scans(ip_addresses))
    print(results)


