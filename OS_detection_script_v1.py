#OS Detection Script
if __name__ == "__main__":
    import nmap
    import datetime

    target_ip = "45.33.32.156"  
    output_file = "os_scan_result.txt"

    with open(output_file, "w") as f:
        os_detection(target_ip, f)

    print(f"\n[+] Results saved to '{output_file}'")
