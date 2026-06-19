import ipaddress
import socket
import threading

try:
    from scapy.layers.l2 import ARP, Ether
    import scapy.all as scapy
except ImportError:
    scapy = None

# Thread lock for safely appending results from multiple threads
print_lock = threading.Lock()

def arp_scan(ip_range):
    """Discovers devices on the local network using ARP requests."""
    if scapy is None:
        print("\n[!] Scapy is not available. Skipping network-wide ARP discovery.")
        return []
    try:
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list, _ = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)

        devices = []
        print("\n[+] Devices found in network:")
        for element in answered_list:
            device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            devices.append(device)
            print(f"IP: {device['ip']} | MAC: {device['mac']}")
        return devices
    except Exception as exc:
        print(f"\n[!] ARP scan failed: {exc}")
        print("On Windows, ensure Npcap/WinPcap is installed for layer-2 packet capture support.")
        return []

def worker(target_ip, port, results):
    """Worker function for threading to check a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            with print_lock:
                results.append(port)
                print(f"  [+] Port {port}: OPEN")
    except Exception:
        pass
    finally:
        sock.close()

def threaded_port_scan(target_ip, start_port=1, end_port=100):
    """Scans ports concurrently using threading for high performance."""
    threads = []
    results = []
    print(f"\n[+] Scanning ports {start_port}-{end_port} on {target_ip}...")
    
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=worker, args=(target_ip, port, results))
        thread.start()
        threads.append(thread)
        
    for thread in threads:
        thread.join()
        
    if not results:
        print("  [-] No open ports found.")
    return results

def get_valid_input(prompt, validation_type):
    """Ensures the user inputs a valid IP address or Subnet range."""
    while True:
        user_input = input(prompt).strip()
        try:
            if validation_type == "subnet":
                # Validates CIDR notation like 192.168.1.0/24
                return str(ipaddress.ip_network(user_input, strict=False))
            elif validation_type == "ip":
                # Validates single IP like 192.168.1.1
                return str(ipaddress.ip_address(user_input))
        except ValueError:
            print(f"[!] Invalid {validation_type} format. Please try again.")

if __name__ == "__main__":
    print("=== Network & Port Scanner ===")
    print("1. Scan Subnet for Live Hosts (ARP Scan)")
    print("2. Scan Specific IP for Open Ports")
    print("3. Run Both (Scan Subnet, then scan a target IP)")
    
    choice = input("\nSelect an option (1-3): ").strip()
    
    if choice in ("1", "3"):
        subnet_input = get_valid_input("Enter Subnet to scan (e.g., 192.168.1.0/24): ", "subnet")
        arp_scan(subnet_input)
        
    if choice in ("2", "3"):
        target_ip = get_valid_input("Enter Target IP to scan (e.g., 192.168.1.1): ", "ip")
        
        try:
            max_port = int(input("Enter maximum port to scan (e.g., 100): ").strip())
            if max_port < 1 or max_port > 65535:
                raise ValueError
        except ValueError:
            print("[!] Invalid port number. Defaulting to 100.")
            max_port = 100
            
        threaded_port_scan(target_ip, start_port=1, end_port=max_port)
        
    if choice not in ("1", "2", "3"):
        print("[!] Invalid choice. Exiting script.")
