import socket
import argparse
import csv
import json
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------
# Common Port Services
# -----------------------------
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

# -----------------------------
# Top Common Ports Preset
# -----------------------------
TOP_PORTS = [
    21,22,23,25,53,80,110,139,143,443,445,3389,
    8080,3306,5900,995,1723,111,995,993
]

# -----------------------------
# Banner Grabbing
# -----------------------------
def grab_banner(sock):
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner
    except:
        return ""

# -----------------------------
# Scan Single Port
# -----------------------------
def scan_port(target, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))

        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            banner = grab_banner(sock)
            sock.close()
            return (port, service, banner)

        sock.close()
        return None

    except:
        return None

# -----------------------------
# Multithreaded Scanner
# -----------------------------
def scan_ports(target, ports, threads, timeout):
    print(f"\nScanning target: {target}")
    print(f"Total ports: {len(ports)}")
    print(f"Threads: {threads}")
    print("-" * 50)

    open_ports = []
    completed = 0
    total = len(ports)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            completed += 1
            progress = (completed / total) * 100
            print(f"\rProgress: {progress:.1f}%", end="")

            result = future.result()
            if result:
                port, service, banner = result
                print(f"\n✅ Port {port} OPEN | Service: {service}")
                if banner:
                    print(f"   Banner: {banner}")
                open_ports.append(result)

    print("\nScan complete.")
    return open_ports

# -----------------------------
# Export Results
# -----------------------------
def export_results(target, results, export_json=False):
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    csv_file = f"results/scan_{target}_{timestamp}.csv"

    with open(csv_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Target", "Port", "Service", "Banner", "Timestamp"])
        for port, service, banner in results:
            writer.writerow([target, port, service, banner, datetime.now()])

    print(f"\n📄 CSV saved to {csv_file}")

    if export_json:
        json_file = f"results/scan_{target}_{timestamp}.json"
        data = [
            {
                "target": target,
                "port": port,
                "service": service,
                "banner": banner,
                "timestamp": str(datetime.now())
            }
            for port, service, banner in results
        ]
        with open(json_file, "w") as f:
            json.dump(data, f, indent=4)

        print(f"📄 JSON saved to {json_file}")

# -----------------------------
# Resolve Host
# -----------------------------
def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        print(f"Resolved {target} → {ip}")
        return ip
    except:
        print("Could not resolve target")
        return None

# -----------------------------
# CLI Interface
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Professional Python Port Scanner")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--start", type=int, help="Start port")
    parser.add_argument("--end", type=int, help="End port")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--timeout", type=float, default=1, help="Connection timeout")
    parser.add_argument("--top-ports", action="store_true", help="Scan common ports only")
    parser.add_argument("--json", action="store_true", help="Export JSON report")

    args = parser.parse_args()

    target_ip = resolve_target(args.target)
    if not target_ip:
        return

    if args.top_ports:
        ports = TOP_PORTS
    else:
        start = args.start if args.start else 1
        end = args.end if args.end else 1024
        ports = list(range(start, end + 1))

    start_time = time.time()

    results = scan_ports(
        target_ip,
        ports,
        args.threads,
        args.timeout
    )

    end_time = time.time()
    duration = round(end_time - start_time, 2)

    export_results(target_ip, results, args.json)

    print("\n=== Scan Summary ===")
    print(f"Target: {target_ip}")
    print(f"Open ports: {len(results)}")
    print(f"Scan time: {duration} seconds")

if __name__ == "__main__":
    main()
