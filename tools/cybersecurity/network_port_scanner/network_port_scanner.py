#!/usr/bin/env python3
"""TCP Port Scanner - Multi-threaded scanner with service fingerprinting."""

import socket
import concurrent.futures
import sys
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP (TLS)", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB", 11211: "Memcached",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict | None:
    """Scan a single TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            banner = grab_banner(sock)
            sock.close()
            return {"port": port, "state": "open", "service": service, "banner": banner}
        sock.close()
    except (socket.error, OSError):
        pass
    return None


def grab_banner(sock: socket.socket) -> str:
    """Attempt to grab service banner."""
    try:
        sock.settimeout(0.5)
        sock.send(b"\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        return banner[:100] if banner else ""
    except Exception:
        return ""


def scan(host: str, ports: list[int] = None, threads: int = 50, timeout: float = 1.0) -> dict:
    """Scan multiple ports on a host."""
    if ports is None:
        ports = sorted(COMMON_PORTS.keys())

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"error": f"Cannot resolve hostname: {host}"}

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    return {
        "host": host,
        "ip": ip,
        "scan_time": datetime.now().isoformat(),
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "risk_assessment": assess_risk(open_ports),
    }


def assess_risk(open_ports: list[dict]) -> list[str]:
    """Assess security risks based on open ports."""
    risks = []
    risky = {23: "Telnet is unencrypted", 21: "FTP is unencrypted", 135: "MSRPC exposed",
             139: "NetBIOS exposed", 445: "SMB exposed (WannaCry vector)",
             6379: "Redis exposed (often no auth)", 27017: "MongoDB exposed (often no auth)",
             11211: "Memcached exposed (DDoS amplification)"}
    for p in open_ports:
        if p["port"] in risky:
            risks.append(f"Port {p['port']}: {risky[p['port']]}")
    return risks if risks else ["No critical risks detected"]


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(f"TCP Port Scanner")
    print(f"Target: {target}")
    print(f"Scanning {len(COMMON_PORTS)} common ports...")
    print("-" * 50)

    results = scan(target)
    if "error" in results:
        print(f"Error: {results['error']}")
        sys.exit(1)

    print(f"Host: {results['host']} ({results['ip']})")
    print(f"\nOpen ports:")
    for p in results["open_ports"]:
        banner = f" | {p['banner']}" if p['banner'] else ""
        print(f"  {p['port']:>5}/tcp  {p['state']:<6}  {p['service']}{banner}")

    print(f"\nRisk Assessment:")
    for risk in results["risk_assessment"]:
        print(f"  - {risk}")
