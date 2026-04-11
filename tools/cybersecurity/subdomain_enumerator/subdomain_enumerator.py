#!/usr/bin/env python3
"""Subdomain Enumerator - Discovers subdomains via DNS resolution."""

import socket
import concurrent.futures
import sys
import json
from datetime import datetime

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
    "dns", "dns1", "dns2", "api", "dev", "staging", "test", "beta", "app",
    "admin", "portal", "blog", "shop", "store", "cdn", "static", "assets",
    "media", "img", "images", "docs", "wiki", "support", "help", "status",
    "monitor", "grafana", "prometheus", "jenkins", "ci", "cd", "git", "gitlab",
    "vpn", "remote", "ssh", "rdp", "db", "database", "mysql", "postgres",
    "redis", "elastic", "kibana", "log", "logs", "sentry", "auth", "sso",
    "login", "oauth", "id", "dashboard", "panel", "cpanel", "whm", "plesk",
    "mx", "mx1", "mx2", "relay", "backup", "bak", "old", "new", "v2",
    "sandbox", "demo", "internal", "intranet", "extranet", "proxy", "gateway",
    "edge", "node", "worker", "queue", "mq", "rabbitmq", "kafka", "vault",
    "s3", "storage", "upload", "download", "file", "files", "share",
    "calendar", "meet", "video", "chat", "slack", "teams", "jira", "confluence",
]


def resolve_subdomain(subdomain: str, domain: str) -> dict | None:
    """Try to resolve a subdomain and return its IP."""
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": ip}
    except socket.gaierror:
        return None


def enumerate(domain: str, wordlist: list[str] = None, threads: int = 20) -> list[dict]:
    """Enumerate subdomains for a given domain."""
    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(resolve_subdomain, sub, domain): sub
            for sub in wordlist
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda x: x["subdomain"])


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"Enumerating subdomains for: {domain}")
    print(f"Wordlist size: {len(COMMON_SUBDOMAINS)}")
    print(f"Started at: {datetime.now().isoformat()}")
    print("-" * 50)

    results = enumerate(domain)

    for r in results:
        print(f"  [FOUND] {r['subdomain']} -> {r['ip']}")

    print(f"\nTotal found: {len(results)}")
    print(json.dumps(results, indent=2))
