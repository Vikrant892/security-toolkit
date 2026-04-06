#!/usr/bin/env python3
"""API Health Monitor - Check uptime, latency, SSL certs, and generate reports."""

import urllib.request
import ssl
import socket
import json
import time
import sys
from datetime import datetime


def check_endpoint(url: str, timeout: int = 10) -> dict:
    """Check health of a single API endpoint."""
    result = {"url": url, "timestamp": datetime.utcnow().isoformat() + "Z"}
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HealthMonitor/1.0"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            elapsed = (time.time() - start) * 1000
            result["status_code"] = resp.status
            result["response_time_ms"] = round(elapsed, 2)
            result["healthy"] = 200 <= resp.status < 400
            result["headers"] = dict(resp.headers)
            content_length = resp.headers.get("Content-Length")
            result["content_length"] = int(content_length) if content_length else None
    except urllib.error.HTTPError as e:
        elapsed = (time.time() - start) * 1000
        result["status_code"] = e.code
        result["response_time_ms"] = round(elapsed, 2)
        result["healthy"] = False
        result["error"] = str(e.reason)
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        result["status_code"] = 0
        result["response_time_ms"] = round(elapsed, 2)
        result["healthy"] = False
        result["error"] = str(e)

    return result


def check_ssl_cert(hostname: str) -> dict:
    """Check SSL certificate details and expiry."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_until_expiry = (not_after - datetime.utcnow()).days
        return {
            "hostname": hostname,
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "expires": not_after.isoformat(),
            "days_until_expiry": days_until_expiry,
            "expired": days_until_expiry < 0,
            "warning": days_until_expiry < 30,
        }
    except Exception as e:
        return {"hostname": hostname, "error": str(e)}


def monitor_endpoints(urls: list[str]) -> dict:
    """Monitor multiple endpoints and generate a health report."""
    results = []
    ssl_results = []

    for url in urls:
        result = check_endpoint(url)
        results.append(result)
        if url.startswith("https://"):
            hostname = url.split("//")[1].split("/")[0].split(":")[0]
            ssl_info = check_ssl_cert(hostname)
            ssl_results.append(ssl_info)

    healthy = sum(1 for r in results if r["healthy"])
    avg_latency = sum(r["response_time_ms"] for r in results) / len(results) if results else 0

    return {
        "report_time": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_endpoints": len(results),
            "healthy": healthy,
            "unhealthy": len(results) - healthy,
            "uptime_pct": round(healthy / len(results) * 100, 1) if results else 0,
            "avg_latency_ms": round(avg_latency, 2),
        },
        "endpoints": results,
        "ssl_certificates": ssl_results,
        "overall_status": "HEALTHY" if healthy == len(results) else "DEGRADED" if healthy > 0 else "DOWN",
    }


DEFAULT_ENDPOINTS = [
    "https://httpbin.org/status/200",
    "https://httpbin.org/delay/1",
    "https://api.github.com",
    "https://jsonplaceholder.typicode.com/posts/1",
]


if __name__ == "__main__":
    urls = sys.argv[1:] if len(sys.argv) > 1 else DEFAULT_ENDPOINTS
    print(f"Monitoring {len(urls)} endpoints...\n")

    report = monitor_endpoints(urls)

    print(f"Overall: {report['overall_status']}")
    print(f"Uptime: {report['summary']['uptime_pct']}% | Avg latency: {report['summary']['avg_latency_ms']}ms\n")

    for ep in report["endpoints"]:
        icon = "+" if ep["healthy"] else "!"
        err = f" ({ep.get('error', '')})" if ep.get("error") else ""
        print(f"  [{icon}] {ep['status_code']} | {ep['response_time_ms']:>8}ms | {ep['url']}{err}")

    if report["ssl_certificates"]:
        print("\nSSL Certificates:")
        for cert in report["ssl_certificates"]:
            if "error" in cert:
                print(f"  [!] {cert['hostname']}: {cert['error']}")
            else:
                icon = "!" if cert["warning"] else "+"
                print(f"  [{icon}] {cert['hostname']}: expires in {cert['days_until_expiry']} days")
