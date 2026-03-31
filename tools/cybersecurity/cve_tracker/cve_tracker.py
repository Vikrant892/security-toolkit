#!/usr/bin/env python3
"""CVE Tracker - Fetch latest vulnerabilities from NIST NVD and generate advisories."""

import urllib.request
import json
import sys
from datetime import datetime, timedelta


def fetch_recent_cves(days: int = 7, keyword: str = None, severity: str = None) -> list[dict]:
    """Fetch recent CVEs from NIST NVD API."""
    end = datetime.utcnow()
    start = end - timedelta(days=days)

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = [
        f"pubStartDate={start.strftime('%Y-%m-%dT00:00:00.000')}",
        f"pubEndDate={end.strftime('%Y-%m-%dT23:59:59.999')}",
        "resultsPerPage=20",
    ]
    if keyword:
        params.append(f"keywordSearch={keyword}")
    if severity:
        params.append(f"cvssV3Severity={severity.upper()}")

    url = f"{base_url}?{'&'.join(params)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityToolkit/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        return parse_cves(data)
    except Exception as e:
        return [{"error": str(e)}]


def parse_cves(data: dict) -> list[dict]:
    """Parse NVD API response into clean CVE records."""
    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

        metrics = cve.get("metrics", {})
        cvss_data = None
        severity = "N/A"
        score = 0.0

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss_data = metrics[version][0].get("cvssData", {})
                severity = metrics[version][0].get("baseSeverity",
                           cvss_data.get("baseSeverity", "N/A"))
                score = cvss_data.get("baseScore", 0.0)
                break

        references = [r.get("url") for r in cve.get("references", [])[:3]]

        cves.append({
            "id": cve_id,
            "description": desc[:300],
            "severity": severity,
            "score": score,
            "published": cve.get("published", "N/A")[:10],
            "references": references,
        })

    return sorted(cves, key=lambda x: x.get("score", 0), reverse=True)


def generate_advisory(cves: list[dict]) -> str:
    """Generate a security advisory report."""
    lines = [
        f"# Security Advisory - {datetime.utcnow().strftime('%Y-%m-%d')}",
        f"\nTotal CVEs found: {len(cves)}\n",
    ]

    severity_icons = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[~]"}

    for cve in cves:
        icon = severity_icons.get(cve["severity"], "[?]")
        lines.append(f"## {icon} {cve['id']} (Score: {cve['score']}, {cve['severity']})")
        lines.append(f"Published: {cve['published']}")
        lines.append(f"{cve['description']}")
        if cve.get("references"):
            lines.append(f"References: {', '.join(cve['references'][:2])}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    keyword = sys.argv[1] if len(sys.argv) > 1 else None
    severity = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"Fetching CVEs (last 7 days)...")
    if keyword:
        print(f"Keyword filter: {keyword}")
    if severity:
        print(f"Severity filter: {severity}")
    print()

    cves = fetch_recent_cves(keyword=keyword, severity=severity)

    if cves and "error" in cves[0]:
        print(f"Error fetching CVEs: {cves[0]['error']}")
        print("Tip: NVD API may rate-limit. Try again in 30 seconds.")
        sys.exit(1)

    advisory = generate_advisory(cves)
    print(advisory)
    print(f"\nTotal: {len(cves)} CVEs | Generated at {datetime.utcnow().isoformat()}Z")
