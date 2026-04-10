#!/usr/bin/env python3
"""Log Anomaly Detector - Finds brute force, suspicious IPs, and unusual patterns."""

import re
from collections import defaultdict, Counter
from datetime import datetime
import json
import sys
import os


class LogAnalyzer:
    """Analyzes log files for security anomalies."""

    # Common log patterns
    PATTERNS = {
        "auth_failure": re.compile(r"(Failed password|authentication failure|invalid user|FAILED LOGIN)", re.I),
        "auth_success": re.compile(r"(Accepted password|session opened|Successful login)", re.I),
        "ip_address": re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
        "ssh_user": re.compile(r"(?:user[= ]|for )([a-zA-Z0-9._-]+)", re.I),
        "timestamp": re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"),
        "http_status": re.compile(r'\s(\d{3})\s'),
        "sql_injection": re.compile(r"(union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*--)", re.I),
        "path_traversal": re.compile(r"(\.\./|%2e%2e/|%252e%252e/)", re.I),
        "xss_attempt": re.compile(r"(<script|javascript:|on\w+\s*=)", re.I),
    }

    def __init__(self):
        self.failed_logins = defaultdict(list)  # IP -> [timestamps]
        self.successful_logins = defaultdict(list)
        self.users_targeted = defaultdict(set)  # IP -> set(usernames)
        self.attack_patterns = []
        self.ip_counter = Counter()
        self.line_count = 0

    def analyze_line(self, line: str):
        self.line_count += 1
        ip_match = self.PATTERNS["ip_address"].search(line)
        ip = ip_match.group(1) if ip_match else "unknown"
        self.ip_counter[ip] += 1

        # Check auth failures
        if self.PATTERNS["auth_failure"].search(line):
            self.failed_logins[ip].append(line.strip())
            user_match = self.PATTERNS["ssh_user"].search(line)
            if user_match:
                self.users_targeted[ip].add(user_match.group(1))

        # Check auth successes
        if self.PATTERNS["auth_success"].search(line):
            self.successful_logins[ip].append(line.strip())

        # Check web attacks
        for attack_name, pattern in [
            ("SQL Injection", self.PATTERNS["sql_injection"]),
            ("Path Traversal", self.PATTERNS["path_traversal"]),
            ("XSS Attempt", self.PATTERNS["xss_attempt"]),
        ]:
            if pattern.search(line):
                self.attack_patterns.append({
                    "type": attack_name,
                    "ip": ip,
                    "evidence": line.strip()[:200],
                })

    def analyze_file(self, filepath: str):
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                self.analyze_line(line)

    def get_report(self) -> dict:
        brute_force = {}
        for ip, failures in self.failed_logins.items():
            if len(failures) >= 5:
                brute_force[ip] = {
                    "attempts": len(failures),
                    "users_targeted": list(self.users_targeted.get(ip, set())),
                    "succeeded_after": ip in self.successful_logins,
                }

        return {
            "summary": {
                "total_lines": self.line_count,
                "unique_ips": len(self.ip_counter),
                "total_failed_logins": sum(len(v) for v in self.failed_logins.values()),
                "total_successful_logins": sum(len(v) for v in self.successful_logins.values()),
                "web_attacks_detected": len(self.attack_patterns),
            },
            "brute_force_suspects": brute_force,
            "top_offenders": dict(self.ip_counter.most_common(10)),
            "web_attacks": self.attack_patterns[:20],
            "risk_level": self._assess_risk(brute_force),
        }

    def _assess_risk(self, brute_force):
        if any(bf["succeeded_after"] for bf in brute_force.values()):
            return "CRITICAL - Brute force followed by successful login detected!"
        if len(self.attack_patterns) > 10:
            return "HIGH - Multiple web attack patterns detected"
        if brute_force:
            return "MEDIUM - Brute force attempts detected"
        if self.failed_logins:
            return "LOW - Some failed login attempts"
        return "MINIMAL - No significant anomalies"


def generate_sample_log():
    """Generate a sample log for testing."""
    lines = []
    lines.append("Mar 30 10:15:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2")
    lines.append("Mar 30 10:15:02 server sshd[1235]: Failed password for root from 192.168.1.100 port 22 ssh2")
    lines.append("Mar 30 10:15:03 server sshd[1236]: Failed password for admin from 192.168.1.100 port 22 ssh2")
    lines.append("Mar 30 10:15:04 server sshd[1237]: Failed password for root from 192.168.1.100 port 22 ssh2")
    lines.append("Mar 30 10:15:05 server sshd[1238]: Failed password for root from 192.168.1.100 port 22 ssh2")
    lines.append("Mar 30 10:15:06 server sshd[1239]: Failed password for root from 192.168.1.100 port 22 ssh2")
    lines.append("Mar 30 10:15:07 server sshd[1240]: Accepted password for root from 192.168.1.100 port 22 ssh2")
    lines.append("Mar 30 11:00:00 server httpd: 10.0.0.50 GET /search?q=1 OR 1=1-- HTTP/1.1 200")
    lines.append("Mar 30 11:00:01 server httpd: 10.0.0.50 GET /../../etc/passwd HTTP/1.1 403")
    lines.append("Mar 30 11:00:02 server httpd: 10.0.0.50 GET /page?x=<script>alert(1)</script> HTTP/1.1 200")
    lines.append("Mar 30 12:00:00 server sshd[2000]: Failed password for invalid user test from 10.0.0.99 port 22")
    lines.append("Mar 30 12:00:01 server sshd[2001]: Accepted password for deploy from 172.16.0.5 port 22 ssh2")
    return "\n".join(lines)


if __name__ == "__main__":
    analyzer = LogAnalyzer()

    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        analyzer.analyze_file(sys.argv[1])
    else:
        print("No log file provided. Using sample data for demo.\n")
        for line in generate_sample_log().split("\n"):
            analyzer.analyze_line(line)

    report = analyzer.get_report()
    print(json.dumps(report, indent=2))

    print(f"\n{'='*60}")
    print(f"RISK LEVEL: {report['risk_level']}")
    if report['brute_force_suspects']:
        print(f"\nBRUTE FORCE SUSPECTS:")
        for ip, info in report['brute_force_suspects'].items():
            status = "COMPROMISED!" if info['succeeded_after'] else "Blocked"
            print(f"  {ip}: {info['attempts']} attempts targeting {info['users_targeted']} - {status}")
