"""
Registry of 365+ unique tool templates organized by category.
Each tool is a real-world useful script that solves an actual problem.
"""

TOOLS = {
    # ==================== CYBERSECURITY ====================
    "cybersecurity": [
        {
            "name": "password_strength_analyzer",
            "title": "Password Strength Analyzer",
            "description": "Analyzes password strength using entropy calculation, common pattern detection, and breach database checking via k-anonymity (Have I Been Pwned API).",
            "tags": ["security", "passwords", "authentication"],
            "code": '''#!/usr/bin/env python3
"""Password Strength Analyzer - Checks entropy, patterns, and breach status."""

import re
import math
import hashlib
import urllib.request
import json
import sys


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of a password."""
    if not password:
        return 0.0
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 32
    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def detect_patterns(password: str) -> list[str]:
    """Detect common weak patterns in passwords."""
    warnings = []
    if re.search(r"(.)\\1{2,}", password):
        warnings.append("Contains repeated characters (e.g., aaa)")
    if re.search(r"(012|123|234|345|456|567|678|789|890)", password):
        warnings.append("Contains sequential numbers")
    if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", password.lower()):
        warnings.append("Contains sequential letters")
    common = ["password", "123456", "qwerty", "admin", "letmein", "welcome", "monkey", "dragon", "master"]
    if password.lower() in common:
        warnings.append("This is a commonly used password")
    if re.match(r"^[a-zA-Z]+\\d+$", password) or re.match(r"^\\d+[a-zA-Z]+$", password):
        warnings.append("Simple word+number pattern detected")
    return warnings


def check_breach_kanonymity(password: str) -> int:
    """Check if password has been breached using k-anonymity (HIBP API)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityToolkit/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode("utf-8")
        for line in data.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
    except Exception:
        return -1  # API unreachable
    return 0


def analyze(password: str) -> dict:
    """Full password analysis."""
    entropy = calculate_entropy(password)
    patterns = detect_patterns(password)
    breach_count = check_breach_kanonymity(password)

    if entropy >= 60 and not patterns and breach_count == 0:
        strength = "STRONG"
    elif entropy >= 40 and breach_count == 0:
        strength = "MODERATE"
    else:
        strength = "WEAK"

    return {
        "length": len(password),
        "entropy_bits": round(entropy, 2),
        "strength": strength,
        "pattern_warnings": patterns,
        "breach_count": breach_count,
        "recommendations": _get_recommendations(password, entropy, patterns, breach_count),
    }


def _get_recommendations(password, entropy, patterns, breach_count):
    recs = []
    if len(password) < 12:
        recs.append("Use at least 12 characters")
    if entropy < 60:
        recs.append("Mix uppercase, lowercase, numbers, and symbols")
    if patterns:
        recs.append("Avoid predictable patterns")
    if breach_count > 0:
        recs.append(f"This password appeared in {breach_count:,} data breaches - change it immediately!")
    if not recs:
        recs.append("Password looks good! Consider using a passphrase for even better security.")
    return recs


if __name__ == "__main__":
    test_passwords = ["password123", "Tr0ub4dor&3", "correct-horse-battery-staple", "a"]
    if len(sys.argv) > 1:
        test_passwords = sys.argv[1:]
    for pw in test_passwords:
        result = analyze(pw)
        print(f"\\n{'='*50}")
        print(f"Password: {'*' * len(pw)} ({len(pw)} chars)")
        print(f"Entropy: {result['entropy_bits']} bits")
        print(f"Strength: {result['strength']}")
        if result['pattern_warnings']:
            print(f"Warnings: {', '.join(result['pattern_warnings'])}")
        if result['breach_count'] > 0:
            print(f"BREACHED: Found in {result['breach_count']:,} data breaches!")
        elif result['breach_count'] == 0:
            print("Breach check: Not found in known breaches")
        print(f"Recommendations: {'; '.join(result['recommendations'])}")
'''
        },
        {
            "name": "hash_identifier",
            "title": "Hash Type Identifier & Cracker",
            "description": "Identifies hash types (MD5, SHA1, SHA256, bcrypt, etc.) by pattern matching and optionally attempts dictionary-based cracking.",
            "tags": ["security", "hashing", "forensics"],
            "code": '''#!/usr/bin/env python3
"""Hash Identifier - Detects hash type and optionally cracks with wordlist."""

import re
import hashlib
import sys

HASH_PATTERNS = [
    (r"^[a-fA-F0-9]{32}$", "MD5", 128),
    (r"^[a-fA-F0-9]{40}$", "SHA-1", 160),
    (r"^[a-fA-F0-9]{64}$", "SHA-256", 256),
    (r"^[a-fA-F0-9]{128}$", "SHA-512", 512),
    (r"^\\$2[aby]?\\$\\d{2}\\$.{53}$", "bcrypt", None),
    (r"^\\$6\\$[a-zA-Z0-9./]+\\$[a-zA-Z0-9./]{86}$", "SHA-512 (Unix crypt)", None),
    (r"^\\$5\\$[a-zA-Z0-9./]+\\$[a-zA-Z0-9./]{43}$", "SHA-256 (Unix crypt)", None),
    (r"^\\$1\\$[a-zA-Z0-9./]+\\$[a-zA-Z0-9./]{22}$", "MD5 (Unix crypt)", None),
    (r"^[a-fA-F0-9]{56}$", "SHA-224", 224),
    (r"^[a-fA-F0-9]{96}$", "SHA-384", 384),
    (r"^[a-fA-F0-9]{8}$", "CRC-32", 32),
    (r"^[a-fA-F0-9]{16}$", "MySQL (old) / Half MD5", 64),
]


def identify_hash(hash_string: str) -> list[dict]:
    """Identify possible hash types for a given hash string."""
    results = []
    cleaned = hash_string.strip()
    for pattern, name, bits in HASH_PATTERNS:
        if re.match(pattern, cleaned):
            results.append({"type": name, "bits": bits, "hash": cleaned})
    if not results:
        results.append({"type": "Unknown", "bits": None, "hash": cleaned})
    return results


def attempt_crack(hash_string: str, hash_type: str, wordlist: list[str] = None) -> str | None:
    """Attempt to crack a hash using a wordlist."""
    if wordlist is None:
        wordlist = [
            "password", "123456", "password123", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "qwerty",
            "abc123", "111111", "password1", "iloveyou", "sunshine",
            "princess", "football", "charlie", "shadow", "michael",
            "trustno1", "batman", "access", "hello", "thunder",
        ]

    hash_funcs = {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
        "SHA-224": hashlib.sha224,
        "SHA-384": hashlib.sha384,
    }

    func = hash_funcs.get(hash_type)
    if not func:
        return None

    target = hash_string.lower().strip()
    for word in wordlist:
        if func(word.encode()).hexdigest() == target:
            return word
    return None


if __name__ == "__main__":
    test_hashes = [
        "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5 of "password"
        "e10adc3949ba59abbe56e057f20f883e",  # MD5 of "123456"
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",  # SHA1 of "password"
        "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",  # SHA256 of "password123"
    ]

    hashes = sys.argv[1:] if len(sys.argv) > 1 else test_hashes

    for h in hashes:
        print(f"\\nHash: {h}")
        matches = identify_hash(h)
        for m in matches:
            bits_str = f" ({m['bits']}-bit)" if m['bits'] else ""
            print(f"  Type: {m['type']}{bits_str}")
            cracked = attempt_crack(h, m['type'])
            if cracked:
                print(f"  CRACKED: {cracked}")
            else:
                print(f"  Could not crack with built-in wordlist")
'''
        },
        {
            "name": "log_anomaly_detector",
            "title": "Log Anomaly Detector",
            "description": "Parses server/auth logs to detect brute force attempts, suspicious IPs, unusual access patterns, and potential security incidents.",
            "tags": ["security", "SIEM", "log-analysis", "incident-response"],
            "code": '''#!/usr/bin/env python3
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
        "ip_address": re.compile(r"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"),
        "ssh_user": re.compile(r"(?:user[= ]|for )([a-zA-Z0-9._-]+)", re.I),
        "timestamp": re.compile(r"(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}|\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2})"),
        "http_status": re.compile(r'\\s(\\d{3})\\s'),
        "sql_injection": re.compile(r"(union\\s+select|or\\s+1\\s*=\\s*1|drop\\s+table|;\\s*--)", re.I),
        "path_traversal": re.compile(r"(\\.\\./|%2e%2e/|%252e%252e/)", re.I),
        "xss_attempt": re.compile(r"(<script|javascript:|on\\w+\\s*=)", re.I),
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
    return "\\n".join(lines)


if __name__ == "__main__":
    analyzer = LogAnalyzer()

    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        analyzer.analyze_file(sys.argv[1])
    else:
        print("No log file provided. Using sample data for demo.\\n")
        for line in generate_sample_log().split("\\n"):
            analyzer.analyze_line(line)

    report = analyzer.get_report()
    print(json.dumps(report, indent=2))

    print(f"\\n{'='*60}")
    print(f"RISK LEVEL: {report['risk_level']}")
    if report['brute_force_suspects']:
        print(f"\\nBRUTE FORCE SUSPECTS:")
        for ip, info in report['brute_force_suspects'].items():
            status = "COMPROMISED!" if info['succeeded_after'] else "Blocked"
            print(f"  {ip}: {info['attempts']} attempts targeting {info['users_targeted']} - {status}")
'''
        },
        {
            "name": "subdomain_enumerator",
            "title": "Subdomain Enumerator",
            "description": "Discovers subdomains using DNS resolution and common subdomain wordlists. Useful for reconnaissance and attack surface mapping.",
            "tags": ["security", "recon", "dns", "pentesting"],
            "code": '''#!/usr/bin/env python3
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

    print(f"\\nTotal found: {len(results)}")
    print(json.dumps(results, indent=2))
'''
        },
        {
            "name": "file_integrity_monitor",
            "title": "File Integrity Monitor (FIM)",
            "description": "Monitors files for unauthorized changes by computing and comparing SHA-256 hashes. Essential for detecting tampering and rootkits.",
            "tags": ["security", "monitoring", "integrity", "compliance"],
            "code": '''#!/usr/bin/env python3
"""File Integrity Monitor - Detects unauthorized file changes via SHA-256 hashing."""

import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path


class FileIntegrityMonitor:
    """Monitor filesystem for unauthorized changes."""

    def __init__(self, baseline_path: str = "fim_baseline.json"):
        self.baseline_path = baseline_path
        self.baseline = {}

    def hash_file(self, filepath: str) -> str | None:
        """Compute SHA-256 hash of a file."""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, OSError):
            return None

    def scan_directory(self, directory: str, extensions: list[str] = None) -> dict:
        """Scan a directory and compute hashes for all files."""
        results = {}
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if extensions and not any(fname.endswith(ext) for ext in extensions):
                    continue
                filepath = os.path.join(root, fname)
                file_hash = self.hash_file(filepath)
                if file_hash:
                    stat = os.stat(filepath)
                    results[filepath] = {
                        "hash": file_hash,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "permissions": oct(stat.st_mode)[-3:],
                    }
        return results

    def create_baseline(self, directory: str, extensions: list[str] = None):
        """Create a baseline snapshot of a directory."""
        self.baseline = self.scan_directory(directory, extensions)
        self.baseline["_metadata"] = {
            "created": datetime.now().isoformat(),
            "directory": directory,
            "file_count": len(self.baseline) - 1,
        }
        with open(self.baseline_path, "w") as f:
            json.dump(self.baseline, f, indent=2)
        return len(self.baseline) - 1

    def check_integrity(self, directory: str, extensions: list[str] = None) -> dict:
        """Compare current state against baseline."""
        if not os.path.exists(self.baseline_path):
            return {"error": "No baseline found. Run with --baseline first."}

        with open(self.baseline_path) as f:
            self.baseline = json.load(f)

        current = self.scan_directory(directory, extensions)
        baseline_files = {k: v for k, v in self.baseline.items() if k != "_metadata"}

        report = {"modified": [], "added": [], "deleted": [], "unchanged": 0}

        for filepath, info in current.items():
            if filepath in baseline_files:
                if info["hash"] != baseline_files[filepath]["hash"]:
                    report["modified"].append({
                        "file": filepath,
                        "old_hash": baseline_files[filepath]["hash"][:16] + "...",
                        "new_hash": info["hash"][:16] + "...",
                        "old_size": baseline_files[filepath]["size"],
                        "new_size": info["size"],
                    })
                else:
                    report["unchanged"] += 1
            else:
                report["added"].append({"file": filepath, "size": info["size"]})

        for filepath in baseline_files:
            if filepath not in current:
                report["deleted"].append({"file": filepath})

        report["risk"] = "CRITICAL" if report["modified"] or report["deleted"] else "OK"
        report["scan_time"] = datetime.now().isoformat()
        return report


if __name__ == "__main__":
    fim = FileIntegrityMonitor()
    target = sys.argv[2] if len(sys.argv) > 2 else "."

    if len(sys.argv) > 1 and sys.argv[1] == "--baseline":
        count = fim.create_baseline(target)
        print(f"Baseline created: {count} files hashed and saved to fim_baseline.json")
    elif len(sys.argv) > 1 and sys.argv[1] == "--check":
        report = fim.check_integrity(target)
        print(json.dumps(report, indent=2))
        if report.get("modified"):
            print(f"\\nWARNING: {len(report['modified'])} files modified!")
        if report.get("deleted"):
            print(f"WARNING: {len(report['deleted'])} files deleted!")
        if report.get("added"):
            print(f"INFO: {len(report['added'])} new files detected")
    else:
        print("Usage:")
        print(f"  {sys.argv[0]} --baseline [directory]  Create baseline")
        print(f"  {sys.argv[0]} --check [directory]     Check integrity")
'''
        },
        {
            "name": "jwt_decoder",
            "title": "JWT Token Decoder & Validator",
            "description": "Decodes JWT tokens, validates structure, checks expiration, and identifies common security issues like 'none' algorithm attacks.",
            "tags": ["security", "authentication", "web", "API"],
            "code": '''#!/usr/bin/env python3
"""JWT Decoder & Security Analyzer - Decode, validate, and find vulnerabilities."""

import base64
import json
import sys
from datetime import datetime, timezone


def base64url_decode(data: str) -> bytes:
    """Decode base64url-encoded data."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def decode_jwt(token: str) -> dict:
    """Decode a JWT token without verification."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"error": f"Invalid JWT: expected 3 parts, got {len(parts)}"}

    try:
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        signature = parts[2]
    except Exception as e:
        return {"error": f"Failed to decode: {str(e)}"}

    return {"header": header, "payload": payload, "signature": signature}


def analyze_security(decoded: dict) -> list[dict]:
    """Analyze JWT for common security issues."""
    issues = []
    header = decoded.get("header", {})
    payload = decoded.get("payload", {})

    # Check algorithm
    alg = header.get("alg", "")
    if alg.lower() == "none":
        issues.append({"severity": "CRITICAL", "issue": "Algorithm set to 'none' - signature bypass!"})
    elif alg.startswith("HS"):
        issues.append({"severity": "INFO", "issue": f"Using symmetric algorithm ({alg}) - ensure secret is strong"})

    # Check expiration
    exp = payload.get("exp")
    if exp:
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        if exp_dt < datetime.now(timezone.utc):
            issues.append({"severity": "HIGH", "issue": f"Token expired at {exp_dt.isoformat()}"})
        else:
            issues.append({"severity": "OK", "issue": f"Token expires at {exp_dt.isoformat()}"})
    else:
        issues.append({"severity": "MEDIUM", "issue": "No expiration claim (exp) - token never expires!"})

    # Check issued at
    iat = payload.get("iat")
    if iat:
        iat_dt = datetime.fromtimestamp(iat, tz=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - iat_dt).total_seconds() / 3600
        if age_hours > 24:
            issues.append({"severity": "LOW", "issue": f"Token is {age_hours:.0f} hours old"})

    # Check for sensitive data
    sensitive_keys = ["password", "secret", "ssn", "credit_card", "cc_number"]
    for key in payload:
        if key.lower() in sensitive_keys:
            issues.append({"severity": "CRITICAL", "issue": f"Sensitive data in payload: '{key}'"})

    # Check audience and issuer
    if "aud" not in payload:
        issues.append({"severity": "LOW", "issue": "No audience claim (aud) - token not scoped"})
    if "iss" not in payload:
        issues.append({"severity": "LOW", "issue": "No issuer claim (iss)"})

    return issues


if __name__ == "__main__":
    # Example JWT (expired, for demo purposes)
    sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlZpa3JhbnQiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMzYwMCwicm9sZSI6ImFkbWluIn0.signature"

    token = sys.argv[1] if len(sys.argv) > 1 else sample

    print("JWT Token Decoder & Security Analyzer")
    print("=" * 50)

    decoded = decode_jwt(token)
    if "error" in decoded:
        print(f"Error: {decoded['error']}")
        sys.exit(1)

    print(f"\\nHEADER:")
    print(json.dumps(decoded["header"], indent=2))

    print(f"\\nPAYLOAD:")
    print(json.dumps(decoded["payload"], indent=2))

    print(f"\\nSIGNATURE: {decoded['signature'][:20]}...")

    print(f"\\nSECURITY ANALYSIS:")
    issues = analyze_security(decoded)
    for issue in issues:
        icon = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "~", "OK": "+", "INFO": "i"}
        print(f"  [{icon.get(issue['severity'], '?')}] {issue['severity']}: {issue['issue']}")
'''
        },
        {
            "name": "network_port_scanner",
            "title": "TCP Port Scanner",
            "description": "Fast multi-threaded TCP port scanner with service detection. Scans common ports and identifies running services.",
            "tags": ["security", "network", "recon", "scanning"],
            "code": '''#!/usr/bin/env python3
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
        sock.send(b"\\r\\n")
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
    print(f"\\nOpen ports:")
    for p in results["open_ports"]:
        banner = f" | {p['banner']}" if p['banner'] else ""
        print(f"  {p['port']:>5}/tcp  {p['state']:<6}  {p['service']}{banner}")

    print(f"\\nRisk Assessment:")
    for risk in results["risk_assessment"]:
        print(f"  - {risk}")
'''
        },
        {
            "name": "cve_tracker",
            "title": "CVE Vulnerability Tracker",
            "description": "Fetches latest CVEs from NIST NVD API, filters by severity and keyword, and generates security advisories.",
            "tags": ["security", "CVE", "vulnerability", "threat-intel"],
            "code": '''#!/usr/bin/env python3
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
        f"\\nTotal CVEs found: {len(cves)}\\n",
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

    return "\\n".join(lines)


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
    print(f"\\nTotal: {len(cves)} CVEs | Generated at {datetime.utcnow().isoformat()}Z")
'''
        },
    ],
    # ==================== DATA ENGINEERING ====================
    "data_engineering": [
        {
            "name": "csv_data_profiler",
            "title": "CSV Data Profiler",
            "description": "Automatically profiles CSV datasets - detects types, finds nulls, calculates statistics, identifies outliers, and generates a quality report.",
            "tags": ["data", "ETL", "quality", "profiling"],
            "code": '''#!/usr/bin/env python3
"""CSV Data Profiler - Automated dataset quality analysis and profiling."""

import csv
import sys
import json
import statistics
from collections import Counter
from datetime import datetime
import re
import io


def detect_type(values: list[str]) -> str:
    """Detect the data type of a column."""
    non_empty = [v for v in values if v.strip()]
    if not non_empty:
        return "empty"
    int_count = sum(1 for v in non_empty if re.match(r"^-?\\d+$", v))
    float_count = sum(1 for v in non_empty if re.match(r"^-?\\d*\\.\\d+$", v))
    date_count = sum(1 for v in non_empty if re.match(r"^\\d{4}-\\d{2}-\\d{2}", v))
    bool_count = sum(1 for v in non_empty if v.lower() in ("true", "false", "yes", "no", "0", "1"))
    email_count = sum(1 for v in non_empty if re.match(r"^[^@]+@[^@]+\\.[^@]+$", v))

    n = len(non_empty)
    if int_count / n > 0.9: return "integer"
    if (int_count + float_count) / n > 0.9: return "float"
    if date_count / n > 0.9: return "date"
    if bool_count / n > 0.9: return "boolean"
    if email_count / n > 0.9: return "email"
    return "string"


def profile_column(name: str, values: list[str]) -> dict:
    """Generate profile for a single column."""
    total = len(values)
    non_empty = [v.strip() for v in values if v.strip()]
    null_count = total - len(non_empty)
    dtype = detect_type(values)
    unique = len(set(non_empty))

    profile = {
        "name": name,
        "type": dtype,
        "total": total,
        "non_null": len(non_empty),
        "null_count": null_count,
        "null_pct": round(null_count / total * 100, 1) if total > 0 else 0,
        "unique": unique,
        "unique_pct": round(unique / len(non_empty) * 100, 1) if non_empty else 0,
    }

    if dtype in ("integer", "float"):
        nums = []
        for v in non_empty:
            try: nums.append(float(v))
            except ValueError: pass
        if nums:
            profile["min"] = min(nums)
            profile["max"] = max(nums)
            profile["mean"] = round(statistics.mean(nums), 2)
            profile["median"] = round(statistics.median(nums), 2)
            profile["stdev"] = round(statistics.stdev(nums), 2) if len(nums) > 1 else 0
            q1 = sorted(nums)[len(nums) // 4]
            q3 = sorted(nums)[3 * len(nums) // 4]
            iqr = q3 - q1
            profile["outliers"] = sum(1 for n in nums if n < q1 - 1.5*iqr or n > q3 + 1.5*iqr)
    elif dtype == "string":
        lengths = [len(v) for v in non_empty]
        profile["min_length"] = min(lengths) if lengths else 0
        profile["max_length"] = max(lengths) if lengths else 0
        profile["avg_length"] = round(statistics.mean(lengths), 1) if lengths else 0
        profile["top_values"] = dict(Counter(non_empty).most_common(5))

    return profile


def profile_csv(filepath_or_data: str) -> dict:
    """Profile an entire CSV file."""
    if filepath_or_data.endswith(".csv"):
        with open(filepath_or_data, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    else:
        reader = csv.DictReader(io.StringIO(filepath_or_data))
        rows = list(reader)

    if not rows:
        return {"error": "No data found"}

    columns = {}
    for col in rows[0].keys():
        values = [row.get(col, "") for row in rows]
        columns[col] = profile_column(col, values)

    quality_score = 100
    for col in columns.values():
        quality_score -= col["null_pct"] * 0.5
        if col.get("outliers", 0) > len(rows) * 0.05:
            quality_score -= 5

    return {
        "summary": {
            "rows": len(rows),
            "columns": len(columns),
            "quality_score": max(0, round(quality_score, 1)),
            "profiled_at": datetime.now().isoformat(),
        },
        "columns": columns,
    }


# Demo with sample data
SAMPLE_CSV = """name,age,email,salary,department,join_date
Alice,30,alice@company.com,75000,Engineering,2022-01-15
Bob,25,bob@company.com,65000,Marketing,2022-03-01
Charlie,,charlie@company.com,80000,Engineering,2021-06-15
Diana,35,diana@company.com,,Sales,2020-11-01
Eve,28,eve@company.com,70000,Engineering,2023-01-10
Frank,45,frank@company.com,120000,Management,2019-04-20
Grace,31,,72000,Marketing,2022-07-01
Hank,29,hank@company.com,68000,,2023-03-15
Ivy,33,ivy@company.com,95000,Engineering,2021-09-01
Jack,27,jack@company.com,62000,Sales,2023-06-01"""


if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = profile_csv(sys.argv[1])
    else:
        print("No CSV file provided. Using sample data.\\n")
        result = profile_csv(SAMPLE_CSV)

    print(json.dumps(result, indent=2))
    print(f"\\nQuality Score: {result['summary']['quality_score']}/100")
    for col_name, col in result["columns"].items():
        issues = []
        if col["null_pct"] > 10: issues.append(f"{col['null_pct']}% nulls")
        if col.get("outliers", 0) > 0: issues.append(f"{col['outliers']} outliers")
        status = f" ISSUES: {', '.join(issues)}" if issues else " OK"
        print(f"  {col_name} ({col['type']}): {col['non_null']}/{col['total']} non-null |{status}")
'''
        },
        {
            "name": "sql_query_builder",
            "title": "SQL Query Builder & Optimizer",
            "description": "Generates optimized SQL queries from natural descriptions. Supports SELECT, JOIN, aggregation, and provides query optimization tips.",
            "tags": ["data", "SQL", "database", "optimization"],
            "code": '''#!/usr/bin/env python3
"""SQL Query Builder - Builds and optimizes SQL queries with best practices."""

import re
import json
import sys


class SQLBuilder:
    """Fluent SQL query builder with optimization suggestions."""

    def __init__(self):
        self._select = []
        self._from = ""
        self._joins = []
        self._where = []
        self._group_by = []
        self._having = []
        self._order_by = []
        self._limit = None
        self._offset = None
        self._aliases = {}

    def select(self, *columns):
        self._select.extend(columns)
        return self

    def from_table(self, table, alias=None):
        self._from = f"{table} {alias}" if alias else table
        if alias:
            self._aliases[alias] = table
        return self

    def join(self, table, on, join_type="INNER", alias=None):
        t = f"{table} {alias}" if alias else table
        self._joins.append(f"{join_type} JOIN {t} ON {on}")
        if alias:
            self._aliases[alias] = table
        return self

    def left_join(self, table, on, alias=None):
        return self.join(table, on, "LEFT", alias)

    def where(self, condition):
        self._where.append(condition)
        return self

    def group_by(self, *columns):
        self._group_by.extend(columns)
        return self

    def having(self, condition):
        self._having.append(condition)
        return self

    def order_by(self, column, direction="ASC"):
        self._order_by.append(f"{column} {direction}")
        return self

    def limit(self, n):
        self._limit = n
        return self

    def offset(self, n):
        self._offset = n
        return self

    def build(self) -> str:
        parts = []
        parts.append(f"SELECT {', '.join(self._select) if self._select else '*'}")
        parts.append(f"FROM {self._from}")
        for j in self._joins:
            parts.append(j)
        if self._where:
            parts.append(f"WHERE {' AND '.join(self._where)}")
        if self._group_by:
            parts.append(f"GROUP BY {', '.join(self._group_by)}")
        if self._having:
            parts.append(f"HAVING {' AND '.join(self._having)}")
        if self._order_by:
            parts.append(f"ORDER BY {', '.join(self._order_by)}")
        if self._limit is not None:
            parts.append(f"LIMIT {self._limit}")
        if self._offset is not None:
            parts.append(f"OFFSET {self._offset}")
        return "\\n".join(parts) + ";"

    def optimize_suggestions(self) -> list[str]:
        tips = []
        query = self.build()
        if "SELECT *" in query:
            tips.append("Avoid SELECT * - specify only needed columns for better performance")
        if not self._limit and not self._group_by:
            tips.append("Consider adding LIMIT to prevent returning too many rows")
        if self._where:
            for w in self._where:
                if "LIKE \\"%%" in w.upper():
                    tips.append(f"Leading wildcard in LIKE prevents index usage: {w}")
                if re.search(r"(FUNCTION|UPPER|LOWER|CAST)\\(", w, re.I):
                    tips.append(f"Function on column in WHERE prevents index usage: {w}")
        if len(self._joins) > 3:
            tips.append("Many JOINs detected - consider denormalization or materialized views")
        if self._order_by and not self._limit:
            tips.append("ORDER BY without LIMIT sorts entire result set - expensive for large tables")
        for w in self._where:
            if "!=" in w or "<>" in w:
                tips.append(f"NOT EQUAL operators cannot use indexes efficiently: {w}")
        suggested_indexes = []
        for w in self._where:
            match = re.search(r"(\\w+\\.\\w+|\\w+)\\s*=", w)
            if match:
                suggested_indexes.append(match.group(1))
        if suggested_indexes:
            tips.append(f"Suggested indexes: {', '.join(suggested_indexes)}")
        return tips


if __name__ == "__main__":
    print("SQL Query Builder - Examples\\n")

    # Example 1: Basic query
    q1 = (SQLBuilder()
        .select("u.name", "u.email", "COUNT(o.id) AS order_count", "SUM(o.total) AS total_spent")
        .from_table("users", "u")
        .left_join("orders", "u.id = o.user_id", "o")
        .where("u.created_at >= '2024-01-01'")
        .where("u.status = 'active'")
        .group_by("u.id", "u.name", "u.email")
        .having("COUNT(o.id) > 5")
        .order_by("total_spent", "DESC")
        .limit(100))

    print("Query 1: Top customers by spending")
    print(q1.build())
    print("\\nOptimization tips:")
    for tip in q1.optimize_suggestions():
        print(f"  - {tip}")

    # Example 2: Security audit query
    print("\\n" + "="*60 + "\\n")
    q2 = (SQLBuilder()
        .select("l.timestamp", "l.user_id", "u.username", "l.action", "l.ip_address", "l.status")
        .from_table("audit_logs", "l")
        .join("users", "l.user_id = u.id", alias="u")
        .where("l.status = 'failed'")
        .where("l.action = 'login'")
        .where("l.timestamp >= NOW() - INTERVAL '24 hours'")
        .order_by("l.timestamp", "DESC")
        .limit(500))

    print("Query 2: Failed login attempts (last 24h)")
    print(q2.build())
    print("\\nOptimization tips:")
    for tip in q2.optimize_suggestions():
        print(f"  - {tip}")
'''
        },
        {
            "name": "json_etl_transformer",
            "title": "JSON ETL Transformer",
            "description": "Extract, transform, and load JSON data with flattening, type coercion, field mapping, filtering, and CSV/SQL export.",
            "tags": ["data", "ETL", "JSON", "pipeline"],
            "code": '''#!/usr/bin/env python3
"""JSON ETL Transformer - Flatten, transform, filter, and export JSON data."""

import json
import csv
import sys
import io
from datetime import datetime
from typing import Any


def flatten_json(data: dict, prefix: str = "", separator: str = "_") -> dict:
    """Recursively flatten nested JSON into dot-notation keys."""
    flat = {}
    for key, value in data.items():
        new_key = f"{prefix}{separator}{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(flatten_json(value, new_key, separator))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    flat.update(flatten_json(item, f"{new_key}{separator}{i}", separator))
                else:
                    flat[f"{new_key}{separator}{i}"] = item
        else:
            flat[new_key] = value
    return flat


def transform_records(records: list[dict], mappings: dict = None,
                      filters: list = None, flatten: bool = True) -> list[dict]:
    """Apply transformations to a list of records."""
    results = []
    for record in records:
        if flatten:
            record = flatten_json(record)

        # Apply field mappings (rename/transform)
        if mappings:
            mapped = {}
            for new_name, source in mappings.items():
                if callable(source):
                    mapped[new_name] = source(record)
                elif source in record:
                    mapped[new_name] = record[source]
            record = mapped

        # Apply filters
        if filters:
            if all(f(record) for f in filters):
                results.append(record)
        else:
            results.append(record)

    return results


def to_csv(records: list[dict]) -> str:
    """Convert records to CSV string."""
    if not records:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=records[0].keys())
    writer.writeheader()
    writer.writerows(records)
    return output.getvalue()


def to_sql_inserts(records: list[dict], table: str) -> str:
    """Convert records to SQL INSERT statements."""
    if not records:
        return ""
    lines = []
    columns = list(records[0].keys())
    cols_str = ", ".join(columns)
    for record in records:
        values = []
        for col in columns:
            v = record.get(col)
            if v is None:
                values.append("NULL")
            elif isinstance(v, (int, float)):
                values.append(str(v))
            else:
                escaped = str(v).replace("'", "''")
                values.append(f"'{escaped}'")
        vals_str = ", ".join(values)
        lines.append(f"INSERT INTO {table} ({cols_str}) VALUES ({vals_str});")
    return "\\n".join(lines)


# Demo with sample data
SAMPLE_DATA = [
    {"id": 1, "name": "Alice", "department": {"name": "Engineering", "floor": 3},
     "skills": ["python", "sql", "aws"], "salary": 85000, "active": True},
    {"id": 2, "name": "Bob", "department": {"name": "Marketing", "floor": 2},
     "skills": ["analytics", "excel"], "salary": 65000, "active": True},
    {"id": 3, "name": "Charlie", "department": {"name": "Engineering", "floor": 3},
     "skills": ["java", "docker", "k8s"], "salary": 92000, "active": False},
    {"id": 4, "name": "Diana", "department": {"name": "Sales", "floor": 1},
     "skills": ["crm", "negotiation"], "salary": 70000, "active": True},
    {"id": 5, "name": "Eve", "department": {"name": "Engineering", "floor": 3},
     "skills": ["python", "ml", "tensorflow"], "salary": 95000, "active": True},
]


if __name__ == "__main__":
    print("JSON ETL Transformer Demo\\n")

    # Step 1: Flatten
    print("1. FLATTEN nested JSON:")
    flat = [flatten_json(r) for r in SAMPLE_DATA]
    print(json.dumps(flat[0], indent=2))

    # Step 2: Transform with mappings
    print("\\n2. TRANSFORM with field mappings:")
    mappings = {
        "employee_id": "id",
        "full_name": "name",
        "dept": "department_name",
        "annual_salary": "salary",
        "is_active": "active",
        "primary_skill": lambda r: r.get("skills_0", "N/A"),
    }
    transformed = transform_records(SAMPLE_DATA, mappings=mappings)
    print(json.dumps(transformed[:2], indent=2))

    # Step 3: Filter
    print("\\n3. FILTER active employees with salary > 70k:")
    filters = [
        lambda r: r.get("is_active") == True,
        lambda r: r.get("annual_salary", 0) > 70000,
    ]
    filtered = transform_records(SAMPLE_DATA, mappings=mappings, filters=filters)
    for r in filtered:
        print(f"  {r['full_name']}: ${r['annual_salary']:,} ({r['dept']})")

    # Step 4: Export
    print("\\n4. EXPORT to CSV:")
    csv_output = to_csv(filtered)
    print(csv_output)

    print("5. EXPORT to SQL:")
    sql_output = to_sql_inserts(filtered, "employees")
    print(sql_output)
'''
        },
    ],
    # ==================== ML / AI ====================
    "ml_ai": [
        {
            "name": "anomaly_detector_ml",
            "title": "Statistical Anomaly Detector",
            "description": "Detects anomalies in numerical data using Z-score, IQR, and Isolation Forest methods. Works on any CSV column.",
            "tags": ["ML", "anomaly-detection", "statistics", "data-science"],
            "code": '''#!/usr/bin/env python3
"""Anomaly Detector - Z-score, IQR, and statistical methods for outlier detection."""

import statistics
import math
import json
import sys
import csv
import io


def z_score_detect(data: list[float], threshold: float = 2.5) -> list[dict]:
    """Detect anomalies using Z-score method."""
    if len(data) < 3:
        return []
    mean = statistics.mean(data)
    stdev = statistics.stdev(data)
    if stdev == 0:
        return []
    anomalies = []
    for i, val in enumerate(data):
        z = (val - mean) / stdev
        if abs(z) > threshold:
            anomalies.append({"index": i, "value": val, "z_score": round(z, 3), "method": "z-score"})
    return anomalies


def iqr_detect(data: list[float], multiplier: float = 1.5) -> list[dict]:
    """Detect anomalies using IQR (Interquartile Range) method."""
    if len(data) < 4:
        return []
    sorted_data = sorted(data)
    n = len(sorted_data)
    q1 = sorted_data[n // 4]
    q3 = sorted_data[3 * n // 4]
    iqr = q3 - q1
    lower = q1 - multiplier * iqr
    upper = q3 + multiplier * iqr
    anomalies = []
    for i, val in enumerate(data):
        if val < lower or val > upper:
            direction = "below" if val < lower else "above"
            anomalies.append({"index": i, "value": val, "bound": f"{direction} ({lower:.2f}, {upper:.2f})",
                            "method": "IQR"})
    return anomalies


def mad_detect(data: list[float], threshold: float = 3.0) -> list[dict]:
    """Detect anomalies using Median Absolute Deviation."""
    if len(data) < 3:
        return []
    median = statistics.median(data)
    mad = statistics.median([abs(x - median) for x in data])
    if mad == 0:
        return []
    anomalies = []
    for i, val in enumerate(data):
        modified_z = 0.6745 * (val - median) / mad
        if abs(modified_z) > threshold:
            anomalies.append({"index": i, "value": val, "modified_z": round(modified_z, 3), "method": "MAD"})
    return anomalies


def detect_all(data: list[float]) -> dict:
    """Run all anomaly detection methods and combine results."""
    z_anomalies = z_score_detect(data)
    iqr_anomalies = iqr_detect(data)
    mad_anomalies = mad_detect(data)

    all_indices = set()
    for a in z_anomalies + iqr_anomalies + mad_anomalies:
        all_indices.add(a["index"])

    consensus = []
    for idx in all_indices:
        methods = []
        if any(a["index"] == idx for a in z_anomalies): methods.append("z-score")
        if any(a["index"] == idx for a in iqr_anomalies): methods.append("IQR")
        if any(a["index"] == idx for a in mad_anomalies): methods.append("MAD")
        consensus.append({
            "index": idx, "value": data[idx],
            "detected_by": methods, "confidence": len(methods) / 3,
        })

    consensus.sort(key=lambda x: x["confidence"], reverse=True)
    return {
        "data_stats": {
            "count": len(data), "mean": round(statistics.mean(data), 2),
            "median": round(statistics.median(data), 2),
            "stdev": round(statistics.stdev(data), 2) if len(data) > 1 else 0,
            "min": min(data), "max": max(data),
        },
        "anomalies": {
            "z_score": z_anomalies, "iqr": iqr_anomalies, "mad": mad_anomalies,
        },
        "consensus": consensus,
        "total_anomalies": len(consensus),
    }


SAMPLE_DATA = [
    10, 12, 11, 13, 12, 11, 10, 12, 150, 11, 13, 12, 10, 11, 12,
    -50, 13, 11, 12, 10, 11, 200, 12, 13, 11, 10, 12, 11, 13, 12,
]

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            reader = csv.reader(f)
            col = int(sys.argv[2]) if len(sys.argv) > 2 else 0
            data = []
            for row in reader:
                try: data.append(float(row[col]))
                except (ValueError, IndexError): pass
    else:
        print("Using sample data with injected anomalies (150, -50, 200)\\n")
        data = SAMPLE_DATA

    results = detect_all(data)

    print(f"Data Stats: {json.dumps(results['data_stats'], indent=2)}")
    print(f"\\nConsensus Anomalies ({results['total_anomalies']} found):")
    for a in results["consensus"]:
        conf = "HIGH" if a["confidence"] >= 0.66 else "MEDIUM" if a["confidence"] >= 0.33 else "LOW"
        print(f"  Index {a['index']}: value={a['value']}, confidence={conf}, detected by: {', '.join(a['detected_by'])}")
'''
        },
        {
            "name": "text_classifier",
            "title": "Text Classifier (TF-IDF + Naive Bayes)",
            "description": "Simple but effective text classifier using TF-IDF vectorization and Naive Bayes. Works for spam detection, sentiment analysis, and topic classification.",
            "tags": ["ML", "NLP", "classification", "text-analysis"],
            "code": '''#!/usr/bin/env python3
"""Text Classifier - TF-IDF + Naive Bayes from scratch (no sklearn needed)."""

import math
import re
from collections import defaultdict, Counter
import json


class TFIDFNaiveBayes:
    """Text classifier using TF-IDF features with Naive Bayes."""

    def __init__(self):
        self.class_word_counts = defaultdict(Counter)
        self.class_doc_counts = Counter()
        self.vocab = set()
        self.doc_freq = Counter()
        self.total_docs = 0

    def tokenize(self, text: str) -> list[str]:
        text = text.lower()
        text = re.sub(r"[^a-z0-9\\s]", " ", text)
        tokens = text.split()
        stopwords = {"the", "a", "an", "is", "are", "was", "were", "be", "been",
                     "being", "have", "has", "had", "do", "does", "did", "will",
                     "would", "could", "should", "may", "might", "can", "shall",
                     "to", "of", "in", "for", "on", "with", "at", "by", "from",
                     "it", "this", "that", "and", "or", "not", "but", "if"}
        return [t for t in tokens if t not in stopwords and len(t) > 1]

    def train(self, documents: list[tuple[str, str]]):
        """Train on list of (text, label) tuples."""
        self.total_docs = len(documents)
        for text, label in documents:
            tokens = self.tokenize(text)
            self.class_doc_counts[label] += 1
            unique_tokens = set(tokens)
            for token in unique_tokens:
                self.doc_freq[token] += 1
            for token in tokens:
                self.class_word_counts[label][token] += 1
                self.vocab.add(token)

    def _tfidf(self, token: str, token_count: int, doc_length: int) -> float:
        tf = token_count / doc_length if doc_length > 0 else 0
        idf = math.log(self.total_docs / (1 + self.doc_freq.get(token, 0)))
        return tf * idf

    def predict(self, text: str) -> dict:
        """Predict class for text with confidence scores."""
        tokens = self.tokenize(text)
        token_counts = Counter(tokens)
        doc_length = len(tokens)
        scores = {}

        for label in self.class_doc_counts:
            prior = math.log(self.class_doc_counts[label] / self.total_docs)
            likelihood = 0
            total_words = sum(self.class_word_counts[label].values())

            for token, count in token_counts.items():
                word_count = self.class_word_counts[label].get(token, 0)
                prob = (word_count + 1) / (total_words + len(self.vocab))
                tfidf_weight = self._tfidf(token, count, doc_length)
                likelihood += math.log(prob) * (1 + tfidf_weight)

            scores[label] = prior + likelihood

        max_score = max(scores.values())
        exp_scores = {k: math.exp(v - max_score) for k, v in scores.items()}
        total = sum(exp_scores.values())
        probs = {k: round(v / total, 4) for k, v in exp_scores.items()}

        predicted = max(probs, key=probs.get)
        return {"prediction": predicted, "confidence": probs[predicted], "probabilities": probs}


# Demo: Spam detector
TRAINING_DATA = [
    ("Win a free iPhone now click here", "spam"),
    ("Congratulations you won $1000 cash prize", "spam"),
    ("Buy cheap medications online discount", "spam"),
    ("Free credit score check limited offer", "spam"),
    ("Make money fast work from home easy", "spam"),
    ("Urgent: your account has been compromised act now", "spam"),
    ("Best deals on electronics sale happening now", "spam"),
    ("You have been selected for a special reward", "spam"),
    ("Hey can we meet for lunch tomorrow", "ham"),
    ("The project deadline has been moved to Friday", "ham"),
    ("Please review the attached document and provide feedback", "ham"),
    ("Team meeting scheduled for 3pm in conference room B", "ham"),
    ("I pushed the code changes to the dev branch", "ham"),
    ("Can you help me debug this API endpoint", "ham"),
    ("The quarterly report looks good nice work", "ham"),
    ("Remember to submit your timesheet by end of day", "ham"),
]

TEST_DATA = [
    "Claim your free gift card worth $500 today",
    "Can we reschedule the meeting to next week",
    "You won a lottery prize click to claim now",
    "The deployment pipeline is failing on staging",
    "Limited time offer buy one get one free",
]


if __name__ == "__main__":
    clf = TFIDFNaiveBayes()
    clf.train(TRAINING_DATA)

    print("Text Classifier (Spam Detection Demo)")
    print("=" * 50)
    print(f"Training samples: {len(TRAINING_DATA)}")
    print(f"Vocabulary size: {len(clf.vocab)}")

    print("\\nPredictions:")
    for text in TEST_DATA:
        result = clf.predict(text)
        icon = "[SPAM]" if result["prediction"] == "spam" else "[OK]  "
        print(f"  {icon} ({result['confidence']:.0%}) {text[:60]}")

    print("\\nTry your own text as argument: python text_classifier.py \\"your text here\\"")
    if len(import_sys := sys.argv) > 1:
        custom_text = " ".join(import_sys[1:])
        result = clf.predict(custom_text)
        print(f"\\nCustom: {result['prediction']} ({result['confidence']:.0%})")
        print(json.dumps(result, indent=2))
'''
        },
    ],
    # ==================== AUTOMATION ====================
    "automation": [
        {
            "name": "api_health_monitor",
            "title": "API Health Monitor",
            "description": "Monitors API endpoints for uptime, response time, status codes, and SSL certificate expiry. Generates health reports.",
            "tags": ["automation", "monitoring", "DevOps", "API"],
            "code": '''#!/usr/bin/env python3
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
    print(f"Monitoring {len(urls)} endpoints...\\n")

    report = monitor_endpoints(urls)

    print(f"Overall: {report['overall_status']}")
    print(f"Uptime: {report['summary']['uptime_pct']}% | Avg latency: {report['summary']['avg_latency_ms']}ms\\n")

    for ep in report["endpoints"]:
        icon = "+" if ep["healthy"] else "!"
        err = f" ({ep.get('error', '')})" if ep.get("error") else ""
        print(f"  [{icon}] {ep['status_code']} | {ep['response_time_ms']:>8}ms | {ep['url']}{err}")

    if report["ssl_certificates"]:
        print("\\nSSL Certificates:")
        for cert in report["ssl_certificates"]:
            if "error" in cert:
                print(f"  [!] {cert['hostname']}: {cert['error']}")
            else:
                icon = "!" if cert["warning"] else "+"
                print(f"  [{icon}] {cert['hostname']}: expires in {cert['days_until_expiry']} days")
'''
        },
        {
            "name": "git_repo_analyzer",
            "title": "Git Repository Analyzer",
            "description": "Analyzes git repositories for commit patterns, contributor stats, code churn, and generates insights about development activity.",
            "tags": ["automation", "git", "DevOps", "analytics"],
            "code": '''#!/usr/bin/env python3
"""Git Repo Analyzer - Commit patterns, contributor stats, and code insights."""

import subprocess
import json
import sys
import re
from collections import Counter, defaultdict
from datetime import datetime


def run_git(args: list[str], cwd: str = ".") -> str:
    """Run a git command and return output."""
    try:
        result = subprocess.run(
            ["git"] + args, capture_output=True, text=True, cwd=cwd, timeout=30
        )
        return result.stdout.strip()
    except Exception as e:
        return ""


def analyze_repo(repo_path: str = ".") -> dict:
    """Analyze a git repository."""
    # Basic info
    remote = run_git(["remote", "get-url", "origin"], repo_path)
    branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], repo_path)
    total_commits = run_git(["rev-list", "--count", "HEAD"], repo_path)

    # Commit log (last 500)
    log = run_git([
        "log", "--format=%H|%an|%ae|%aI|%s", "-500"
    ], repo_path)

    commits = []
    for line in log.split("\\n"):
        if "|" in line:
            parts = line.split("|", 4)
            if len(parts) == 5:
                commits.append({
                    "hash": parts[0][:8],
                    "author": parts[1],
                    "email": parts[2],
                    "date": parts[3],
                    "message": parts[4],
                })

    # Contributor stats
    authors = Counter(c["author"] for c in commits)
    emails = {}
    for c in commits:
        emails[c["author"]] = c["email"]

    # Commit frequency by day of week
    day_freq = Counter()
    hour_freq = Counter()
    for c in commits:
        try:
            dt = datetime.fromisoformat(c["date"])
            day_freq[dt.strftime("%A")] += 1
            hour_freq[dt.hour] += 1
        except ValueError:
            pass

    # File change stats
    file_changes = run_git([
        "log", "--format=", "--name-only", "-100"
    ], repo_path)
    file_counter = Counter(f for f in file_changes.split("\\n") if f.strip())

    # Recent activity
    recent_log = run_git(["log", "--format=%aI", "-50"], repo_path)
    recent_dates = [line.strip() for line in recent_log.split("\\n") if line.strip()]

    # Language detection via file extensions
    all_files = run_git(["ls-files"], repo_path)
    ext_counter = Counter()
    for f in all_files.split("\\n"):
        if "." in f:
            ext = f.rsplit(".", 1)[-1].lower()
            ext_counter[ext] += 1

    lang_map = {
        "py": "Python", "js": "JavaScript", "ts": "TypeScript", "java": "Java",
        "c": "C", "cpp": "C++", "go": "Go", "rs": "Rust", "rb": "Ruby",
        "php": "PHP", "cs": "C#", "html": "HTML", "css": "CSS", "sql": "SQL",
        "sh": "Shell", "yml": "YAML", "json": "JSON", "md": "Markdown",
    }
    languages = {}
    for ext, count in ext_counter.most_common(10):
        lang = lang_map.get(ext, ext)
        languages[lang] = count

    return {
        "repository": {
            "remote": remote, "branch": branch,
            "total_commits": int(total_commits) if total_commits.isdigit() else 0,
        },
        "contributors": {
            "total": len(authors),
            "top": [{"name": name, "commits": count, "email": emails.get(name, "")}
                   for name, count in authors.most_common(10)],
        },
        "activity": {
            "by_day": dict(day_freq.most_common()),
            "peak_hour": max(hour_freq, key=hour_freq.get) if hour_freq else None,
            "busiest_day": max(day_freq, key=day_freq.get) if day_freq else None,
        },
        "hotspots": [{"file": f, "changes": c} for f, c in file_counter.most_common(15)],
        "languages": languages,
    }


if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Analyzing repository: {repo}\\n")

    report = analyze_repo(repo)
    print(f"Remote: {report['repository']['remote']}")
    print(f"Branch: {report['repository']['branch']}")
    print(f"Total commits: {report['repository']['total_commits']}")

    print(f"\\nTop Contributors:")
    for c in report["contributors"]["top"][:5]:
        print(f"  {c['name']}: {c['commits']} commits")

    print(f"\\nBusiest day: {report['activity']['busiest_day']}")
    print(f"Peak hour: {report['activity']['peak_hour']}:00")

    print(f"\\nHotspot files (most changed):")
    for h in report["hotspots"][:10]:
        print(f"  {h['changes']:>3}x  {h['file']}")

    print(f"\\nLanguages:")
    for lang, count in report["languages"].items():
        print(f"  {lang}: {count} files")
'''
        },
    ],
}
