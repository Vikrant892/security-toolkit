#!/usr/bin/env python3
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
    if re.search(r"(.)\1{2,}", password):
        warnings.append("Contains repeated characters (e.g., aaa)")
    if re.search(r"(012|123|234|345|456|567|678|789|890)", password):
        warnings.append("Contains sequential numbers")
    if re.search(r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", password.lower()):
        warnings.append("Contains sequential letters")
    common = ["password", "123456", "qwerty", "admin", "letmein", "welcome", "monkey", "dragon", "master"]
    if password.lower() in common:
        warnings.append("This is a commonly used password")
    if re.match(r"^[a-zA-Z]+\d+$", password) or re.match(r"^\d+[a-zA-Z]+$", password):
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
        print(f"\n{'='*50}")
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
