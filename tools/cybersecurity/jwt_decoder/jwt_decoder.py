#!/usr/bin/env python3
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

    print(f"\nHEADER:")
    print(json.dumps(decoded["header"], indent=2))

    print(f"\nPAYLOAD:")
    print(json.dumps(decoded["payload"], indent=2))

    print(f"\nSIGNATURE: {decoded['signature'][:20]}...")

    print(f"\nSECURITY ANALYSIS:")
    issues = analyze_security(decoded)
    for issue in issues:
        icon = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "~", "OK": "+", "INFO": "i"}
        print(f"  [{icon.get(issue['severity'], '?')}] {issue['severity']}: {issue['issue']}")
