#!/usr/bin/env python3
"""Hash Identifier - Detects hash type and optionally cracks with wordlist."""

import re
import hashlib
import sys

HASH_PATTERNS = [
    (r"^[a-fA-F0-9]{32}$", "MD5", 128),
    (r"^[a-fA-F0-9]{40}$", "SHA-1", 160),
    (r"^[a-fA-F0-9]{64}$", "SHA-256", 256),
    (r"^[a-fA-F0-9]{128}$", "SHA-512", 512),
    (r"^\$2[aby]?\$\d{2}\$.{53}$", "bcrypt", None),
    (r"^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86}$", "SHA-512 (Unix crypt)", None),
    (r"^\$5\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$", "SHA-256 (Unix crypt)", None),
    (r"^\$1\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{22}$", "MD5 (Unix crypt)", None),
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
        print(f"\nHash: {h}")
        matches = identify_hash(h)
        for m in matches:
            bits_str = f" ({m['bits']}-bit)" if m['bits'] else ""
            print(f"  Type: {m['type']}{bits_str}")
            cracked = attempt_crack(h, m['type'])
            if cracked:
                print(f"  CRACKED: {cracked}")
            else:
                print(f"  Could not crack with built-in wordlist")
