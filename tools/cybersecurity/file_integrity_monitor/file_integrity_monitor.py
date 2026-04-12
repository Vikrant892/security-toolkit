#!/usr/bin/env python3
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
            print(f"\nWARNING: {len(report['modified'])} files modified!")
        if report.get("deleted"):
            print(f"WARNING: {len(report['deleted'])} files deleted!")
        if report.get("added"):
            print(f"INFO: {len(report['added'])} new files detected")
    else:
        print("Usage:")
        print(f"  {sys.argv[0]} --baseline [directory]  Create baseline")
        print(f"  {sys.argv[0]} --check [directory]     Check integrity")
