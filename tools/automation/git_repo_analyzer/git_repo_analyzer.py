#!/usr/bin/env python3
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
    for line in log.split("\n"):
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
    file_counter = Counter(f for f in file_changes.split("\n") if f.strip())

    # Recent activity
    recent_log = run_git(["log", "--format=%aI", "-50"], repo_path)
    recent_dates = [line.strip() for line in recent_log.split("\n") if line.strip()]

    # Language detection via file extensions
    all_files = run_git(["ls-files"], repo_path)
    ext_counter = Counter()
    for f in all_files.split("\n"):
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
    print(f"Analyzing repository: {repo}\n")

    report = analyze_repo(repo)
    print(f"Remote: {report['repository']['remote']}")
    print(f"Branch: {report['repository']['branch']}")
    print(f"Total commits: {report['repository']['total_commits']}")

    print(f"\nTop Contributors:")
    for c in report["contributors"]["top"][:5]:
        print(f"  {c['name']}: {c['commits']} commits")

    print(f"\nBusiest day: {report['activity']['busiest_day']}")
    print(f"Peak hour: {report['activity']['peak_hour']}:00")

    print(f"\nHotspot files (most changed):")
    for h in report["hotspots"][:10]:
        print(f"  {h['changes']:>3}x  {h['file']}")

    print(f"\nLanguages:")
    for lang, count in report["languages"].items():
        print(f"  {lang}: {count} files")
