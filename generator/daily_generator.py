#!/usr/bin/env python3
"""
Daily Tool Generator - Picks a unique tool each day and generates it.
Uses day-of-year to cycle through all tools, ensuring no repeats within a year.
"""

import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tool_registry import TOOLS


def get_all_tools() -> list[tuple[str, dict]]:
    """Get flat list of (category, tool) pairs."""
    all_tools = []
    for category, tools in TOOLS.items():
        for tool in tools:
            all_tools.append((category, tool))
    return all_tools


def pick_tool_for_today() -> tuple[str, dict]:
    """Pick today's tool based on day of year."""
    all_tools = get_all_tools()
    today = datetime.now(timezone.utc)
    # Use combination of day_of_year and year to cycle through tools
    index = (today.timetuple().tm_yday + today.year * 7) % len(all_tools)
    return all_tools[index]


def generate_tool_files(category: str, tool: dict, base_dir: str = ".") -> dict:
    """Generate the tool files in the repository."""
    today = datetime.now(timezone.utc)
    date_str = today.strftime("%Y-%m-%d")

    # Directory structure: tools/<category>/<tool_name>/
    tool_dir = os.path.join(base_dir, "tools", category, tool["name"])
    os.makedirs(tool_dir, exist_ok=True)

    # Write the tool script
    script_path = os.path.join(tool_dir, f"{tool['name']}.py")
    with open(script_path, "w", newline="\n") as f:
        f.write(tool["code"].lstrip())

    # Write tool README
    readme_path = os.path.join(tool_dir, "README.md")
    tags_str = " ".join(f"`{t}`" for t in tool.get("tags", []))
    readme_content = f"""# {tool['title']}

{tool['description']}

## Category
`{category}`

## Tags
{tags_str}

## Usage

```bash
python {tool['name']}.py
```

## Added
{date_str}

---
*Part of [Security & Data Toolkit](../../..) - Daily tools for cybersecurity, data engineering, and ML.*
"""
    with open(readme_path, "w", newline="\n") as f:
        f.write(readme_content)

    # Update the main catalog
    catalog_path = os.path.join(base_dir, "CATALOG.md")
    catalog_entry = f"| {date_str} | [{tool['title']}](tools/{category}/{tool['name']}) | {category} | {tool['description'][:80]}... |\n"

    if os.path.exists(catalog_path):
        with open(catalog_path, "r") as f:
            content = f.read()
        # Insert after the header row
        if catalog_entry.strip() not in content:
            lines = content.split("\n")
            # Find the header separator line
            for i, line in enumerate(lines):
                if line.startswith("|---"):
                    lines.insert(i + 1, catalog_entry.strip())
                    break
            with open(catalog_path, "w", newline="\n") as f:
                f.write("\n".join(lines))

    # Update daily log
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{today.strftime('%Y-%m')}.md")
    log_entry = f"- **{date_str}**: [{tool['title']}](../tools/{category}/{tool['name']}) - {tool['description'][:100]}\n"

    with open(log_path, "a") as f:
        if not os.path.getsize(log_path) if os.path.exists(log_path) else True:
            f.write(f"# Tool Log - {today.strftime('%B %Y')}\n\n")
        f.write(log_entry)

    return {
        "tool_name": tool["name"],
        "title": tool["title"],
        "category": category,
        "directory": tool_dir,
        "date": date_str,
    }


if __name__ == "__main__":
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

    category, tool = pick_tool_for_today()
    print(f"Today's tool: {tool['title']} ({category})")

    result = generate_tool_files(category, tool, base)
    print(f"Generated: {result['directory']}")
    print(json.dumps(result, indent=2))
