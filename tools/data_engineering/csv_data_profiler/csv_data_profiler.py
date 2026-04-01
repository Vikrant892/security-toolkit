#!/usr/bin/env python3
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
    int_count = sum(1 for v in non_empty if re.match(r"^-?\d+$", v))
    float_count = sum(1 for v in non_empty if re.match(r"^-?\d*\.\d+$", v))
    date_count = sum(1 for v in non_empty if re.match(r"^\d{4}-\d{2}-\d{2}", v))
    bool_count = sum(1 for v in non_empty if v.lower() in ("true", "false", "yes", "no", "0", "1"))
    email_count = sum(1 for v in non_empty if re.match(r"^[^@]+@[^@]+\.[^@]+$", v))

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
        print("No CSV file provided. Using sample data.\n")
        result = profile_csv(SAMPLE_CSV)

    print(json.dumps(result, indent=2))
    print(f"\nQuality Score: {result['summary']['quality_score']}/100")
    for col_name, col in result["columns"].items():
        issues = []
        if col["null_pct"] > 10: issues.append(f"{col['null_pct']}% nulls")
        if col.get("outliers", 0) > 0: issues.append(f"{col['outliers']} outliers")
        status = f" ISSUES: {', '.join(issues)}" if issues else " OK"
        print(f"  {col_name} ({col['type']}): {col['non_null']}/{col['total']} non-null |{status}")
