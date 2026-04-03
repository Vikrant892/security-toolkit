#!/usr/bin/env python3
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
    return "\n".join(lines)


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
    print("JSON ETL Transformer Demo\n")

    # Step 1: Flatten
    print("1. FLATTEN nested JSON:")
    flat = [flatten_json(r) for r in SAMPLE_DATA]
    print(json.dumps(flat[0], indent=2))

    # Step 2: Transform with mappings
    print("\n2. TRANSFORM with field mappings:")
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
    print("\n3. FILTER active employees with salary > 70k:")
    filters = [
        lambda r: r.get("is_active") == True,
        lambda r: r.get("annual_salary", 0) > 70000,
    ]
    filtered = transform_records(SAMPLE_DATA, mappings=mappings, filters=filters)
    for r in filtered:
        print(f"  {r['full_name']}: ${r['annual_salary']:,} ({r['dept']})")

    # Step 4: Export
    print("\n4. EXPORT to CSV:")
    csv_output = to_csv(filtered)
    print(csv_output)

    print("5. EXPORT to SQL:")
    sql_output = to_sql_inserts(filtered, "employees")
    print(sql_output)
