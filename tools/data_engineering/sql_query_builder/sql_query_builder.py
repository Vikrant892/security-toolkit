#!/usr/bin/env python3
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
        return "\n".join(parts) + ";"

    def optimize_suggestions(self) -> list[str]:
        tips = []
        query = self.build()
        if "SELECT *" in query:
            tips.append("Avoid SELECT * - specify only needed columns for better performance")
        if not self._limit and not self._group_by:
            tips.append("Consider adding LIMIT to prevent returning too many rows")
        if self._where:
            for w in self._where:
                if "LIKE \"%%" in w.upper():
                    tips.append(f"Leading wildcard in LIKE prevents index usage: {w}")
                if re.search(r"(FUNCTION|UPPER|LOWER|CAST)\(", w, re.I):
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
            match = re.search(r"(\w+\.\w+|\w+)\s*=", w)
            if match:
                suggested_indexes.append(match.group(1))
        if suggested_indexes:
            tips.append(f"Suggested indexes: {', '.join(suggested_indexes)}")
        return tips


if __name__ == "__main__":
    print("SQL Query Builder - Examples\n")

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
    print("\nOptimization tips:")
    for tip in q1.optimize_suggestions():
        print(f"  - {tip}")

    # Example 2: Security audit query
    print("\n" + "="*60 + "\n")
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
    print("\nOptimization tips:")
    for tip in q2.optimize_suggestions():
        print(f"  - {tip}")
