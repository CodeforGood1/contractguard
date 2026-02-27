"""SQL Query Performance & Safety Analyzer.

Static heuristics via sqlparse, plus optional EXPLAIN mode for SQLite.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

import sqlparse
from sqlparse.sql import (
    Comparison,
    Function,
    Identifier,
    IdentifierList,
    Parenthesis,
    Where,
)
from sqlparse.tokens import DML, Keyword, Wildcard

from contractguard.engine import Finding, load_rules_for_analyzer, run_rules


def extract_facts(sql: str) -> dict[str, Any]:
    """Extract static facts from a SQL query string."""
    parsed = sqlparse.parse(sql)
    if not parsed:
        return {}
    stmt = parsed[0]
    tokens = list(stmt.flatten())

    facts: dict[str, Any] = {
        "contains_select_star": False,
        "missing_where_clause": False,
        "uses_or_in_where": False,
        "has_subquery": False,
        "uses_like_wildcard_prefix": False,
        "join_count": 0,
        "union_count": 0,
        "has_order_by": False,
        "has_limit": False,
        "has_group_by": False,
        "table_count": 0,
        "function_count": 0,
        "query_length": len(sql),
        "statement_type": "",
        "uses_distinct": False,
        "has_having": False,
        "nested_subquery_depth": 0,
        "uses_cartesian_join": False,
    }

    upper_sql = sql.upper()

    for token in tokens:
        if token.ttype is DML:
            facts["statement_type"] = str(token).upper()
            break

    for token in tokens:
        if token.ttype is Wildcard:
            facts["contains_select_star"] = True
            break

    has_where = False
    for token in stmt.tokens:
        if isinstance(token, Where):
            has_where = True
            where_text = str(token).upper()
            if " OR " in where_text:
                facts["uses_or_in_where"] = True
            break

    if facts["statement_type"] in ("SELECT", "UPDATE", "DELETE") and not has_where:
        facts["missing_where_clause"] = True

    paren_depth = 0
    max_depth = 0
    for token in tokens:
        s = str(token)
        if s == "(":
            paren_depth += 1
            max_depth = max(max_depth, paren_depth)
        elif s == ")":
            paren_depth = max(0, paren_depth - 1)
    if "SELECT" in upper_sql.split("(", 1)[-1] if "(" in upper_sql else "":
        facts["has_subquery"] = True
    facts["nested_subquery_depth"] = max_depth

    facts["join_count"] = len(re.findall(r"\bJOIN\b", upper_sql))

    facts["union_count"] = len(re.findall(r"\bUNION\b", upper_sql))

    facts["has_order_by"] = bool(re.search(r"\bORDER\s+BY\b", upper_sql))
    facts["has_limit"] = bool(re.search(r"\bLIMIT\b", upper_sql))
    facts["has_group_by"] = bool(re.search(r"\bGROUP\s+BY\b", upper_sql))
    facts["has_having"] = bool(re.search(r"\bHAVING\b", upper_sql))
    facts["uses_distinct"] = bool(re.search(r"\bDISTINCT\b", upper_sql))

    facts["uses_like_wildcard_prefix"] = bool(
        re.search(r"LIKE\s+['\"]%", upper_sql)
    )

    facts["table_count"] = 1 + facts["join_count"] if facts["statement_type"] == "SELECT" else 0

    from_match = re.search(r"\bFROM\s+(.+?)(?:\bWHERE\b|\bORDER\b|\bGROUP\b|\bLIMIT\b|\bJOIN\b|$)", upper_sql, re.DOTALL)
    if from_match:
        from_clause = from_match.group(1)
        if "," in from_clause and "JOIN" not in from_clause:
            facts["uses_cartesian_join"] = True

    facts["function_count"] = len(re.findall(r"\b\w+\s*\(", upper_sql)) - upper_sql.count("(SELECT")

    return facts


def explain_query(sql: str, db_path: str) -> dict[str, Any] | None:
    """Run EXPLAIN QUERY PLAN on a SQLite database and return the plan."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.execute(f"EXPLAIN QUERY PLAN {sql}")
        rows = cursor.fetchall()
        conn.close()
        return {
            "explain_rows": [{"id": r[0], "parent": r[1], "detail": r[3]} for r in rows],
            "uses_full_scan": any("SCAN" in str(r[3]).upper() for r in rows),
        }
    except Exception:
        return None


def load_sql_queries(path: str | Path) -> list[tuple[str, str]]:
    """Load SQL queries from a file or directory.

    Returns list of (source_label, sql_text) tuples.
    Supports .sql files (one query per file or semicolon‐delimited).
    """
    path = Path(path)
    queries: list[tuple[str, str]] = []

    if path.is_dir():
        for f in sorted(path.glob("*.sql")):
            queries.extend(_load_sql_file(f))
    else:
        queries.extend(_load_sql_file(path))

    return queries


def _load_sql_file(filepath: Path) -> list[tuple[str, str]]:
    """Split a SQL file into individual statements."""
    with open(filepath, "r", encoding="utf-8") as fh:
        content = fh.read()
    statements = sqlparse.split(content)
    return [
        (str(filepath), stmt.strip())
        for stmt in statements
        if stmt.strip()
    ]


def analyze(
    path: str | Path,
    rules_dir: str | Path,
    db_path: str | None = None,
) -> list[Finding]:
    """Run SQL analysis on queries at *path* using rules from *rules_dir*."""
    queries = load_sql_queries(path)
    rules = load_rules_for_analyzer(rules_dir, "sql")
    all_findings: list[Finding] = []

    for source, sql in queries:
        facts = extract_facts(sql)

        # Optional EXPLAIN enrichment
        if db_path:
            explain = explain_query(sql, db_path)
            if explain:
                facts.update(explain)

        findings = run_rules(facts, rules)
        for f in findings:
            f.location = source
            f.context = sql[:200]
        all_findings.extend(findings)

    return all_findings
