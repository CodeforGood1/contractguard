"""CSV Schema Analyzer.

Detects type inconsistencies across rows, missing values, duplicate primary keys,
column count mismatches, and encoding issues in CSV data.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from contractguard.engine import Finding, load_rules_for_analyzer, run_rules


def _infer_type(value: str) -> str:
    """Infer the type of a CSV cell value."""
    if value == "" or value.lower() in ("null", "none", "na", "n/a", "nan", ""):
        return "null"
    if value.lower() in ("true", "false", "yes", "no"):
        return "boolean"
    try:
        int(value)
        return "integer"
    except ValueError:
        pass
    try:
        float(value)
        return "number"
    except ValueError:
        pass
    if re.match(r"^\d{4}-\d{2}-\d{2}", value):
        return "date"
    if re.match(r"^\d{1,2}/\d{1,2}/\d{2,4}$", value):
        return "date"
    return "string"


def extract_facts(content: str, filename: str = "") -> dict[str, Any]:
    """Analyze CSV content and extract facts."""
    facts: dict[str, Any] = {
        "row_count": 0,
        "column_count": 0,
        "has_header": True,
        "inconsistent_column_count": False,
        "missing_value_count": 0,
        "duplicate_rows": 0,
        "mixed_type_columns": 0,
        "null_heavy_columns": 0,
        "column_type_map": {},
        "has_encoding_issues": False,
        "empty_rows": 0,
        "max_column_count_variance": 0,
    }

    if "\ufffd" in content or "\x00" in content:
        facts["has_encoding_issues"] = True

    try:
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
    except csv.Error:
        facts["has_encoding_issues"] = True
        return facts

    if not rows:
        return facts

    header = rows[0]
    data_rows = rows[1:]
    facts["column_count"] = len(header)
    facts["row_count"] = len(data_rows)

    column_counts = Counter(len(r) for r in data_rows)
    if len(column_counts) > 1:
        facts["inconsistent_column_count"] = True
        counts = list(column_counts.keys())
        facts["max_column_count_variance"] = max(counts) - min(counts)

    col_types: dict[str, Counter] = defaultdict(Counter)
    missing_per_col: dict[str, int] = defaultdict(int)

    for row in data_rows:
        for i, cell in enumerate(row):
            col_name = header[i] if i < len(header) else f"col_{i}"
            cell_type = _infer_type(cell.strip())
            col_types[col_name][cell_type] += 1
            if cell_type == "null":
                missing_per_col[col_name] += 1

    # Count columns with mixed types (excluding null)
    for col_name, type_counter in col_types.items():
        non_null_types = {t for t in type_counter if t != "null"}
        if len(non_null_types) > 1:
            facts["mixed_type_columns"] += 1

    # Null-heavy columns (>50% null)
    for col_name, null_count in missing_per_col.items():
        if facts["row_count"] > 0 and null_count / facts["row_count"] > 0.5:
            facts["null_heavy_columns"] += 1

    facts["missing_value_count"] = sum(missing_per_col.values())
    facts["column_type_map"] = {k: dict(v) for k, v in col_types.items()}

    row_tuples = [tuple(r) for r in data_rows]
    facts["duplicate_rows"] = len(row_tuples) - len(set(row_tuples))

    facts["empty_rows"] = sum(1 for r in data_rows if all(c.strip() == "" for c in r))

    # Pre-compute for rule engine
    for col_name in col_types:
        non_null = {t for t in col_types[col_name] if t != "null"}
        facts[f"field_types('{col_name}')"] = len(non_null)

    return facts


def load_csv_files(path: str | Path) -> list[tuple[str, str]]:
    """Load CSV files from a file or directory."""
    path = Path(path)
    files: list[tuple[str, str]] = []

    if path.is_dir():
        for f in sorted(path.glob("*.csv")):
            try:
                files.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                continue
    elif path.is_file():
        try:
            files.append((str(path), path.read_text(encoding="utf-8", errors="replace")))
        except Exception:
            pass
    return files


def analyze(path: str | Path, rules_dir: str | Path) -> list[Finding]:
    """Run CSV analysis on files at *path*."""
    files = load_csv_files(path)
    rules = load_rules_for_analyzer(rules_dir, "csv")
    all_findings: list[Finding] = []

    for source, content in files:
        facts = extract_facts(content, source)
        findings = run_rules(facts, rules)
        for f in findings:
            f.location = source
            f.context = f"{facts['row_count']} rows, {facts['column_count']} columns"
        all_findings.extend(findings)

    return all_findings
