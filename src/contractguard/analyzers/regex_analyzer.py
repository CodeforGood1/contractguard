"""Regex Debugger & Complexity Analyzer.

Uses Python's sre_parse to decompose regex patterns and detect
catastrophic backtracking risks (nested quantifiers, excessive groups, etc.).
"""

from __future__ import annotations

import re
import re._parser as sre_parse  # modern alias (sre_parse deprecated in 3.11+)
from pathlib import Path
from typing import Any

from contractguard.engine import Finding, load_rules_for_analyzer, run_rules

# sre_parse opcodes for quantifiers
_QUANTIFIER_OPS = {"MAX_REPEAT", "MIN_REPEAT"}
_BACKREF_OP = "GROUPREF"


def _walk(parsed: sre_parse.SubPattern, depth: int = 0) -> list[tuple[str, int, Any]]:
    """Walk the sre_parse tree and yield (opcode_name, depth, args)."""
    items: list[tuple[str, int, Any]] = []
    for op, av in parsed.data:
        op_name = str(op).rsplit(".", 1)[-1] if "." in str(op) else str(op)
        items.append((op_name, depth, av))
        if isinstance(av, sre_parse.SubPattern):
            items.extend(_walk(av, depth + 1))
        elif isinstance(av, (list, tuple)):
            for sub in av:
                if isinstance(sub, sre_parse.SubPattern):
                    items.extend(_walk(sub, depth + 1))
    return items


def extract_facts(pattern: str) -> dict[str, Any]:
    """Extract complexity facts from a regex pattern string."""
    facts: dict[str, Any] = {
        "nested_quantifiers": False,
        "has_backreference": False,
        "quantifier_count": 0,
        "group_count": 0,
        "max_depth": 0,
        "complexity_score": 0,
        "has_alternation": False,
        "alternation_count": 0,
        "char_class_count": 0,
        "anchor_count": 0,
        "uses_lookahead": False,
        "uses_lookbehind": False,
        "pattern_length": len(pattern),
        "is_valid": True,
        "error_message": "",
    }

    try:
        parsed = sre_parse.parse(pattern)
    except re.error as exc:
        facts["is_valid"] = False
        facts["error_message"] = str(exc)
        facts["complexity_score"] = 100  # invalid patterns are maximally risky
        return facts

    items = _walk(parsed)

    quantifier_depths: list[int] = []
    for op_name, depth, _ in items:
        if op_name in _QUANTIFIER_OPS:
            quantifier_depths.append(depth)
        if op_name == _BACKREF_OP:
            facts["has_backreference"] = True

    facts["quantifier_count"] = len(quantifier_depths)
    facts["group_count"] = parsed.state.groups - 1 if parsed.state.groups > 0 else 0
    facts["max_depth"] = max((d for _, d, _ in items), default=0)

    # Nested quantifiers: any quantifier inside another quantifier's subpattern
    if len(quantifier_depths) >= 2:
        sorted_depths = sorted(quantifier_depths)
        for i in range(1, len(sorted_depths)):
            if sorted_depths[i] > sorted_depths[i - 1]:
                facts["nested_quantifiers"] = True
                break

    for op_name, _, _ in items:
        if op_name == "BRANCH":
            facts["has_alternation"] = True
            facts["alternation_count"] += 1

    for op_name, _, _ in items:
        if op_name in ("ASSERT", "ASSERT_NOT"):
            facts["uses_lookahead"] = True
        if op_name in ("AT_BEGINNING", "AT_END"):
            facts["anchor_count"] += 1

    facts["char_class_count"] = sum(1 for op, _, _ in items if op == "IN")

    # Heuristic complexity score (0-100)
    score = 0
    score += facts["quantifier_count"] * 5
    score += facts["group_count"] * 3
    score += facts["alternation_count"] * 4
    score += facts["max_depth"] * 3
    if facts["nested_quantifiers"]:
        score += 30
    if facts["has_backreference"]:
        score += 15
    if facts["uses_lookahead"]:
        score += 5
    score += min(facts["pattern_length"] // 20, 10)
    facts["complexity_score"] = min(score, 100)

    return facts


def load_regex_patterns(path: str | Path) -> list[tuple[str, str]]:
    """Load regex patterns from a file or directory.

    Supports .txt or .regex files with one pattern per line (blank/comment lines skipped).
    """
    path = Path(path)
    patterns: list[tuple[str, str]] = []

    if path.is_dir():
        for ext in ("*.txt", "*.regex"):
            for f in sorted(path.glob(ext)):
                patterns.extend(_load_pattern_file(f))
    else:
        patterns.extend(_load_pattern_file(path))

    return patterns


def _load_pattern_file(filepath: Path) -> list[tuple[str, str]]:
    """Read patterns from a file, one per line."""
    with open(filepath, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    results: list[tuple[str, str]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            results.append((f"{filepath}:{i}", stripped))
    return results


def analyze(path: str | Path, rules_dir: str | Path) -> list[Finding]:
    """Run regex analysis on patterns at *path* using rules from *rules_dir*."""
    patterns = load_regex_patterns(path)
    rules = load_rules_for_analyzer(rules_dir, "regex")
    all_findings: list[Finding] = []

    for source, pattern in patterns:
        facts = extract_facts(pattern)
        findings = run_rules(facts, rules)
        for f in findings:
            f.location = source
            f.context = pattern[:200]
        all_findings.extend(findings)

    return all_findings
