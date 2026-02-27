"""Security Scorer — computes an overall project security grade (A-F).

This makes ContractGuard competitive with enterprise security tools.
The grade is composited from all findings across all analyzers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from contractguard.engine import Finding, Severity


@dataclass
class SecurityScore:
    """Aggregate security score for a scan."""
    grade: str           # A, B, C, D, F
    score: int           # 0-100
    total_findings: int
    block_count: int
    critical_count: int
    warning_count: int
    info_count: int
    risk_summary: str    # human-readable summary
    attack_surface: list[str]  # identified attack vectors
    top_risks: list[str]       # top 3 actionable items


def compute_score(findings: list[Finding]) -> SecurityScore:
    """Compute an overall security score from a list of findings."""
    block_count = sum(1 for f in findings if f.severity == Severity.BLOCK)
    critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    warning_count = sum(1 for f in findings if f.severity == Severity.WARNING)
    info_count = sum(1 for f in findings if f.severity == Severity.INFO)
    total = len(findings)

    # Score starts at 100/100, deductions based on severity
    score = 100
    score -= block_count * 20
    score -= critical_count * 10
    score -= warning_count * 4
    score -= info_count * 1
    score = max(0, min(100, score))

    # Automatic F if any BLOCK-level findings
    if block_count > 0:
        grade = "F"
        score = min(score, 15)
    elif score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    attack_surface = list({f.attack_vector for f in findings if f.attack_vector})[:10]

    severity_order = {Severity.BLOCK: 0, Severity.CRITICAL: 1, Severity.WARNING: 2, Severity.INFO: 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))
    seen_descriptions: set[str] = set()
    top_risks: list[str] = []
    for f in sorted_findings:
        if f.description not in seen_descriptions and len(top_risks) < 5:
            top_risks.append(f"[{f.severity.value.upper()}] {f.description}")
            seen_descriptions.add(f.description)

    if grade == "A":
        risk_summary = "Minimal risk. Good security posture."
    elif grade == "B":
        risk_summary = "Low risk. A few issues to address before production."
    elif grade == "C":
        risk_summary = "Moderate risk. Several issues need attention."
    elif grade == "D":
        risk_summary = "High risk. Significant security issues detected."
    else:
        risk_summary = "CRITICAL RISK. Deployment must be blocked until issues are resolved."

    return SecurityScore(
        grade=grade,
        score=score,
        total_findings=total,
        block_count=block_count,
        critical_count=critical_count,
        warning_count=warning_count,
        info_count=info_count,
        risk_summary=risk_summary,
        attack_surface=attack_surface,
        top_risks=top_risks,
    )
