"""Tests for the security scorer."""

import pytest

from contractguard.engine import Finding, Severity
from contractguard.scorer import SecurityScore, compute_score


def _make_finding(severity: Severity, desc: str = "test", attack_vector: str = "") -> Finding:
    return Finding(
        rule_id="TEST-001",
        rule_name="test",
        severity=severity,
        description=desc,
        explanation="test",
        suggestion="fix it",
        attack_vector=attack_vector,
    )


class TestComputeScore:
    def test_no_findings_grade_a(self):
        score = compute_score([])
        assert score.grade == "A"
        assert score.score == 100
        assert score.total_findings == 0

    def test_info_only_grade_a(self):
        findings = [_make_finding(Severity.INFO) for _ in range(5)]
        score = compute_score(findings)
        assert score.grade == "A"
        assert score.score == 95

    def test_warnings_grade_b(self):
        findings = [_make_finding(Severity.WARNING) for _ in range(5)]
        score = compute_score(findings)
        assert score.grade == "B"
        assert score.score == 80

    def test_critical_lowers_score(self):
        findings = [_make_finding(Severity.CRITICAL)]
        score = compute_score(findings)
        assert score.score == 90
        assert score.grade == "A"

    def test_block_forces_f(self):
        findings = [_make_finding(Severity.BLOCK)]
        score = compute_score(findings)
        assert score.grade == "F"
        assert score.score <= 15

    def test_mixed_findings(self):
        findings = [
            _make_finding(Severity.CRITICAL, "crit1"),
            _make_finding(Severity.WARNING, "warn1"),
            _make_finding(Severity.WARNING, "warn2"),
            _make_finding(Severity.INFO, "info1"),
        ]
        score = compute_score(findings)
        # 100 - 10 - 4 - 4 - 1 = 81
        assert score.score == 81
        assert score.grade == "B"

    def test_attack_surface_extracted(self):
        findings = [
            _make_finding(Severity.CRITICAL, attack_vector="SQL injection via user input"),
            _make_finding(Severity.WARNING, attack_vector="XSS via unescaped output"),
        ]
        score = compute_score(findings)
        assert len(score.attack_surface) == 2

    def test_top_risks_populated(self):
        findings = [
            _make_finding(Severity.BLOCK, "Leaked AWS credentials"),
            _make_finding(Severity.CRITICAL, "SQL injection"),
            _make_finding(Severity.WARNING, "Debug mode"),
        ]
        score = compute_score(findings)
        assert len(score.top_risks) >= 2
        assert "BLOCK" in score.top_risks[0]

    def test_risk_summary_matches_grade(self):
        score_a = compute_score([])
        assert "Minimal" in score_a.risk_summary

        score_f = compute_score([_make_finding(Severity.BLOCK)])
        assert "CRITICAL" in score_f.risk_summary

    def test_score_clamped_to_zero(self):
        findings = [_make_finding(Severity.BLOCK) for _ in range(10)]
        score = compute_score(findings)
        assert score.score >= 0
