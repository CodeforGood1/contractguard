"""Tests for the HTML reporter."""

from contractguard.engine import Finding, Severity
from contractguard.reporter import render_html_report


class TestRenderHtmlReport:
    def test_renders_with_findings(self):
        findings = [
            Finding(
                rule_id="TEST001",
                rule_name="test",
                severity=Severity.CRITICAL,
                description="Bad thing",
                explanation="Matched",
                suggestion="Fix it",
                location="test.json",
                context='{"a": 1}',
            )
        ]
        html = render_html_report(findings, analyzer_type="json", source_path="test.json")
        assert "ContractGuard Security Report" in html
        assert "TEST001" in html
        assert "critical" in html.lower()
        assert "Fix it" in html

    def test_renders_empty(self):
        html = render_html_report([], analyzer_type="sql", source_path="test.sql")
        assert "All clear" in html

    def test_contains_metadata(self):
        html = render_html_report([], analyzer_type="regex", source_path="patterns.txt")
        assert "regex" in html
        assert "patterns.txt" in html
