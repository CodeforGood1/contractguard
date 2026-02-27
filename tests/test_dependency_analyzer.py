"""Tests for the dependency vulnerability analyzer."""

from pathlib import Path
import tempfile

import pytest

from contractguard.analyzers.dependency_analyzer import (
    analyze,
    extract_facts_from_requirements,
    _parse_version,
    _version_matches,
)
from contractguard.engine import Severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class TestVersionParsing:
    def test_simple_version(self):
        assert _parse_version("2.3.1") == (2, 3, 1)

    def test_two_part_version(self):
        assert _parse_version("1.0") == (1, 0)

    def test_version_with_prefix(self):
        assert _parse_version(">=2.3.1") == (2, 3, 1)

    def test_version_matches_less_than(self):
        assert _version_matches("2.0.0", "<", "2.31.0") is True
        assert _version_matches("3.0.0", "<", "2.31.0") is False

    def test_version_matches_equal(self):
        assert _version_matches("1.0.0", "==", "1.0.0") is True
        assert _version_matches("1.0.1", "==", "1.0.0") is False


class TestExtractFacts:
    def test_detects_vulnerable_django(self):
        content = "django==2.2.0\n"
        facts = extract_facts_from_requirements(content)
        assert facts["has_vulnerable_packages"] is True
        assert facts["vulnerable_count"] >= 1

    def test_detects_vulnerable_flask(self):
        content = "flask==0.12.0\n"
        facts = extract_facts_from_requirements(content)
        assert facts["has_vulnerable_packages"] is True

    def test_detects_unpinned(self):
        content = "flask\nrequests\n"
        facts = extract_facts_from_requirements(content)
        assert facts["has_unpinned_packages"] is True
        assert facts["unpinned_count"] == 2

    def test_safe_versions(self):
        content = "django==5.0.0\nflask==3.0.0\nrequests==2.32.0\n"
        facts = extract_facts_from_requirements(content)
        assert facts["vulnerable_count"] == 0

    def test_skips_comments_and_flags(self):
        content = "# comment\n-r base.txt\nflask==3.0.0\n"
        facts = extract_facts_from_requirements(content)
        assert facts["total_packages"] == 1

    def test_multiple_vulns(self):
        content = "django==2.2.0\nflask==0.12.0\nurllib3==1.24.0\ncryptography==2.1.0\n"
        facts = extract_facts_from_requirements(content)
        assert facts["vulnerable_count"] >= 3

    def test_counts_critical(self):
        content = "django==2.2.0\ncryptography==2.1.0\n"
        facts = extract_facts_from_requirements(content)
        assert facts["critical_vuln_count"] >= 1


class TestAnalyze:
    def test_analyze_vulnerable_requirements(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="requirements") as f:
            f.write("django==2.2.0\nflask==0.12.0\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            assert len(findings) > 0
            assert any("CVE" in f.rule_id for f in findings)
        finally:
            path.unlink(missing_ok=True)

    def test_analyze_safe_requirements(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="requirements") as f:
            f.write("django==5.0.0\nflask==3.0.0\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            # No vulns for latest versions
            vuln_findings = [f for f in findings if "CVE" in f.rule_id]
            assert len(vuln_findings) == 0
        finally:
            path.unlink(missing_ok=True)

    def test_findings_have_cve(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="requirements") as f:
            f.write("django==2.2.0\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            cve_findings = [f for f in findings if f.rule_id.startswith("CVE")]
            assert len(cve_findings) >= 1
        finally:
            path.unlink(missing_ok=True)
