"""Tests for the Regex analyzer."""

import pytest

from contractguard.analyzers.regex_analyzer import analyze, extract_facts, load_regex_patterns


class TestExtractFacts:
    def test_simple_pattern(self):
        facts = extract_facts(r"^\d{3}-\d{2}-\d{4}$")
        assert facts["is_valid"] is True
        assert facts["nested_quantifiers"] is False

    def test_nested_quantifiers(self):
        facts = extract_facts(r"(a+)+$")
        assert facts["nested_quantifiers"] is True
        assert facts["complexity_score"] > 25

    def test_backreference(self):
        facts = extract_facts(r"(.+)\1+")
        assert facts["has_backreference"] is True

    def test_invalid_pattern(self):
        facts = extract_facts(r"(unclosed[group")
        assert facts["is_valid"] is False
        assert facts["complexity_score"] == 100

    def test_long_pattern(self):
        pattern = r"[a-z]" * 30  # 150 chars
        facts = extract_facts(pattern)
        assert facts["pattern_length"] > 100

    def test_alternation(self):
        facts = extract_facts(r"cat|dog|bird")
        assert facts["has_alternation"] is True

    def test_complexity_grows_with_nesting(self):
        simple = extract_facts(r"\d+")
        nested = extract_facts(r"(\d+)+")
        assert nested["complexity_score"] > simple["complexity_score"]

    def test_email_pattern(self):
        facts = extract_facts(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        assert facts["is_valid"] is True
        assert facts["nested_quantifiers"] is False


class TestLoadRegexPatterns:
    def test_load_file(self, tmp_path):
        f = tmp_path / "patterns.txt"
        f.write_text("# comment\n^\\d+$\n\n[a-z]+\n")
        patterns = load_regex_patterns(f)
        assert len(patterns) == 2

    def test_load_directory(self, tmp_path):
        (tmp_path / "a.txt").write_text("^a$\n")
        (tmp_path / "b.txt").write_text("^b$\n")
        patterns = load_regex_patterns(tmp_path)
        assert len(patterns) == 2


class TestAnalyze:
    def test_full_pipeline(self, tmp_path):
        pattern_file = tmp_path / "test.txt"
        pattern_file.write_text("(a+)+$\n")

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "regex.yaml").write_text("""
- id: REGEX001
  name: nested_quantifiers
  analyzer: regex
  severity: critical
  description: "Nested quantifiers."
  matcher: "nested_quantifiers == true"
  suggestion: "Refactor."
""")

        findings = analyze(pattern_file, rules_dir)
        assert len(findings) >= 1
        assert any(f.rule_id == "REGEX001" for f in findings)

    def test_clean_pattern_no_findings(self, tmp_path):
        pattern_file = tmp_path / "clean.txt"
        pattern_file.write_text(r"^\d{4}-\d{2}-\d{2}$" + "\n")

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "regex.yaml").write_text("""
- id: REGEX001
  name: nested_quantifiers
  analyzer: regex
  severity: critical
  description: "Nested quantifiers."
  matcher: "nested_quantifiers == true"
  suggestion: "Refactor."
""")

        findings = analyze(pattern_file, rules_dir)
        assert len(findings) == 0
