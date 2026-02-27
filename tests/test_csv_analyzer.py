"""Tests for the CSV analyzer."""

from pathlib import Path
import tempfile

import pytest

from contractguard.analyzers.csv_analyzer import analyze, extract_facts

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class TestExtractFacts:
    def test_basic_csv(self):
        content = "name,age,score\nAlice,30,95\nBob,25,88\n"
        facts = extract_facts(content)
        assert facts["row_count"] == 2
        assert facts["column_count"] == 3
        assert facts["duplicate_rows"] == 0

    def test_mixed_types(self):
        content = "id,value\n1,hello\n2,42\n3,world\n"
        facts = extract_facts(content)
        # 'value' column has string and integer — mixed
        assert facts["mixed_type_columns"] >= 1

    def test_null_values(self):
        content = "name,email\nAlice,a@b.com\nBob,\nCarol,\nDave,\n"
        facts = extract_facts(content)
        assert facts["missing_value_count"] >= 2

    def test_duplicate_rows(self):
        content = "a,b\n1,2\n1,2\n3,4\n"
        facts = extract_facts(content)
        assert facts["duplicate_rows"] == 1

    def test_inconsistent_columns(self):
        content = "a,b,c\n1,2,3\n4,5\n6,7,8,9\n"
        facts = extract_facts(content)
        assert facts["inconsistent_column_count"] is True

    def test_encoding_issues(self):
        content = "name\nHello\x00World\n"
        facts = extract_facts(content)
        assert facts["has_encoding_issues"] is True

    def test_empty_csv(self):
        content = ""
        facts = extract_facts(content)
        assert facts["row_count"] == 0


class TestAnalyze:
    def test_analyze_csv_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("id,name,value\n1,Alice,hello\n2,Bob,42\n1,Alice,hello\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            # Should find mixed types + duplicate rows
            assert len(findings) >= 1
        finally:
            path.unlink(missing_ok=True)

    def test_analyze_clean_csv(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,age\nAlice,30\nBob,25\nCarol,28\n")
            path = Path(f.name)
        try:
            findings = analyze(path, RULES_DIR)
            # Clean CSV with consistent types, no nulls, no dupes
            assert len(findings) == 0
        finally:
            path.unlink(missing_ok=True)

    def test_analyze_directory(self, tmp_path):
        (tmp_path / "data.csv").write_text("a,b\n1,2\n1,2\n")
        findings = analyze(tmp_path, RULES_DIR)
        assert len(findings) >= 1  # duplicate rows
