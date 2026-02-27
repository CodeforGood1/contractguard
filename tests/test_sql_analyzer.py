"""Tests for the SQL analyzer."""

import pytest

from contractguard.analyzers.sql_analyzer import analyze, extract_facts, load_sql_queries


class TestExtractFacts:
    def test_select_star(self):
        facts = extract_facts("SELECT * FROM users")
        assert facts["contains_select_star"] is True
        assert facts["statement_type"] == "SELECT"

    def test_no_select_star(self):
        facts = extract_facts("SELECT id, name FROM users")
        assert facts["contains_select_star"] is False

    def test_missing_where(self):
        facts = extract_facts("SELECT * FROM users")
        assert facts["missing_where_clause"] is True

    def test_has_where(self):
        facts = extract_facts("SELECT id FROM users WHERE active = 1")
        assert facts["missing_where_clause"] is False

    def test_delete_no_where(self):
        facts = extract_facts("DELETE FROM sessions")
        assert facts["missing_where_clause"] is True
        assert facts["statement_type"] == "DELETE"

    def test_like_wildcard(self):
        facts = extract_facts("SELECT id FROM products WHERE name LIKE '%widget%'")
        assert facts["uses_like_wildcard_prefix"] is True

    def test_no_like_wildcard(self):
        facts = extract_facts("SELECT id FROM products WHERE name LIKE 'widget%'")
        assert facts["uses_like_wildcard_prefix"] is False

    def test_or_in_where(self):
        facts = extract_facts("SELECT * FROM events WHERE status = 'a' OR cat = 'b'")
        assert facts["uses_or_in_where"] is True

    def test_join_count(self):
        sql = "SELECT u.name FROM users u JOIN orders o ON u.id = o.uid JOIN items i ON o.id = i.oid"
        facts = extract_facts(sql)
        assert facts["join_count"] == 2

    def test_cartesian_join(self):
        facts = extract_facts("SELECT u.name, o.total FROM users u, orders o")
        assert facts["uses_cartesian_join"] is True

    def test_distinct(self):
        facts = extract_facts("SELECT DISTINCT name FROM users")
        assert facts["uses_distinct"] is True

    def test_order_by_limit(self):
        facts = extract_facts("SELECT id FROM users ORDER BY name LIMIT 10")
        assert facts["has_order_by"] is True
        assert facts["has_limit"] is True

    def test_group_by_having(self):
        facts = extract_facts("SELECT dept, COUNT(*) FROM emp GROUP BY dept HAVING COUNT(*) > 5")
        assert facts["has_group_by"] is True
        assert facts["has_having"] is True


class TestLoadSqlQueries:
    def test_load_file(self, tmp_path):
        f = tmp_path / "test.sql"
        f.write_text("SELECT 1;\nSELECT 2;")
        queries = load_sql_queries(f)
        assert len(queries) == 2

    def test_load_directory(self, tmp_path):
        (tmp_path / "a.sql").write_text("SELECT 1;")
        (tmp_path / "b.sql").write_text("SELECT 2;")
        queries = load_sql_queries(tmp_path)
        assert len(queries) == 2


class TestAnalyze:
    def test_full_pipeline(self, tmp_path):
        sql_file = tmp_path / "test.sql"
        sql_file.write_text("SELECT * FROM users;")

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "sql.yaml").write_text("""
- id: SQL001
  name: select_star
  analyzer: sql
  severity: warning
  description: "Avoid SELECT *."
  matcher: "contains_select_star == true"
  suggestion: "List columns."
""")

        findings = analyze(sql_file, rules_dir)
        assert len(findings) >= 1
        assert any(f.rule_id == "SQL001" for f in findings)
