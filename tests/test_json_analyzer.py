"""Tests for the JSON analyzer."""

import json

import pytest

from contractguard.analyzers.json_analyzer import (
    _flatten,
    _type_label,
    analyze,
    infer_facts,
    load_json_samples,
)


class TestTypeLabel:
    def test_types(self):
        assert _type_label(None) == "null"
        assert _type_label(True) == "boolean"
        assert _type_label(42) == "integer"
        assert _type_label(3.14) == "number"
        assert _type_label("hi") == "string"
        assert _type_label([]) == "array"
        assert _type_label({}) == "object"


class TestFlatten:
    def test_simple_object(self):
        pairs = _flatten({"a": 1, "b": "hi"})
        keys = [k for k, _ in pairs]
        assert "a" in keys
        assert "b" in keys

    def test_nested_object(self):
        pairs = _flatten({"user": {"name": "Alice"}})
        keys = [k for k, _ in pairs]
        assert "user" in keys
        assert "user.name" in keys


class TestInferFacts:
    def test_consistent_types(self):
        samples = [
            {"id": 1, "name": "a"},
            {"id": 2, "name": "b"},
        ]
        facts = infer_facts(samples)
        assert facts["field_types('id')"] == 1
        assert facts["total_samples"] == 2

    def test_inconsistent_types(self):
        samples = [
            {"price": 9.99},
            {"price": "9.99"},
        ]
        facts = infer_facts(samples)
        assert facts["field_types('price')"] == 2  # number + string

    def test_nullable_field(self):
        samples = [
            {"email": "a@b.com"},
            {"email": None},
        ]
        facts = infer_facts(samples)
        assert facts["nullable_fields"] >= 1

    def test_optional_field(self):
        samples = [
            {"id": 1, "bonus": 10},
            {"id": 2},
        ]
        facts = infer_facts(samples)
        assert facts["optional_fields"] >= 1

    def test_callable_field_types(self):
        samples = [{"x": 1}, {"x": "1"}]
        facts = infer_facts(samples)
        fn = facts["field_types"]
        assert fn("x") == 2
        assert fn("nonexistent") == 0


class TestLoadJsonSamples:
    def test_load_array_file(self, tmp_path):
        data = [{"a": 1}, {"a": 2}]
        f = tmp_path / "data.json"
        f.write_text(json.dumps(data))
        result = load_json_samples(f)
        assert len(result) == 2

    def test_load_single_object(self, tmp_path):
        f = tmp_path / "item.json"
        f.write_text(json.dumps({"a": 1}))
        result = load_json_samples(f)
        assert len(result) == 1

    def test_load_directory(self, tmp_path):
        (tmp_path / "a.json").write_text(json.dumps({"x": 1}))
        (tmp_path / "b.json").write_text(json.dumps([{"y": 2}]))
        result = load_json_samples(tmp_path)
        assert len(result) == 2


class TestAnalyze:
    def test_full_pipeline(self, tmp_path):
        # Create samples
        samples = [{"price": 9.99}, {"price": "9.99"}]
        sample_file = tmp_path / "samples.json"
        sample_file.write_text(json.dumps(samples))

        # Create rule
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_yaml = """
- id: JSON001
  name: inconsistent_field_types
  analyzer: json
  severity: warning
  description: "Field 'price' has multiple types."
  matcher: "field_types('price') > 1"
  suggestion: "Fix it."
"""
        (rules_dir / "json.yaml").write_text(rule_yaml)

        findings = analyze(sample_file, rules_dir)
        assert len(findings) == 1
        assert findings[0].rule_id == "JSON001"

    def test_no_findings_on_clean_data(self, tmp_path):
        samples = [{"id": 1}, {"id": 2}]
        sample_file = tmp_path / "clean.json"
        sample_file.write_text(json.dumps(samples))

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_yaml = """
- id: JSON001
  name: inconsistent_field_types
  analyzer: json
  severity: warning
  description: "Field 'price' has multiple types."
  matcher: "field_types('price') > 1"
  suggestion: "Fix it."
"""
        (rules_dir / "json.yaml").write_text(rule_yaml)

        findings = analyze(sample_file, rules_dir)
        assert len(findings) == 0
