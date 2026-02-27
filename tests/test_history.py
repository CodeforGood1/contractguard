"""Tests for the scan history module."""

from pathlib import Path
import tempfile
import pytest

from contractguard.engine import Finding, Severity
from contractguard.history import record_scan, get_history, get_trend


def _make_findings(n_critical: int = 0, n_warning: int = 0) -> list[Finding]:
    findings = []
    for i in range(n_critical):
        findings.append(Finding(
            rule_id=f"CRIT-{i}", rule_name="test", severity=Severity.CRITICAL,
            description=f"Critical issue {i}", explanation="test", suggestion="fix",
        ))
    for i in range(n_warning):
        findings.append(Finding(
            rule_id=f"WARN-{i}", rule_name="test", severity=Severity.WARNING,
            description=f"Warning {i}", explanation="test", suggestion="fix",
        ))
    return findings


class TestHistory:
    def test_record_and_retrieve(self, tmp_path):
        db = tmp_path / "test.db"
        findings = _make_findings(n_critical=2, n_warning=3)
        score = record_scan(findings, analyzer="json", source_path="test.json", db_path=db)
        assert score.grade in "ABCDF"
        assert score.total_findings == 5

        history = get_history(db_path=db)
        assert len(history) == 1
        assert history[0]["analyzer"] == "json"
        assert history[0]["total_findings"] == 5

    def test_multiple_scans(self, tmp_path):
        db = tmp_path / "test.db"
        record_scan(_make_findings(n_critical=5), "scan1", "path1", db)
        record_scan(_make_findings(n_warning=2), "scan2", "path2", db)
        record_scan([], "scan3", "path3", db)

        history = get_history(db_path=db)
        assert len(history) == 3

    def test_history_ordered_desc(self, tmp_path):
        db = tmp_path / "test.db"
        record_scan([], "first", "path1", db)
        record_scan(_make_findings(n_critical=1), "second", "path2", db)

        history = get_history(db_path=db)
        assert history[0]["analyzer"] == "second"
        assert history[1]["analyzer"] == "first"

    def test_history_limit(self, tmp_path):
        db = tmp_path / "test.db"
        for i in range(10):
            record_scan([], f"scan{i}", f"path{i}", db)

        history = get_history(limit=3, db_path=db)
        assert len(history) == 3

    def test_empty_history(self, tmp_path):
        db = tmp_path / "nonexistent.db"
        history = get_history(db_path=db)
        assert history == []

    def test_trend_no_data(self, tmp_path):
        db = tmp_path / "empty.db"
        trend = get_trend(db_path=db)
        assert trend["trend"] == "no_data"

    def test_trend_improving(self, tmp_path):
        db = tmp_path / "test.db"
        # First scan: bad (many criticals)
        record_scan(_make_findings(n_critical=8), "json", "p", db)
        # Second scan: good (no findings)
        record_scan([], "json", "p", db)

        trend = get_trend(db_path=db)
        assert trend["trend"] == "improving"

    def test_trend_degrading(self, tmp_path):
        db = tmp_path / "test.db"
        record_scan([], "json", "p", db)
        record_scan(_make_findings(n_critical=8), "json", "p", db)

        trend = get_trend(db_path=db)
        assert trend["trend"] == "degrading"

    def test_trend_stable(self, tmp_path):
        db = tmp_path / "test.db"
        record_scan(_make_findings(n_warning=1), "json", "p", db)
        record_scan(_make_findings(n_warning=1), "json", "p", db)

        trend = get_trend(db_path=db)
        assert trend["trend"] == "stable"
