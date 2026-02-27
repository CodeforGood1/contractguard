"""Run History — SQLite-backed tracking of ContractGuard scans over time.

Enables trend analysis: is your security posture improving or degrading?
"""

from __future__ import annotations

import datetime
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from contractguard.engine import Finding
from contractguard.scorer import SecurityScore, compute_score

_DEFAULT_DB = Path.cwd() / ".contractguard" / "history.db"


def _ensure_db(db_path: Path) -> sqlite3.Connection:
    """Create the history database if it doesn't exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            analyzer TEXT NOT NULL,
            source_path TEXT NOT NULL,
            grade TEXT NOT NULL,
            score INTEGER NOT NULL,
            total_findings INTEGER NOT NULL,
            block_count INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            warning_count INTEGER NOT NULL,
            info_count INTEGER NOT NULL,
            findings_json TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def record_scan(
    findings: list[Finding],
    analyzer: str,
    source_path: str,
    db_path: Path | None = None,
) -> SecurityScore:
    """Record a scan and return the security score."""
    db_path = db_path or _DEFAULT_DB
    score = compute_score(findings)

    findings_data = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "description": f.description,
            "location": f.location,
        }
        for f in findings
    ]

    conn = _ensure_db(db_path)
    conn.execute(
        """
        INSERT INTO scans (timestamp, analyzer, source_path, grade, score,
                          total_findings, block_count, critical_count, warning_count,
                          info_count, findings_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
            analyzer,
            source_path,
            score.grade,
            score.score,
            score.total_findings,
            score.block_count,
            score.critical_count,
            score.warning_count,
            score.info_count,
            json.dumps(findings_data),
        ),
    )
    conn.commit()
    conn.close()
    return score


def get_history(
    limit: int = 20,
    analyzer: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Retrieve scan history."""
    db_path = db_path or _DEFAULT_DB
    if not db_path.exists():
        return []

    conn = _ensure_db(db_path)
    if analyzer:
        cursor = conn.execute(
            "SELECT * FROM scans WHERE analyzer = ? ORDER BY id DESC LIMIT ?",
            (analyzer, limit),
        )
    else:
        cursor = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        )

    columns = [desc[0] for desc in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_trend(db_path: Path | None = None) -> dict[str, Any]:
    """Get scoring trend over last scans."""
    history = get_history(limit=10, db_path=db_path)
    if not history:
        return {"trend": "no_data", "scores": []}

    scores = [h["score"] for h in reversed(history)]
    if len(scores) >= 2:
        diff = scores[-1] - scores[0]
        if diff > 5:
            trend = "improving"
        elif diff < -5:
            trend = "degrading"
        else:
            trend = "stable"
    else:
        trend = "insufficient_data"

    return {
        "trend": trend,
        "scores": scores,
        "latest_grade": history[0]["grade"],
        "latest_score": history[0]["score"],
    }
