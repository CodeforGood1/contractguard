"""Tests for the Dockerfile security analyzer."""

from pathlib import Path
import tempfile

import pytest

from contractguard.analyzers.dockerfile_analyzer import analyze, extract_facts

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class TestExtractFacts:
    def test_runs_as_root_by_default(self):
        content = "FROM ubuntu\nRUN apt-get update\n"
        facts = extract_facts(content)
        assert facts["runs_as_root"] is True

    def test_non_root_user(self):
        content = "FROM ubuntu\nUSER appuser\nRUN echo hi\n"
        facts = extract_facts(content)
        assert facts["runs_as_root"] is False

    def test_latest_tag(self):
        content = "FROM python:latest\n"
        facts = extract_facts(content)
        assert facts["uses_latest_tag"] is True

    def test_no_tag_implies_latest(self):
        content = "FROM ubuntu\n"
        facts = extract_facts(content)
        assert facts["uses_latest_tag"] is True

    def test_pinned_tag(self):
        content = "FROM python:3.12-slim\n"
        facts = extract_facts(content)
        assert facts["uses_latest_tag"] is False

    def test_copy_dot(self):
        content = "FROM ubuntu\nCOPY . /app\n"
        facts = extract_facts(content)
        assert facts["has_copy_dot"] is True

    def test_hardcoded_secrets(self):
        content = "FROM ubuntu\nENV DB_PASSWORD=mypassword\n"
        facts = extract_facts(content)
        assert facts["hardcoded_secrets"] is True

    def test_curl_pipe_bash(self):
        content = "FROM ubuntu\nRUN curl -sSL https://example.com/install.sh | bash\n"
        facts = extract_facts(content)
        assert facts["curl_pipe_bash"] is True

    def test_expose_ssh(self):
        content = "FROM ubuntu\nEXPOSE 22\n"
        facts = extract_facts(content)
        assert facts["exposes_ssh"] is True

    def test_sudo_usage(self):
        content = "FROM ubuntu\nRUN sudo apt-get install -y curl\n"
        facts = extract_facts(content)
        assert facts["uses_sudo"] is True

    def test_no_healthcheck(self):
        content = "FROM ubuntu\nCMD [\"python\", \"app.py\"]\n"
        facts = extract_facts(content)
        assert facts["no_healthcheck"] is True

    def test_has_healthcheck(self):
        content = "FROM ubuntu\nHEALTHCHECK CMD curl -f http://localhost/\n"
        facts = extract_facts(content)
        assert facts["no_healthcheck"] is False

    def test_clean_dockerfile(self):
        content = "FROM python:3.12-slim\nUSER appuser\nHEALTHCHECK CMD curl -f http://localhost/\nCOPY app.py /app/\nCMD [\"python\", \"app.py\"]\n"
        facts = extract_facts(content)
        assert facts["runs_as_root"] is False
        assert facts["uses_latest_tag"] is False
        assert facts["has_copy_dot"] is False
        assert facts["hardcoded_secrets"] is False


class TestAnalyze:
    def test_analyze_bad_dockerfile(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:latest\nRUN apt-get update\nCOPY . /app\nENV PASSWORD=secret\nEXPOSE 22\n")
        findings = analyze(tmp_path, RULES_DIR)
        assert len(findings) >= 3  # latest, copy dot, secrets, ssh, root, no healthcheck

    def test_analyze_good_dockerfile(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12-slim\nUSER nonroot\nHEALTHCHECK CMD curl -f http://localhost/\nCOPY app.py /app/\nCMD [\"python\", \"app.py\"]\n")
        findings = analyze(tmp_path, RULES_DIR)
        assert len(findings) == 0
