"""Dockerfile Security Linter.

Detects security anti-patterns in Dockerfiles: running as root, using latest tags,
COPY without .dockerignore, exposed secrets, apt-get without cleanup, etc.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from contractguard.engine import Finding, Severity, load_rules_for_analyzer, run_rules


def extract_facts(content: str, filename: str = "") -> dict[str, Any]:
    """Extract security facts from a Dockerfile."""
    facts: dict[str, Any] = {
        "runs_as_root": True,  # default true unless USER is set
        "uses_latest_tag": False,
        "has_copy_dot": False,
        "has_add_instruction": False,
        "apt_get_no_cleanup": False,
        "hardcoded_secrets": False,
        "no_healthcheck": True,
        "exposes_ssh": False,
        "curl_pipe_bash": False,
        "too_many_layers": False,
        "uses_sudo": False,
        "missing_pinned_version": False,
        "layer_count": 0,
        "security_issues_count": 0,
    }

    lines = content.splitlines()
    has_user_instruction = False
    has_healthcheck = False
    run_count = 0

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        upper = stripped.upper()

        if upper.startswith("FROM "):
            from_image = stripped[5:].strip().split()[0]
            if ":latest" in from_image:
                facts["uses_latest_tag"] = True
                facts["security_issues_count"] += 1
            elif ":" not in from_image and "@" not in from_image and from_image.lower() != "scratch":
                facts["uses_latest_tag"] = True
                facts["security_issues_count"] += 1

        if upper.startswith("USER "):
            user = stripped[5:].strip().lower()
            if user not in ("root", "0"):
                has_user_instruction = True

        if re.match(r"^COPY\s+\.\s+", stripped, re.I) or re.match(r"^COPY\s+\.\.\s", stripped, re.I):
            facts["has_copy_dot"] = True
            facts["security_issues_count"] += 1

        if upper.startswith("ADD "):
            facts["has_add_instruction"] = True
            facts["security_issues_count"] += 1

        if upper.startswith("RUN ") and "apt-get install" in stripped.lower():
            if "rm -rf /var/lib/apt/lists" not in stripped:
                facts["apt_get_no_cleanup"] = True
                facts["security_issues_count"] += 1
            run_count += 1
        elif upper.startswith("RUN "):
            run_count += 1

        if upper.startswith("ENV "):
            env_line = stripped[4:].strip().lower()
            if any(kw in env_line for kw in ["password", "secret", "api_key", "token", "private_key"]):
                facts["hardcoded_secrets"] = True
                facts["security_issues_count"] += 1

        if upper.startswith("HEALTHCHECK "):
            has_healthcheck = True

        if upper.startswith("EXPOSE ") and "22" in stripped.split():
            facts["exposes_ssh"] = True
            facts["security_issues_count"] += 1

        if re.search(r"curl.*\|\s*(?:ba)?sh", stripped, re.I) or \
           re.search(r"wget.*\|\s*(?:ba)?sh", stripped, re.I):
            facts["curl_pipe_bash"] = True
            facts["security_issues_count"] += 1

        if re.search(r"\bsudo\b", stripped):
            facts["uses_sudo"] = True
            facts["security_issues_count"] += 1

    facts["runs_as_root"] = not has_user_instruction
    if not has_user_instruction:
        facts["security_issues_count"] += 1

    facts["no_healthcheck"] = not has_healthcheck
    if not has_healthcheck:
        facts["security_issues_count"] += 1

    facts["layer_count"] = run_count
    if run_count > 10:
        facts["too_many_layers"] = True
        facts["security_issues_count"] += 1

    return facts


def load_dockerfiles(path: str | Path) -> list[tuple[str, str]]:
    """Load Dockerfiles from a path."""
    path = Path(path)
    files: list[tuple[str, str]] = []

    if path.is_dir():
        for name in ["Dockerfile", "dockerfile", "Dockerfile.prod", "Dockerfile.dev"]:
            f = path / name
            if f.exists():
                files.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
        for f in sorted(path.glob("Dockerfile*")):
            if str(f) not in [x[0] for x in files]:
                files.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
        for f in sorted(path.glob("*.dockerfile")):
            files.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
    elif path.is_file():
        files.append((str(path), path.read_text(encoding="utf-8", errors="replace")))

    return files


def analyze(path: str | Path, rules_dir: str | Path) -> list[Finding]:
    """Run Dockerfile security analysis."""
    files = load_dockerfiles(path)
    rules = load_rules_for_analyzer(rules_dir, "dockerfile")
    all_findings: list[Finding] = []

    for source, content in files:
        facts = extract_facts(content, source)
        findings = run_rules(facts, rules)
        for f in findings:
            f.location = source
            f.context = f"Dockerfile: {Path(source).name}"
        all_findings.extend(findings)

    return all_findings
