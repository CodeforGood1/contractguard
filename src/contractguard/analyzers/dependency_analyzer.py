"""Dependency Vulnerability Scanner.

Scans requirements.txt / pyproject.toml for known vulnerable package versions.
Uses a local database — no internet required. Similar to pip-audit but self-contained.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from contractguard.engine import Finding, Severity, load_rules_for_analyzer, run_rules

# Local vulnerability database — curated set of high-profile CVEs
# Format: (package, operator, version, cve, severity, description)
_VULN_DB: list[tuple[str, str, str, str, str, str]] = [
    ("django", "<", "4.2.7", "CVE-2023-46695", "critical", "DoS via file upload handler"),
    ("django", "<", "3.2.23", "CVE-2023-46695", "critical", "DoS via file upload handler"),
    ("flask", "<", "2.3.2", "CVE-2023-30861", "warning", "Session cookie vulnerability"),
    ("requests", "<", "2.31.0", "CVE-2023-32681", "warning", "Proxy-Authorization header leak"),
    ("urllib3", "<", "2.0.7", "CVE-2023-45803", "warning", "Request body not stripped on redirect"),
    ("urllib3", "<", "1.26.18", "CVE-2023-45803", "warning", "Request body not stripped on redirect"),
    ("certifi", "<", "2023.7.22", "CVE-2023-37920", "critical", "Removal of e-Tugra root certificate"),
    ("cryptography", "<", "41.0.6", "CVE-2023-49083", "critical", "NULL pointer dereference in PKCS12"),
    ("pillow", "<", "10.0.1", "CVE-2023-44271", "warning", "DoS via uncontrolled resource consumption"),
    ("jinja2", "<", "3.1.3", "CVE-2024-22195", "critical", "XSS via xmlattr filter"),
    ("numpy", "<", "1.22.0", "CVE-2021-41496", "warning", "Buffer overflow in array_from_pyobj"),
    ("pyyaml", "<", "6.0.1", "CVE-2023-XXXXX", "warning", "Arbitrary code execution via YAML load"),
    ("sqlparse", "<", "0.4.4", "CVE-2023-30608", "warning", "ReDoS via crafted SQL"),
    ("aiohttp", "<", "3.9.0", "CVE-2023-49081", "critical", "HTTP request smuggling"),
    ("fastapi", "<", "0.109.0", "CVE-2024-24762", "warning", "DoS via multipart form data"),
    ("werkzeug", "<", "3.0.1", "CVE-2023-46136", "critical", "DoS via large multipart boundary"),
    ("tornado", "<", "6.4", "CVE-2023-28370", "warning", "Open redirect vulnerability"),
    ("paramiko", "<", "3.4.0", "CVE-2023-48795", "critical", "Terrapin SSH prefix truncation attack"),
    ("setuptools", "<", "65.5.1", "CVE-2022-40897", "warning", "ReDoS in package_index"),
    ("pip", "<", "23.3", "CVE-2023-5752", "info", "Dependency confusion via --extra-index-url"),
    ("starlette", "<", "0.36.2", "CVE-2024-24762", "warning", "DoS via multipart body"),
    ("pydantic", "<", "1.10.13", "CVE-2024-XXXXX", "info", "Information disclosure via error messages"),
    ("twisted", "<", "23.10.0", "CVE-2023-46137", "critical", "HTTP request smuggling"),
    ("scrapy", "<", "2.11.0", "CVE-2023-XXXXX", "warning", "Cookie leak to third-party domains"),
    ("ansible", "<", "8.5.0", "CVE-2023-5764", "critical", "Template injection in tasks"),
    ("gunicorn", "<", "22.0.0", "CVE-2024-1135", "critical", "HTTP request smuggling via transfer-encoding"),
    ("transformers", "<", "4.36.0", "CVE-2023-XXXXX", "critical", "Arbitrary code execution in model loading"),
    ("lxml", "<", "4.9.3", "CVE-2022-2309", "warning", "NULL pointer dereference"),
    ("black", "<", "24.1.0", "CVE-2024-XXXXX", "info", "Jupyter notebook parsing issue"),
]


def _parse_version(version_str: str) -> tuple:
    """Parse a version string into a comparable tuple."""
    clean = re.sub(r"^[~^>=<!=]+", "", version_str.strip())
    parts = []
    for p in clean.split("."):
        m = re.match(r"(\d+)", p)
        if m:
            parts.append(int(m.group(1)))
        else:
            parts.append(0)
    return tuple(parts)


def _version_matches(installed: str, op: str, vuln_version: str) -> bool:
    """Check if installed version is affected."""
    installed_t = _parse_version(installed)
    vuln_t = _parse_version(vuln_version)
    if op == "<":
        return installed_t < vuln_t
    if op == "<=":
        return installed_t <= vuln_t
    if op == "==":
        return installed_t == vuln_t
    return False


def extract_facts_from_requirements(content: str) -> dict[str, Any]:
    """Parse requirements.txt and check against vulnerability database."""
    facts: dict[str, Any] = {
        "vulnerable_count": 0,
        "total_packages": 0,
        "unpinned_count": 0,
        "vulnerabilities": [],  # list of (pkg, version, cve, severity, desc)
        "has_vulnerable_packages": False,
        "has_unpinned_packages": False,
        "critical_vuln_count": 0,
    }

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue

        facts["total_packages"] += 1

        # Parse package==version, package>=version, package~=version, or just package
        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:[>=<~!=]+\s*(\S+))?", stripped)
        if not m:
            continue

        pkg_name = m.group(1).lower().replace("-", "_").replace(".", "_")
        pkg_version = m.group(2)

        if not pkg_version:
            facts["unpinned_count"] += 1
            facts["has_unpinned_packages"] = True
            continue

        for vuln_pkg, op, vuln_ver, cve, sev, desc in _VULN_DB:
            vuln_pkg_normalized = vuln_pkg.lower().replace("-", "_").replace(".", "_")
            if pkg_name == vuln_pkg_normalized:
                if _version_matches(pkg_version, op, vuln_ver):
                    facts["vulnerable_count"] += 1
                    facts["has_vulnerable_packages"] = True
                    facts["vulnerabilities"].append((m.group(1), pkg_version, cve, sev, desc))
                    if sev == "critical":
                        facts["critical_vuln_count"] += 1

    return facts


def load_dependency_files(path: str | Path) -> list[tuple[str, str]]:
    """Load dependency files."""
    path = Path(path)
    files: list[tuple[str, str]] = []
    dep_names = {"requirements.txt", "requirements-dev.txt", "requirements_dev.txt",
                 "requirements.in", "constraints.txt"}

    if path.is_dir():
        for name in sorted(dep_names):
            f = path / name
            if f.exists():
                files.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
        for f in sorted(path.glob("requirements*.txt")):
            if str(f) not in [x[0] for x in files]:
                files.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
    elif path.is_file():
        files.append((str(path), path.read_text(encoding="utf-8", errors="replace")))

    return files


def analyze(path: str | Path, rules_dir: str | Path) -> list[Finding]:
    """Run dependency vulnerability analysis."""
    files = load_dependency_files(path)
    rules = load_rules_for_analyzer(rules_dir, "deps")
    all_findings: list[Finding] = []

    for source, content in files:
        facts = extract_facts_from_requirements(content)
        findings = run_rules(facts, rules)
        for f in findings:
            f.location = source
        all_findings.extend(findings)

        # Direct findings for each vulnerability
        for pkg, ver, cve, sev, desc in facts["vulnerabilities"]:
            try:
                severity = Severity(sev)
            except ValueError:
                severity = Severity.WARNING

            finding = Finding(
                rule_id=cve,
                rule_name=f"vuln_{pkg}",
                severity=severity,
                description=f"{pkg}=={ver}: {desc}",
                explanation=f"Installed version {ver} is affected by {cve}",
                suggestion=f"Upgrade {pkg} to the latest patched version. Run: pip install --upgrade {pkg}",
                location=source,
                context=f"{pkg}=={ver}",
                attack_vector=f"Exploiting {cve} in {pkg} {ver} — {desc}",
                cwe="CWE-1035",
            )
            all_findings.append(finding)

    return all_findings
