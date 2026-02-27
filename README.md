# ContractGuard

**Stop bad inputs before they break your systems.**

ContractGuard is a production-grade security analysis platform that scans your entire project — data files, configs, Dockerfiles, dependencies, source code — and flags reliability, safety, and security issues **before they reach production**. Think of it as a security-first linter for everything that touches your pipeline.

**9 Analyzers. 1 Engine. 57+ Rules. A-F Security Grading. SARIF Export. CI/CD Ready.**

---

## What It Catches

| Analyzer | What It Detects | Severity Range |
|----------|-----------------|----------------|
| **JSON Schema** | Type drift, inconsistent schemas, nullable fields | Warning-Critical |
| **SQL Performance** | `SELECT *`, missing `WHERE`, cartesian joins, ReDoS-prone LIKE | Warning-Critical |
| **Regex Complexity** | Nested quantifiers (ReDoS), backreferences, catastrophic backtracking | Warning-Critical |
| **Secrets Detection** | AWS keys, GitHub tokens, Stripe keys, private keys, JWTs, DB URLs (21 patterns) | Critical-BLOCK |
| **PII Detection** | SSNs, credit cards, emails, phone numbers, medical records, passports, IBAN | Critical-BLOCK |
| **CSV Data Quality** | Mixed types, null-heavy columns, duplicate rows, encoding issues | Info-Warning |
| **Config Security** | Debug mode, CORS wildcards, weak secrets, SSL disabled, default passwords | Warning-Critical |
| **Dockerfile Lint** | Running as root, `:latest` tags, `COPY .`, hardcoded secrets, `curl\|bash` | Warning-Critical |
| **Dependency Vulns** | 29+ known CVEs (Django, Flask, cryptography, urllib3, etc.) — offline DB | Warning-BLOCK |

All analyzers share a **YAML-based rule engine** with consistent severities, CWE IDs, attack vector descriptions, and actionable suggestions.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/contractguard/contractguard.git
cd contractguard
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # macOS/Linux
pip install -e ".[dev]"
```

### Run a Full Scan

```bash
# Scan EVERYTHING — all 9 analyzers at once
contractguard analyze --type all --path . --report security-report.html --score

# Individual analyzers
contractguard analyze --type secrets --path .
contractguard analyze --type deps --path requirements.txt
contractguard analyze --type dockerfile --path .
contractguard analyze --type config --path config/
contractguard analyze --type pii --path data/
contractguard analyze --type sql --path queries/ --ci
```

### Security Grade

```bash
contractguard score --path .
# Output: Grade F | Score 0/100 | 30 BLOCK, 130 CRITICAL findings
```

### Scan History & Trends

```bash
contractguard analyze --type all --path . --record  # Track over time
contractguard history                                # Show trend
```

### Watch Mode

```bash
contractguard watch --path src/ --type secrets --interval 5
# Re-scans on every file change
```

### SARIF Export (GitHub Code Scanning)

```bash
contractguard analyze --type all --path . --report-sarif results.sarif
# Upload to GitHub → Security tab → Code scanning alerts
```

### Web UI

```bash
contractguard serve
# Open http://127.0.0.1:8000 — upload files, pick analyzer, get instant report
```

### CI/CD Integration

```bash
# In your CI pipeline — fails on critical/block findings
contractguard analyze --type all --path . --ci --report-sarif results.sarif
```

---

## 90-Second Demo Script

> **Step 1 — The Problem (10s)**
> "Your API schemas drift. Your SQL hides performance bombs. Your configs leak secrets. Your Dockerfiles run as root. Your dependencies have known CVEs."

> **Step 2 — Full Project Scan (20s)**
> ```bash
> contractguard analyze --type all --path samples/ --report report.html --score
> ```
> Open report.html — Grade F, 164 findings, attack surface mapped, BLOCK-level secrets and vulnerabilities flagged.

> **Step 3 — Secrets Detection (15s)**
> ```bash
> contractguard analyze --type secrets --path samples/secrets/
> ```
> AWS keys detected, DB passwords found, private keys exposed — each with CWE IDs and attack scenarios.

> **Step 4 — Dependency Vulnerabilities (15s)**
> ```bash
> contractguard analyze --type deps --path samples/deps/
> ```
> Django CVE-2023-46695, cryptography NULL-ptr deref, Werkzeug DoS — all caught offline, no API needed.

> **Step 5 — SARIF + CI (15s)**
> "Upload the SARIF file to GitHub Security tab. In CI, BLOCK-level findings return exit code 2 — deployment stops automatically."

> **Step 6 — Web UI (15s)**
> Start the web server, upload a Dockerfile, see instant results with attack vectors and remediation steps.

---

## Architecture

```
contractguard/
├── src/contractguard/
│   ├── __init__.py              # v2.0.0
│   ├── cli.py                   # Typer CLI — analyze, score, history, watch, serve
│   ├── engine.py                # YAML rule engine — BLOCK severity, CWE, attack vectors
│   ├── reporter.py              # HTML (dark theme + grade), JSON, SARIF 2.1.0
│   ├── scorer.py                # A-F security grade calculator
│   ├── history.py               # SQLite scan tracking + trend analysis
│   ├── web.py                   # FastAPI web UI (all 9 analyzers)
│   └── analyzers/
│       ├── json_analyzer.py     # JSON schema inference
│       ├── sql_analyzer.py      # SQL static analysis
│       ├── regex_analyzer.py    # Regex complexity / ReDoS detection
│       ├── secrets_analyzer.py  # 21+ secret patterns (AWS, GCP, Stripe, etc.)
│       ├── pii_analyzer.py      # 13 PII patterns (SSN, CC, IBAN, MRN, etc.)
│       ├── csv_analyzer.py      # CSV type/null/duplicate detection
│       ├── config_analyzer.py   # Config security audit (YAML/TOML/ENV)
│       ├── dockerfile_analyzer.py # Dockerfile security linting
│       └── dependency_analyzer.py # Offline CVE scanner (29+ vulns)
├── rules/                       # 9 YAML rule files, 57+ rules
├── samples/                     # Demo inputs for all analyzer types
├── tests/                       # 162 unit tests
├── .github/workflows/           # GitHub Actions CI
└── pyproject.toml
```

---

## Severity Levels

| Level | Meaning | CI Behavior |
|-------|---------|-------------|
| `info` | Best practice suggestion | Pass |
| `warning` | Should fix before production | Pass |
| `critical` | Security/reliability risk | Fail (`--ci`) |
| `block` | Deployment must be stopped immediately | Fail (`--ci`) |

---

## Rule Format

```yaml
- id: SEC001
  name: hardcoded_secrets
  analyzer: secrets
  severity: block
  description: "Hardcoded secrets found — immediate rotation required."
  matcher: "secret_count > 0"
  suggestion: "Use environment variables or a secrets vault (AWS SSM, HashiCorp Vault)."
  attack_vector: "Attacker clones repo → extracts credentials → gains unauthorized access"
  cwe: "CWE-798"
```

---

## CLI Reference

```
contractguard analyze [OPTIONS]
  -t, --type TEXT       json|sql|regex|secrets|pii|csv|config|dockerfile|deps|all
  -p, --path PATH       File or directory to scan
  --report PATH         HTML report output
  --report-json PATH    JSON report output
  --report-sarif PATH   SARIF 2.1.0 output (GitHub Code Scanning)
  --score               Show security grade after scan
  --record              Save to history database
  --ci                  Exit 2 on critical/block findings

contractguard score --path .          # Full scan → letter grade
contractguard history                 # Scan trends
contractguard watch --path . --type all  # Re-scan on changes
contractguard serve                   # Web UI on :8000
```

---

## Hackathon Themes

- **Software Development & Engineering** — CLI tool, CI/CD integration, rule-based architecture
- **Cybersecurity & Privacy** — Secrets detection, PII scanning, Dockerfile hardening, dependency CVEs, SARIF
- **Data Science & Analytics** — Schema inference, CSV quality analysis, data contract enforcement
- **Business & Productivity** — Security scoring, trend tracking, automated compliance checks

---

## Future Scope (VS Code Extension Ready)

ContractGuard is architecturally ready for VS Code extension conversion:

- **Language Server Protocol**: Each analyzer returns structured `Finding` objects with file paths and line numbers — directly mappable to VS Code Diagnostics
- **Real-time analysis**: The `watch` mode already implements file-change detection — LSP `onDidChangeTextDocument` is a natural fit
- **Inline annotations**: Every finding includes severity, description, suggestion, CWE, and attack vector — all displayable as hover tooltips
- **Quick fixes**: Suggestions can power VS Code Quick Fix actions (e.g., "Remove hardcoded secret", "Pin Docker image tag")
- **Security Score in status bar**: The scoring system maps directly to a status bar item showing project health
- **SARIF integration**: VS Code's SARIF Viewer extension can display ContractGuard output natively

---

## Tech Stack

| Component | Library |
|-----------|---------|
| CLI | Typer + Rich |
| Rule Engine | PyYAML + custom evaluator |
| HTML Reports | Jinja2 (dark theme, security grade, attack vectors) |
| SARIF | Custom 2.1.0 generator |
| Web UI | FastAPI + Uvicorn |
| History | SQLite3 |
| Testing | pytest (162 tests) |

---

## License

MIT
