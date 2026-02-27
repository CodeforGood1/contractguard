# ContractGuard — Step-by-Step Instructions

> For a full capabilities reference see [CAPABILITIES.md](CAPABILITIES.md).
> For deployment options see [DEPLOYMENT.md](DEPLOYMENT.md).

---

## Table of Contents

1. [Installation](#1-installation)
2. [First Run (2 minutes)](#2-first-run-2-minutes)
3. [Running Each Analyzer](#3-running-each-analyzer)
4. [Reading the Results](#4-reading-the-results)
5. [Generating Reports](#5-generating-reports)
6. [Using the Web UI](#6-using-the-web-ui)
7. [Setting Up CI/CD](#7-setting-up-cicd)
8. [Scanning Your Own Project](#8-scanning-your-own-project)
9. [Pre-commit Hook Setup](#9-pre-commit-hook-setup)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Installation

### Requirements

- Python 3.11 or higher
- pip

### Windows

```powershell
git clone https://github.com/contractguard/contractguard.git
cd contractguard
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
contractguard version
```

### macOS / Linux

```bash
git clone https://github.com/contractguard/contractguard.git
cd contractguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
contractguard version
```

### Verify Installation

```
$ contractguard version
ContractGuard v2.0.0
```

---

## 2. First Run (2 minutes)

### Scan everything in the included samples directory

```bash
contractguard analyze --type all --path samples/ --score
```

Expected output:
- A findings table with 100+ issues across secrets, PII, config, Dockerfile, and dependencies
- A security grade panel showing **Grade F** with score breakdown
- Attack surface and top risks listed

### Generate an HTML report

```bash
contractguard analyze --type all --path samples/ --report my-first-report.html --score
```

Open `my-first-report.html` in your browser — dark theme, animated BLOCK badges, attack surface map.

---

## 3. Running Each Analyzer

### Secrets Detection

Scans any file for hardcoded API keys, tokens, passwords, private keys.

```bash
# Scan a single file
contractguard analyze --type secrets --path config/.env

# Scan an entire directory
contractguard analyze --type secrets --path src/

# Fail CI pipeline if secrets found
contractguard analyze --type secrets --path . --ci
```

### PII Detection

Scans for SSNs, credit cards, emails, medical records, passports.

```bash
contractguard analyze --type pii --path data/
contractguard analyze --type pii --path exports/customers.json
```

### Dependency Vulnerabilities

Scans `requirements.txt` or `pyproject.toml` against a local CVE database.

```bash
contractguard analyze --type deps --path requirements.txt
contractguard analyze --type deps --path .   # finds requirements.txt automatically
```

### Config Security

Audits `.env`, `.yaml`, `.toml`, `.ini`, `.json` files for dangerous settings.

```bash
contractguard analyze --type config --path config/
contractguard analyze --type config --path .env
```

### Dockerfile

Scans Dockerfiles for root execution, `:latest` tags, hardcoded secrets, `curl | bash`.

```bash
contractguard analyze --type dockerfile --path .
contractguard analyze --type dockerfile --path docker/Dockerfile.prod
```

### JSON Schema

Detects type drift, inconsistent schemas, nullable fields.

```bash
contractguard analyze --type json --path api/payloads/
contractguard analyze --type json --path data.json
```

### SQL Analysis

Flags `SELECT *`, missing `WHERE`, cartesian joins, ReDoS-prone `LIKE`.

```bash
contractguard analyze --type sql --path queries/
contractguard analyze --type sql --path migrations/
```

### Regex Complexity

Detects ReDoS-vulnerable patterns, nested quantifiers, excessive complexity.

```bash
contractguard analyze --type regex --path src/validators.py
contractguard analyze --type regex --path patterns/
```

### CSV Data Quality

Checks type consistency, null rates, duplicate rows, encoding issues.

```bash
contractguard analyze --type csv --path data/exports/
```

### Full Scan (All Analyzers)

```bash
contractguard analyze --type all --path . --score --report report.html
```

---

## 4. Reading the Results

### CLI Output

Each finding shows:

| Column | Meaning |
|--------|---------|
| ID | Rule ID (e.g. `SEC001`, `DEP002`) |
| Severity | `INFO` / `WARNING` / `CRITICAL` / `🚫 BLOCK` |
| Description | What was found |
| Location | File path |
| Suggestion | How to fix it |

### Severity at a Glance

- `INFO` — awareness only, no action required
- `WARNING` — fix before your next release
- `CRITICAL` — active risk, fix before any deployment
- `🚫 BLOCK` — stop everything, fix immediately

### Score Panel (with `--score`)

```
╭─ Security Score ──────────────────────────╮
│  Grade: F  |  Score: 0/100                │
│  BLOCK: 30  CRITICAL: 130  WARNING: 4     │
│  Attack Surface: credential_theft, ...    │
│  Top Risks: hardcoded_secrets, ...        │
╰───────────────────────────────────────────╯
```

---

## 5. Generating Reports

### HTML Report

```bash
contractguard analyze --type all --path . --report security-report.html
```

Open in any browser. Includes grade banner, attack surface map, animated BLOCK badges.

### JSON Report (machine-readable)

```bash
contractguard analyze --type all --path . --report-json findings.json
```

Pipe into other tools, dashboards, or custom scripts.

### SARIF 2.1.0 (GitHub Code Scanning)

```bash
contractguard analyze --type all --path . --report-sarif results.sarif
```

Upload to GitHub Security tab for inline annotations on your code.

### All three at once

```bash
contractguard analyze --type all --path . \
  --report report.html \
  --report-json report.json \
  --report-sarif report.sarif \
  --score
```

---

## 6. Using the Web UI

### Start the server

```bash
contractguard serve
```

Opens at `http://127.0.0.1:8000`

### Usage

1. Open `http://127.0.0.1:8000` in your browser
2. Choose an analyzer type from the dropdown (or select **all**)
3. Click **Choose File** and upload the file you want to scan
4. Click **Analyze**
5. Results appear inline on the page

### What you can upload

- Any text file for secrets/PII scanning
- `.env`, `.yaml`, `.toml`, `.json`, `.ini` for config scanning
- `Dockerfile` for container analysis
- `requirements.txt` for dependency scanning
- `.csv` files for data quality analysis
- SQL files for query analysis
- Any `.json` file for schema analysis

---

## 7. Setting Up CI/CD

### GitHub Actions (built-in)

The workflow file `.github/workflows/contractguard-ci.yml` is already included.

It runs on every `push` and `pull_request`:
- Scans the whole repo with `--type all`
- Uploads HTML report as a downloadable artifact
- Uploads SARIF to GitHub Code Scanning
- **Fails the build** (`exit 2`) on CRITICAL or BLOCK findings

Activate it by pushing to GitHub — no additional setup needed.

### Manual CI integration

Add this to any CI pipeline:

```bash
pip install contractguard
contractguard analyze --type all --path . --ci --report-sarif results.sarif
# exit code 2 = critical/block findings found
```

### GitHub SARIF Upload (in your existing workflow)

```yaml
- name: Run ContractGuard
  run: contractguard analyze --type all --path . --report-sarif results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Track scan history in CI

```bash
contractguard analyze --type all --path . --ci --record
contractguard history
```

---

## 8. Scanning Your Own Project

ContractGuard can analyze its own source code (and any Python project):

```bash
# Secrets and PII in source files
contractguard analyze --type secrets --path src/
contractguard analyze --type pii --path src/

# Dependency vulnerabilities
contractguard analyze --type deps --path pyproject.toml

# Config files
contractguard analyze --type config --path .

# Full project scan
contractguard analyze --type all --path . --score
```

> **Note:** The tool flags its own `secrets_analyzer.py` for containing PEM header strings (e.g. `-----BEGIN PRIVATE KEY-----`). These are regex detection patterns, not real secrets — but this demonstrates how aggressive the scanner is. In production, add a `.contractguardignore` exclusion list (future feature) or note these as false positives.

### Scan history and trends

```bash
# Record today's scan
contractguard analyze --type all --path . --score --record

# Check trend over time
contractguard history
```

---

## 9. Pre-commit Hook Setup

Run secrets detection automatically on every `git commit`.

### Install

```bash
pip install pre-commit
pre-commit install
```

### What it does

Every `git commit` will run:
- Secrets scan on all staged files
- If secrets are found, the commit is **blocked** with a finding report

### Manual run (all files)

```bash
pre-commit run --all-files
```

---

## 10. Troubleshooting

### `UnicodeEncodeError` on Windows

Set UTF-8 encoding before running:

```powershell
$env:PYTHONIOENCODING = "utf-8"
contractguard analyze ...
```

Or add it to your PowerShell profile permanently.

### `contractguard: command not found`

Make sure your virtual environment is activated:

```bash
# Windows
.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Then reinstall: `pip install -e .`

### No findings returned

- Check that the path points to real files: `--path src/` not `--path src`
- Make sure the file type matches the analyzer (e.g. `--type deps` needs a `requirements.txt`)
- Try `--type all` for broad coverage

### Web UI returns 500 error

Check the terminal running `contractguard serve` for the traceback. Common cause: uploaded file has binary content when the analyzer expects text.

### Tests failing after code changes

```bash
pytest tests/ -v --tb=short
```

Check the specific failing test for the assertion that broke.
