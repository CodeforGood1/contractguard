# ContractGuard — Full Capabilities Reference

> Version 2.0.0 | 9 Analyzers | 57+ Rules | 162 Tests

---

## Table of Contents

1. [Analyzer Capabilities](#1-analyzer-capabilities)
2. [Security Scoring](#2-security-scoring)
3. [Reporting Formats](#3-reporting-formats)
4. [CLI Commands](#4-cli-commands)
5. [Web UI](#5-web-ui)
6. [Rule Engine](#6-rule-engine)
7. [CI/CD Integration](#7-cicd-integration)
8. [Scan History & Trends](#8-scan-history--trends)
9. [Severity Model](#9-severity-model)
10. [Compliance Coverage](#10-compliance-coverage)

---

## 1. Analyzer Capabilities

### 1.1 JSON Schema Analyzer (`--type json`)

Scans JSON files and infers schema facts from the actual data, then checks those facts against rules.

| Capability | Detail |
|------------|--------|
| Type inference | Detects integer, number, string, boolean, null, array, object per field |
| Type drift detection | Flags fields that hold more than one type across records |
| Nullable field detection | Reports fields that are null in some records |
| Structural consistency | Checks field presence vs absence across object arrays |
| Schema violations | Catches empty arrays, deeply nested objects, unexpected schema shapes |
| Multi-file support | Scans every `.json` file in a directory |

**Rules:** 8 rules (JSON001–JSON008)

---

### 1.2 SQL Query Analyzer (`--type sql`)

Static analysis of SQL queries for performance anti-patterns and security issues.

| Capability | Detail |
|------------|--------|
| `SELECT *` detection | Flags queries selecting all columns |
| Missing `WHERE` clause | Detects full-table reads on `DELETE`, `UPDATE`, `SELECT` |
| Cartesian join detection | Finds `JOIN` without `ON` conditions |
| Subquery in `WHERE` | Flags correlated subquery patterns |
| Leading-wildcard `LIKE` | Detects `LIKE '%value'` which defeats indexes |
| `OR` in `WHERE` | Flags conditions that may prevent index use |
| Multi-statement detection | Warns on semicolon-separated statement chains |
| Optional EXPLAIN support | Can run `EXPLAIN` against a live SQLite DB |

**Rules:** 8 rules (SQL001–SQL008)

---

### 1.3 Regex Complexity Analyzer (`--type regex`)

Parses regex patterns using Python's internal `re._parser` AST and scores structural complexity.

| Capability | Detail |
|------------|--------|
| Complexity scoring | 0–100 score based on nested quantifiers, alternations, groups |
| ReDoS detection | Flags nested quantifiers (`(a+)+`, `(a*)*`) — catastrophic backtracking |
| Backreference detection | Warns on `\1`, `\2` style backreferences |
| Long alternation chains | Detects alternation with 10+ branches |
| Syntax validation | Catches invalid regex patterns outright |
| Pattern length | Flags patterns over 200 characters |

**Rules:** 7 rules (REG001–REG007)

---

### 1.4 Secrets Detection Analyzer (`--type secrets`)

Scans any file for hardcoded credentials using 21 regex patterns. All matched values are **redacted** in output.

| Pattern | What It Catches |
|---------|----------------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` format |
| AWS Secret Key | 40-char alphanumeric after `aws_secret` keys |
| GitHub Token | `ghp_`, `gho_`, `ghs_`, `github_pat_` prefixes |
| Stripe Secret Key | `sk_live_` and `sk_test_` |
| Stripe Publishable Key | `pk_live_` and `pk_test_` |
| Slack Token | `xoxb-`, `xoxp-`, `xoxa-` prefixes |
| GCP API Key | `AIza[0-9A-Za-z]{35}` |
| Generic API Key | `api[_-]?key\s*=\s*` patterns |
| Database URLs | `postgresql://`, `mysql://`, `mongodb://` with credentials |
| Private Keys | PEM `-----BEGIN PRIVATE KEY-----` headers |
| RSA Private Key | PEM `-----BEGIN RSA PRIVATE KEY-----` headers |
| JWT Tokens | Three-segment base64 with `.` separators |
| npm Auth Token | `_authToken` in `.npmrc` |
| SendGrid API Key | `SG.[a-zA-Z0-9]{22}` format |
| Twilio Auth Token | 32-char hex after `twilio` keyword |
| Generic Passwords | `password\s*=\s*` with non-placeholder values |
| Hex Secrets | 32–64 char hex strings in secret/token fields |
| Base64 Secrets | Long base64 blobs in secret/key fields |
| Bearer Tokens | `Authorization: Bearer ...` headers |
| Hardcoded Auth Headers | Auth header values in source files |
| Generic Secret Fields | `secret\s*=\s*` or `token\s*=\s*` patterns |

**Rules:** 5 rules (SEC001–SEC005) | Default severity: **BLOCK / CRITICAL**

---

### 1.5 PII Detection Analyzer (`--type pii`)

Detects personally identifiable information across any file type. Maps findings to GDPR, CCPA, and HIPAA.

| Pattern | Regulation | Severity |
|---------|-----------|----------|
| US Social Security Number (SSN) | HIPAA, CCPA | **BLOCK** |
| Credit / Debit Card Numbers | PCI-DSS, CCPA | **BLOCK** |
| Email Addresses | GDPR, CCPA | CRITICAL |
| US Phone Numbers | CCPA | CRITICAL |
| Date of Birth | GDPR, HIPAA | CRITICAL |
| IP Addresses | GDPR | WARNING |
| Passport Numbers | GDPR | CRITICAL |
| IBAN / Bank Account Numbers | GDPR | CRITICAL |
| Driver's License Numbers | CCPA | CRITICAL |
| Medical Record Numbers (MRN) | HIPAA | **BLOCK** |
| NHS / National Health IDs | GDPR | CRITICAL |
| PII Field Name Detection | All | WARNING |

Also detects PII by **field name** heuristics: fields named `ssn`, `dob`, `passport`, `credit_card`, `medical_id`, etc.

**Rules:** 4 rules (PII001–PII004)

---

### 1.6 CSV Data Quality Analyzer (`--type csv`)

Audits CSV files for structural and data quality issues.

| Capability | Detail |
|------------|--------|
| Type inference per column | Classifies each column: null / boolean / integer / number / date / string |
| Mixed-type columns | Flags columns where values resolve to more than one type |
| Inconsistent column counts | Detects rows with different field counts than the header |
| Null-heavy columns | Flags columns with more than 30% null/empty values |
| Duplicate rows | Detects identical rows across the dataset |
| Encoding issues | Catches non-UTF-8 characters suggesting encoding corruption |
| Large file warning | Notes very large CSVs that may cause memory issues |

**Rules:** 5 rules (CSV001–CSV005)

---

### 1.7 Config Security Analyzer (`--type config`)

Audits configuration files for dangerous settings. Supports `.yaml`, `.yml`, `.toml`, `.json`, `.env`, `.ini`, `.cfg`, `.conf`.

| Check | What It Detects | Severity |
|-------|----------------|----------|
| Debug mode enabled | `DEBUG=true`, `debug: true` | CRITICAL |
| CORS wildcard | `CORS_ALLOW_ALL`, `allow_origins: ["*"]` | CRITICAL |
| Insecure secret key | Weak/default `SECRET_KEY` values | **BLOCK** |
| Default passwords | `password=admin`, `password=12345`, etc. | **BLOCK** |
| SSL/TLS disabled | `ssl_enabled: false`, `tls=off`, `https=disabled` | CRITICAL |
| Wildcard host binding | `HOST=0.0.0.0` in non-container configs | WARNING |
| Root user | `DB_USER=root` or `user=root` entries | CRITICAL |
| HTTP instead of HTTPS | `http://` URLs in production configs | WARNING |
| Exposed admin ports | Common admin ports (8080, 9200, 5601, 15672) | WARNING |

**Rules:** 9 rules (CFG001–CFG009)

---

### 1.8 Dockerfile Analyzer (`--type dockerfile`)

Static analysis of Dockerfiles for security misconfigurations and bad practices.

| Check | What It Detects | Severity |
|-------|----------------|----------|
| Runs as root | No `USER` instruction set | CRITICAL |
| Latest tag | `FROM image:latest` (non-deterministic builds) | WARNING |
| `COPY .` (broad copy) | Copies entire build context including secrets | WARNING |
| Hardcoded secrets in ENV | `ENV API_KEY=...`, `ENV PASSWORD=...` | **BLOCK** |
| `curl \| bash` installs | Remote code execution at build time | CRITICAL |
| Exposed SSH port | `EXPOSE 22` opens SSH | CRITICAL |
| `sudo` usage | Privilege escalation inside container | WARNING |
| No `HEALTHCHECK` | Missing container health monitoring | INFO |
| Too many `RUN` layers | More than 10 `RUN` commands (image bloat) | INFO |

**Rules:** 8 rules (DOCK001–DOCK008)

---

### 1.9 Dependency Vulnerability Analyzer (`--type deps`)

Scans `requirements.txt` against a built-in offline vulnerability database — **no API key, no network request**.

**Coverage:** 29 vulnerability entries across 15 packages

| Package | Vulnerable Versions | Issue |
|---------|-------------------|-------|
| Django | <2.2.28, <3.2.15, <4.1.2 | Multiple CVEs (SQL injection, XSS, CSRF bypass, auth bypass) |
| Flask | <1.0.0 | Debug mode exposure, known security issues |
| Requests | <2.20.0 | CVE-2018-18074 — credential exposure on redirect |
| urllib3 | <1.24.2 | CVE-2019-11324 — certificate verification bypass |
| cryptography | <41.0.0 | NULL pointer deref, memory corruption |
| Jinja2 | <2.11.3 | CVE-2020-28493 — ReDoS vulnerability |
| PyYAML | <5.4 | CVE-2020-14343 — arbitrary code execution |
| sqlparse | <0.4.4 | CVE-2023-30608 — ReDoS vulnerability |
| aiohttp | <3.8.5 | CVE-2023-37276 — request smuggling |
| FastAPI | <0.95.0 | Dependency confusion, known security patches |
| Werkzeug | <2.2.3 | CVE-2023-23934, CVE-2023-25577 — cookie injection, DoS |
| Paramiko | <2.10.1 | CVE-2022-24302 — private key file race condition |
| Pillow | <9.3.0 | Multiple CVEs — buffer overflow, arbitrary code exec |
| lxml | <4.9.1 | CVE-2022-2309 — NULL deref |
| Setuptools | <65.5.1 | CVE-2022-40897 — ReDoS |

Also detects **unpinned dependencies** (no version specifier) as a WARNING.

**Rules:** 3 rules (DEP001–DEP003) | Critical CVEs severity: **BLOCK**

---

### 1.10 Full Project Scan (`--type all`)

Runs all 9 analyzers in a single pass across an entire directory tree.

- Recursively discovers all relevant file types
- Deduplicates findings per file
- Produces a unified finding list with analyzer attribution
- Computes a single security score across all findings
- Generates one combined HTML, JSON, or SARIF report

```bash
contractguard analyze --type all --path . --report report.html --score
```

---

## 2. Security Scoring

Every scan produces an **A–F security grade** and a **0–100 numeric score**.

### Grade Scale

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90–100 | Production ready |
| B | 75–89 | Minor issues to address |
| C | 60–74 | Moderate risk — review before deploy |
| D | 40–59 | Significant issues — do not deploy |
| F | 0–39 | Critical failures — deployment blocked |

### Score Deductions

| Severity | Deduction per Finding |
|----------|----------------------|
| BLOCK | 20 points + automatic F |
| CRITICAL | 10 points |
| WARNING | 4 points |
| INFO | 1 point |

> Any single **BLOCK** finding forces the grade to **F** regardless of total score.

### Score Output Includes

- Letter grade (A–F)
- Numeric score (0–100)
- Finding counts per severity
- Attack surface list (unique attack vectors identified)
- Top risks summary (highest-severity findings)

---

## 3. Reporting Formats

### 3.1 HTML Report (`--report report.html`)

- Dark theme with aggressive security posture styling
- **Security grade banner** — large A–F circle with color coding (green → red)
- Attack surface section — lists all unique attack vectors found
- Top risks section — top 5 highest-severity findings
- Full findings table with: Severity badge, Rule ID, Name, File, Description, CWE, Attack Vector, Suggestion
- BLOCK severity findings pulse/animate to draw attention
- Summary statistics bar

### 3.2 JSON Report (`--report-json report.json`)

Structured machine-readable output:

```json
{
  "summary": { "total": 164, "block": 30, "critical": 130, "warning": 4, "info": 0 },
  "score": { "grade": "F", "score": 0 },
  "findings": [
    {
      "rule_id": "SEC001",
      "name": "hardcoded_secrets",
      "severity": "block",
      "file": "config/.env",
      "description": "...",
      "suggestion": "...",
      "cwe": "CWE-798",
      "attack_vector": "..."
    }
  ]
}
```

### 3.3 SARIF 2.1.0 (`--report-sarif results.sarif`)

Fully compliant [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) output for direct upload to:

- **GitHub Code Scanning** (Security tab → Code scanning alerts)
- **Azure DevOps** Security scans
- Any SARIF-compatible viewer

SARIF output includes:
- `$schema` and `version: "2.1.0"`
- `tool.driver` with all rules, CWE taxa references
- `results` with per-finding locations, message, level, and rule reference
- Physical location with `artifactLocation.uri` and `region.startLine`
- CWE taxonomy references in `taxa`

---

## 4. CLI Commands

### `analyze` — Core analysis command

```
contractguard analyze [OPTIONS]

  -t, --type    TEXT   json|sql|regex|secrets|pii|csv|config|dockerfile|deps|all
  -p, --path    PATH   File or directory to scan
  --report      PATH   Write HTML report
  --report-json PATH   Write JSON report
  --report-sarif PATH  Write SARIF 2.1.0 report
  --score              Print security grade after scan
  --record             Save scan to history database
  --ci                 Exit code 2 on critical/block findings
```

### `score` — Grade your entire project

```
contractguard score [OPTIONS]
  -p, --path PATH   Directory to scan (default: .)

Runs all 9 analyzers and displays a security grade panel.
```

### `history` — View scan trends

```
contractguard history [OPTIONS]
  --limit INT   Number of past scans to show (default: 10)
  --db    PATH  Path to history database
```

### `watch` — Continuous scanning

```
contractguard watch [OPTIONS]
  -p, --path     PATH   Directory to watch
  -t, --type     TEXT   Analyzer type (default: all)
  --interval INT        Seconds between scans (default: 30)

Re-runs the specified analyzer every N seconds. Useful during development.
```

### `serve` — Launch web UI

```
contractguard serve
Opens http://127.0.0.1:8000 — file upload UI with all 9 analyzer types.
```

### `version` — Show version

```
contractguard version
```

---

## 5. Web UI

A FastAPI-powered single-page application accessible at `http://127.0.0.1:8000`.

| Feature | Detail |
|---------|--------|
| File upload | Upload any file directly from the browser |
| Analyzer selection | Dropdown with all 9 types + "all" |
| Inline results | Findings table rendered directly on the page |
| Dark theme | Consistent with CLI and HTML reports |
| No JavaScript frameworks | Pure HTML + inline CSS, zero dependencies |
| API endpoint | `POST /analyze` — accepts `multipart/form-data` |

---

## 6. Rule Engine

The shared rule engine is the backbone of all 9 analyzers.

### Rule Structure

```yaml
- id: SEC001
  name: hardcoded_secrets
  analyzer: secrets
  severity: block           # info | warning | critical | block
  description: "Hardcoded secrets detected — credentials are exposed."
  matcher: "secret_count > 0"
  suggestion: "Use environment variables or a secrets vault."
  attack_vector: "Attacker clones repo → extracts credentials → unauthorized access"
  cwe: "CWE-798"
```

### Matcher DSL

Two expression forms are supported:

| Form | Example |
|------|---------|
| Simple comparison | `fact_name == value`, `fact_name > 0`, `fact_name != false` |
| Function call | `field_types('price') > 1`, `has_column('ssn') == true` |

Operators: `==`, `!=`, `>`, `>=`, `<`, `<=`, `contains`, `startswith`

### Rule Files

| File | Analyzer | Rules |
|------|----------|-------|
| `rules/json_rules.yaml` | json | 8 |
| `rules/sql_rules.yaml` | sql | 8 |
| `rules/regex_rules.yaml` | regex | 7 |
| `rules/secrets_rules.yaml` | secrets | 5 |
| `rules/pii_rules.yaml` | pii | 4 |
| `rules/csv_rules.yaml` | csv | 5 |
| `rules/config_rules.yaml` | config | 9 |
| `rules/dockerfile_rules.yaml` | dockerfile | 8 |
| `rules/dependency_rules.yaml` | deps | 3 |
| **Total** | | **57 rules** |

---

## 7. CI/CD Integration

### GitHub Actions

`.github/workflows/contractguard-ci.yml` runs on every push and pull request:

- Installs ContractGuard
- Runs all 9 analyzers
- Uploads HTML report as artifact
- Uploads SARIF to GitHub Code Scanning
- Fails the build on BLOCK/CRITICAL findings (`--ci` flag)

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean scan — no critical or block findings |
| `1` | Tool error (bad arguments, file not found) |
| `2` | Security findings above threshold (use with `--ci`) |

### SARIF Upload to GitHub

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

`.pre-commit-config.yaml` runs secrets detection on every commit:

```bash
pre-commit install
# Now every git commit scans staged files for secrets
```

---

## 8. Scan History & Trends

ContractGuard tracks scan results over time in a local SQLite database (`.contractguard/history.db`).

| Feature | Detail |
|---------|--------|
| Automatic storage | Use `--record` flag with any `analyze` command |
| Score tracking | Stores numeric score and grade per scan |
| Finding counts | Records block/critical/warning/info counts per scan |
| Trend analysis | Returns `improving`, `degrading`, or `stable` |
| History view | `contractguard history` — table of past scans with scores |
| Persistent | Survives across sessions — tracks project health over time |

---

## 9. Severity Model

ContractGuard uses a 4-tier severity model, stricter than most tools.

| Severity | Weight | Meaning | CI Behavior |
|----------|--------|---------|-------------|
| `info` | 1 | Best practice, low risk | Pass |
| `warning` | 3 | Should fix before production | Pass |
| `critical` | 7 | Active security/reliability risk | Fail (`--ci`) |
| `block` | 15 | Deployment must stop immediately | Fail (`--ci`) |

**BLOCK** is a custom severity above CRITICAL, reserved for findings that represent an immediate, exploitable risk:
- Hardcoded secrets (live credentials)
- SSN or credit card data in files
- Known CVSS 9.0+ CVEs in direct dependencies
- Insecure secret keys / default passwords

---

## 10. Compliance Coverage

| Regulation | Covered By |
|------------|-----------|
| **GDPR** (EU General Data Protection Regulation) | PII analyzer — email, DOB, IP, passport, IBAN |
| **CCPA** (California Consumer Privacy Act) | PII analyzer — SSN, credit cards, phone, driver's license |
| **HIPAA** (US Health Insurance Portability and Accountability Act) | PII analyzer — SSN, medical record numbers, health IDs |
| **PCI-DSS** (Payment Card Industry Data Security Standard) | PII analyzer — credit/debit card detection |
| **CWE** (Common Weakness Enumeration) | All analyzers — every rule carries a CWE ID |
| **OWASP Top 10** | SQL injection (SQL analyzer), secrets (secrets analyzer), vulnerable components (deps analyzer), security misconfiguration (config + dockerfile analyzers) |

---

## Summary Stats

| Metric | Value |
|--------|-------|
| Analyzer types | 9 |
| Total rules | 57+ |
| Secret patterns | 21 |
| PII patterns | 13 |
| Known CVE entries | 29 |
| Test coverage | 162 tests |
| Output formats | HTML, JSON, SARIF 2.1.0 |
| Offline operation | Yes — no API keys, no network |
| Python requirement | 3.11+ |
