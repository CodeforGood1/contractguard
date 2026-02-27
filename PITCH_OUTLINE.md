# Slide 1: The Problem
- Secrets leak into repos — AWS keys, API tokens, database passwords committed daily
- PII sits unprotected — SSNs, credit cards, medical records exposed in data files
- Dependencies ship with known CVEs — attackers don't find zero-days, they Google yours
- Configs run debug mode in prod, disable SSL, use wildcard CORS
- Dockerfiles run as root with `:latest` tags and `curl | bash` installs
- These issues are caught too late — in staging or *in production*

# Slide 2: ContractGuard — The Solution
- "Stop bad inputs before they break your systems"
- 9 analyzers, 57+ rules, A-F security grading — one command: `--type all`
- Secrets, PII, SQL, Regex, JSON, CSV, Config, Dockerfile, Dependency scanning
- BLOCK severity = deployment must stop. Not a suggestion — an enforcement.
- No cloud, no API keys, no AI hallucinations — deterministic, offline, explainable

# Slide 3: How It Works
- CLI: `contractguard analyze --type all --path . --report report.html --score`
- 9 analyzers extract facts → YAML rule engine evaluates → HTML/SARIF report
- Each finding has CWE ID, attack vector, confidence, severity, and fix suggestion
- Security score: A-F grade based on finding severity (any BLOCK = automatic F)
- CI mode: exit code 2 on critical/block → gates your deployment pipeline
- SARIF 2.1.0 export → GitHub Code Scanning integration

# Slide 4: Live Demo (show terminal + browser)
- Full project scan: `--type all --path samples/ --score` → 164 findings, Grade F
- Secrets detection: AWS keys, GitHub tokens, DB passwords — all in a leaked .env
- Dependency CVEs: Django, Flask, cryptography — caught offline, no API needed
- SARIF export → show GitHub Security tab integration
- Web UI: upload Dockerfile → instant findings with attack vectors

# Slide 5: Architecture & Extensibility
- Modular: plug-in analyzer pattern — add new analyzers with `extract_facts()` + YAML
- Works fully offline — pip install and go, no cloud dependency, no API keys
- CI-ready: GitHub Action included, SARIF artifact upload
- FastAPI web UI for non-CLI users
- SQLite history tracking with trend analysis (improving/degrading/stable)
- VS Code extension ready: structured findings map directly to LSP Diagnostics

# Slide 6: Impact & Themes
- Cybersecurity: Secrets detection, PII scanning, dependency CVEs, Dockerfile hardening
- Developer Tooling: CLI + CI + SARIF + web UI — engineers actually use this
- Data Quality: Schema inference, CSV analysis, data contract enforcement
- Privacy & Compliance: GDPR, CCPA, HIPAA — PII detection with regulation mapping
- Business: Reduces breach risk, shifts security left, automated compliance auditing
- Open source, zero paid dependencies, runs anywhere Python runs
