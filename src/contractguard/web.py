"""ContractGuard Web UI — FastAPI single-page app for uploading and analyzing inputs."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse

from contractguard.engine import Finding
from contractguard.reporter import render_html_report

_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"

_UPLOAD_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ContractGuard</title>
<style>
  :root { --bg:#0a0e14; --surface:#11151c; --border:#1e2733; --text:#e6edf3; --muted:#7d8590; --accent:#58a6ff; --green:#3fb950; --red:#f85149; }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
  .container{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:2.5rem;max-width:560px;width:100%}
  h1{font-size:1.6rem;margin-bottom:.25rem}
  .tagline{color:var(--muted);margin-bottom:1.5rem;font-size:.9rem}
  label{display:block;margin-bottom:.4rem;font-weight:600;font-size:.85rem}
  select,input[type=file]{width:100%;padding:.6rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);margin-bottom:1rem;font-size:.9rem}
  select:focus,input:focus{outline:none;border-color:var(--accent)}
  textarea{width:100%;padding:.6rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:monospace;font-size:.85rem;resize:vertical;min-height:120px;margin-bottom:1rem}
  button{background:var(--accent);color:#fff;border:none;padding:.7rem 2rem;border-radius:6px;font-size:.95rem;cursor:pointer;font-weight:600;width:100%}
  button:hover{opacity:.9}
  .or{text-align:center;color:var(--muted);margin:.5rem 0;font-size:.8rem}
  .types{display:grid;grid-template-columns:1fr 1fr;gap:.25rem .5rem;margin-bottom:1rem}
  .types label{font-weight:400;font-size:.85rem;display:flex;align-items:center;gap:.4rem;cursor:pointer}
  .section-label{font-weight:600;font-size:.85rem;margin-bottom:.5rem;display:block}
</style>
</head>
<body>
<div class="container">
  <h1>&#128737; ContractGuard</h1>
  <p class="tagline">Stop bad inputs before they break your systems.</p>
  <form method="post" action="/analyze" enctype="multipart/form-data">
    <span class="section-label">Analyzer Type</span>
    <select name="type" id="type">
      <option value="all">All Analyzers (full scan)</option>
      <option value="json">JSON Schema Inference</option>
      <option value="sql">SQL Query Performance</option>
      <option value="regex">Regex Complexity</option>
      <option value="secrets">Secrets &amp; Credential Detection</option>
      <option value="pii">PII / Personal Data Detection</option>
      <option value="csv">CSV Data Quality</option>
      <option value="config">Config Security Audit</option>
      <option value="dockerfile">Dockerfile Security Lint</option>
      <option value="deps">Dependency Vulnerability Scan</option>
    </select>
    <label for="file">Upload File</label>
    <input type="file" name="file" id="file">
    <div class="or">&mdash; or paste content directly &mdash;</div>
    <label for="content">Paste Input</label>
    <textarea name="content" id="content" placeholder="Paste content here..."></textarea>
    <button type="submit">Analyze</button>
  </form>
</div>
</body>
</html>"""


def _resolve_rules_dir() -> Path:
    """Find rules directory (relative to package or CWD)."""
    if _RULES_DIR.exists():
        return _RULES_DIR
    cwd_rules = Path.cwd() / "rules"
    if cwd_rules.exists():
        return cwd_rules
    return _RULES_DIR


def _run_analyzer(analyzer_type: str, path: Path, rules_dir: Path) -> list[Finding]:
    """Run a single analyzer or all analyzers."""
    if analyzer_type == "all":
        from contractguard.cli import _run_all_analyzers
        return _run_all_analyzers(path, rules_dir)
    if analyzer_type == "json":
        from contractguard.analyzers.json_analyzer import analyze as fn
        return fn(path, rules_dir)
    if analyzer_type == "sql":
        from contractguard.analyzers.sql_analyzer import analyze as fn
        return fn(path, rules_dir)
    if analyzer_type == "regex":
        from contractguard.analyzers.regex_analyzer import analyze as fn
        return fn(path, rules_dir)
    if analyzer_type == "secrets":
        from contractguard.analyzers.secrets_analyzer import analyze as fn
        return fn(path, rules_dir)
    if analyzer_type == "pii":
        from contractguard.analyzers.pii_analyzer import analyze as fn
        return fn(path, rules_dir)
    if analyzer_type == "csv":
        from contractguard.analyzers.csv_analyzer import analyze as fn
        return fn(path, rules_dir)
    if analyzer_type == "config":
        from contractguard.analyzers.config_analyzer import analyze as fn
        return fn(path, rules_dir)
    if analyzer_type == "dockerfile":
        from contractguard.analyzers.dockerfile_analyzer import analyze as fn
        return fn(path, rules_dir)
    if analyzer_type == "deps":
        from contractguard.analyzers.dependency_analyzer import analyze as fn
        return fn(path, rules_dir)
    return []


def create_app() -> FastAPI:
    """Factory function for the FastAPI application."""
    app = FastAPI(title="ContractGuard", version="1.0.0")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return _UPLOAD_PAGE

    @app.post("/analyze", response_class=HTMLResponse)
    async def analyze_endpoint(
        type: str = Form(...),
        file: UploadFile | None = File(None),
        content: str = Form(""),
    ):
        rules_dir = _resolve_rules_dir()

        raw = ""
        if file and file.filename:
            raw = (await file.read()).decode("utf-8", errors="replace")
        elif content.strip():
            raw = content.strip()
        else:
            return HTMLResponse("<h2>No input provided.</h2><a href='/'>Go back</a>", status_code=400)

        suffix_map = {
            "json": ".json", "sql": ".sql", "regex": ".txt", "secrets": ".env",
            "pii": ".json", "csv": ".csv", "config": ".yaml", "dockerfile": "",
            "deps": ".txt", "all": ".txt",
        }
        suffix = suffix_map.get(type, ".txt")
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tmp:
            tmp.write(raw)
            tmp_path = Path(tmp.name)

        findings: list[Finding] = []
        try:
            findings = _run_analyzer(type, tmp_path, rules_dir)
        finally:
            tmp_path.unlink(missing_ok=True)

        source_label = file.filename if file and file.filename else "pasted input"
        html = render_html_report(findings, analyzer_type=type, source_path=source_label)
        return HTMLResponse(html)

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": "1.0.0"}

    return app
