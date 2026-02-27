"""HTML, JSON, & SARIF report generation.

Produces:
- Self-contained HTML report with security grade, attack vectors, dark aggressive theme
- SARIF 2.1.0 output for GitHub Code Scanning integration
"""

from __future__ import annotations

import datetime
from typing import Any

from jinja2 import Environment, BaseLoader

from contractguard.engine import Finding, Severity
from contractguard.scorer import SecurityScore, compute_score

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ContractGuard Security Report</title>
<style>
  :root {
    --bg: #0a0e14; --surface: #11151c; --surface2: #161b24; --border: #1e2733;
    --text: #e6edf3; --muted: #7d8590;
    --red: #f85149; --bright-red: #ff4444; --yellow: #d29922; --blue: #58a6ff;
    --green: #3fb950; --purple: #bc8cff; --orange: #f0883e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 2rem; margin-bottom: .25rem; }
  .tagline { color: var(--muted); margin-bottom: 1rem; font-size: .95rem; }
  .meta { color: var(--muted); font-size: .85rem; margin-bottom: 1.5rem; }

  /* Grade banner */
  .grade-banner { display: flex; align-items: center; gap: 2rem; padding: 1.5rem 2rem;
    background: var(--surface); border: 2px solid var(--border); border-radius: 12px;
    margin-bottom: 2rem; }
  .grade-circle { width: 80px; height: 80px; border-radius: 50%; display: flex;
    align-items: center; justify-content: center; font-size: 2.5rem; font-weight: 800;
    border: 3px solid; }
  .grade-A { border-color: var(--green); color: var(--green); }
  .grade-B { border-color: var(--green); color: var(--green); }
  .grade-C { border-color: var(--yellow); color: var(--yellow); }
  .grade-D { border-color: var(--orange); color: var(--orange); }
  .grade-F { border-color: var(--bright-red); color: var(--bright-red); background: rgba(255,68,68,.08); }
  .grade-details { flex: 1; }
  .grade-details .score { font-size: 1.3rem; font-weight: 700; }
  .grade-details .risk { font-size: .9rem; margin-top: .25rem; }

  .summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
          padding: 1rem 1.5rem; min-width: 120px; text-align: center; }
  .card .num { font-size: 2rem; font-weight: 700; }
  .card.block .num { color: var(--bright-red); text-shadow: 0 0 10px rgba(255,68,68,.4); }
  .card.critical .num { color: var(--red); }
  .card.warning .num { color: var(--yellow); }
  .card.info .num { color: var(--blue); }
  .card.total .num { color: var(--text); }
  .card .label { color: var(--muted); font-size: .8rem; text-transform: uppercase; }

  /* Attack surface */
  .attack-surface { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 1.25rem; margin-bottom: 2rem; }
  .attack-surface h3 { color: var(--orange); font-size: .9rem; text-transform: uppercase; margin-bottom: .75rem; }
  .attack-tag { display: inline-block; background: rgba(240,136,62,.1); color: var(--orange);
    border: 1px solid rgba(240,136,62,.3); padding: 3px 10px; border-radius: 12px;
    font-size: .8rem; margin: 3px 4px 3px 0; }
  .top-risks { margin-top: .75rem; }
  .top-risks li { color: var(--red); font-size: .85rem; margin-left: 1.5rem; margin-top: .25rem; }

  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }
  th { background: var(--surface2); text-align: left; padding: .75rem 1rem; font-size: .75rem;
       text-transform: uppercase; color: var(--muted); border-bottom: 1px solid var(--border); }
  td { padding: .75rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; font-size: .85rem; }
  tr:last-child td { border-bottom: none; }
  .sev { font-weight: 700; text-transform: uppercase; font-size: .7rem; padding: 2px 8px;
         border-radius: 4px; display: inline-block; }
  .sev.block { background: rgba(255,68,68,.2); color: var(--bright-red); animation: pulse 2s infinite; }
  .sev.critical { background: rgba(248,81,73,.15); color: var(--red); }
  .sev.warning  { background: rgba(210,153,34,.15); color: var(--yellow); }
  .sev.info     { background: rgba(88,166,255,.15); color: var(--blue); }
  @keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:.7 } }
  .context { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .75rem;
             background: var(--bg); padding: 4px 8px; border-radius: 4px; display: inline-block;
             max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .suggestion { color: var(--green); font-size: .8rem; }
  .attack-col { color: var(--orange); font-size: .8rem; }
  .cwe { font-family: monospace; color: var(--purple); font-size: .75rem; }
  .no-issues { text-align: center; padding: 3rem; color: var(--green); font-size: 1.2rem; }
  footer { margin-top: 2rem; text-align: center; color: var(--muted); font-size: .75rem; }
</style>
</head>
<body>
<div class="container">
  <h1>&#128737; ContractGuard Security Report</h1>
  <p class="tagline">Stop bad inputs before they break your systems.</p>
  <p class="meta">Analyzer: <strong>{{ analyzer_type }}</strong> &nbsp;|&nbsp;
     Source: <strong>{{ source_path }}</strong> &nbsp;|&nbsp;
     Generated: {{ timestamp }}</p>

  <!-- Grade Banner -->
  <div class="grade-banner">
    <div class="grade-circle grade-{{ grade }}">{{ grade }}</div>
    <div class="grade-details">
      <div class="score">Security Score: {{ score_value }}/100</div>
      <div class="risk">{{ risk_summary }}</div>
    </div>
  </div>

  <div class="summary">
    <div class="card total"><div class="num">{{ total }}</div><div class="label">Total</div></div>
    <div class="card block"><div class="num">{{ block }}</div><div class="label">&#128683; Block</div></div>
    <div class="card critical"><div class="num">{{ critical }}</div><div class="label">Critical</div></div>
    <div class="card warning"><div class="num">{{ warning }}</div><div class="label">Warning</div></div>
    <div class="card info"><div class="num">{{ info }}</div><div class="label">Info</div></div>
  </div>

  {% if attack_surface %}
  <div class="attack-surface">
    <h3>&#9888;&#65039; Attack Surface Identified</h3>
    {% for a in attack_surface %}<span class="attack-tag">{{ a }}</span>{% endfor %}
    {% if top_risks %}
    <ul class="top-risks">
      {% for r in top_risks %}<li>{{ r }}</li>{% endfor %}
    </ul>
    {% endif %}
  </div>
  {% endif %}

  {% if findings %}
  <table>
    <thead>
      <tr><th>ID</th><th>Severity</th><th>CWE</th><th>Description</th><th>Location</th><th>Attack Vector</th><th>Suggestion</th></tr>
    </thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td><strong>{{ f.rule_id }}</strong></td>
        <td><span class="sev {{ f.severity.value }}">{{ f.severity.value }}</span></td>
        <td class="cwe">{{ f.cwe }}</td>
        <td>{{ f.description }}</td>
        <td>{{ f.location }}<br><span class="context" title="{{ f.context | e }}">{{ f.context | truncate(60) }}</span></td>
        <td class="attack-col">{{ f.attack_vector | truncate(80) }}</td>
        <td class="suggestion">{{ f.suggestion }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="no-issues">&#9989; All clear — no issues found.</div>
  {% endif %}

  <footer>ContractGuard v1.0.0 &mdash; Built for DevPost Season of Code</footer>
</div>
</body>
</html>"""


def render_html_report(
    findings: list[Finding],
    analyzer_type: str = "",
    source_path: str = "",
) -> str:
    """Render findings to a self-contained HTML report with security grade."""
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(_HTML_TEMPLATE)

    score_obj = compute_score(findings)

    block = sum(1 for f in findings if f.severity == Severity.BLOCK)
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    warning = sum(1 for f in findings if f.severity == Severity.WARNING)
    info = sum(1 for f in findings if f.severity == Severity.INFO)

    return template.render(
        findings=findings,
        analyzer_type=analyzer_type,
        source_path=source_path,
        timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        total=len(findings),
        block=block,
        critical=critical,
        warning=warning,
        info=info,
        grade=score_obj.grade,
        score_value=score_obj.score,
        risk_summary=score_obj.risk_summary,
        attack_surface=score_obj.attack_surface,
        top_risks=score_obj.top_risks,
    )


def render_sarif_report(
    findings: list[Finding],
    analyzer_type: str = "",
) -> dict[str, Any]:
    """Render findings as SARIF 2.1.0 for GitHub Code Scanning integration."""
    severity_map = {
        Severity.INFO: "note",
        Severity.WARNING: "warning",
        Severity.CRITICAL: "error",
        Severity.BLOCK: "error",
    }

    rules: list[dict] = []
    results: list[dict] = []
    seen_rule_ids: set[str] = set()

    for f in findings:
        if f.rule_id not in seen_rule_ids:
            seen_rule_ids.add(f.rule_id)
            rule_def: dict[str, Any] = {
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": severity_map.get(f.severity, "warning"),
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-', '')}.html" if f.cwe else "",
            }
            if f.attack_vector:
                rule_def["fullDescription"] = {"text": f"Attack vector: {f.attack_vector}"}
            rules.append(rule_def)

        file_path = f.location.split(":")[0] if f.location else ""
        line = 1
        if ":" in f.location:
            parts = f.location.rsplit(":", 1)
            try:
                line = int(parts[1])
            except ValueError:
                pass

        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": severity_map.get(f.severity, "warning"),
            "message": {"text": f"{f.description} — {f.suggestion}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path.replace("\\", "/")},
                    "region": {"startLine": line},
                }
            }],
        }
        if f.cwe:
            result["taxa"] = [{"id": f.cwe, "toolComponent": {"name": "CWE"}}]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ContractGuard",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/contractguard",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
