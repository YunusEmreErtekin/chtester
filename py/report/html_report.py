"""HTML report generator — Turkish output, styled, single-file."""
from __future__ import annotations
import html
from datetime import datetime

from .. import schema

_RESULT_EMOJI = {
    schema.RESULT_ALLOWED: "&#x1F534;",   # red circle
    schema.RESULT_BLOCKED: "&#x1F7E2;",   # green circle
    schema.RESULT_PARTIAL: "&#x1F7E1;",   # yellow circle
    schema.RESULT_ERROR: "&#x26A0;",      # warning
    schema.RESULT_NOT_APPLICABLE: "&#x2796;",
}

_RESULT_TR = {
    schema.RESULT_ALLOWED: "Izin Verildi (Zayif)",
    schema.RESULT_BLOCKED: "Engellendi (Iyi)",
    schema.RESULT_PARTIAL: "Kismi",
    schema.RESULT_ERROR: "Hata",
    schema.RESULT_NOT_APPLICABLE: "Uygulanamaz",
}

_RISK_COLOR = {
    schema.RISK_CRITICAL: "#dc2626",
    schema.RISK_HIGH: "#ea580c",
    schema.RISK_MEDIUM: "#ca8a04",
    schema.RISK_LOW: "#2563eb",
    schema.RISK_INFO: "#6b7280",
}


def generate(report: schema.Report) -> str:
    allowed = sum(1 for r in report.results if r.result == schema.RESULT_ALLOWED)
    blocked = sum(1 for r in report.results if r.result == schema.RESULT_BLOCKED)
    partial = sum(1 for r in report.results if r.result == schema.RESULT_PARTIAL)
    error = sum(1 for r in report.results if r.result == schema.RESULT_ERROR)
    na = sum(1 for r in report.results if r.result == schema.RESULT_NOT_APPLICABLE)
    total = len(report.results)

    categories: dict[str, list[schema.Result]] = {}
    for r in report.results:
        categories.setdefault(r.category, []).append(r)

    rows = []
    for cat, results in sorted(categories.items()):
        rows.append(f'<tr class="cat-header"><td colspan="7"><strong>{_e(cat)}</strong></td></tr>')
        for r in results:
            emoji = _RESULT_EMOJI.get(r.result, "")
            result_text = _RESULT_TR.get(r.result, r.result)
            risk_color = _RISK_COLOR.get(r.risk_when_open, "#6b7280")
            rec_html = f'<div class="rec">{_e(r.recommendation)}</div>' if r.recommendation else ""
            poc_html = ""
            if r.poc_artifacts:
                poc_items = []
                for a in r.poc_artifacts:
                    poc_items.append(f'<a href="{_e(a.filename)}" class="poc-link">[{_e(a.artifact_type)}] {_e(a.description or a.filename)}</a>')
                poc_html = '<div class="poc">' + " | ".join(poc_items) + '</div>'
            rows.append(f"""<tr>
  <td><code>{_e(r.test_id)}</code></td>
  <td>{_e(r.name)}</td>
  <td>{emoji} {result_text}</td>
  <td style="color:{risk_color};font-weight:600">{_e(r.risk_when_open)}</td>
  <td>{r.risk_score}</td>
  <td class="evidence">{_e(r.evidence)}{rec_html}{poc_html}</td>
  <td>{_e(r.mapping.attack)}</td>
</tr>""")

    table_body = "\n".join(rows)

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>CHtester Rapor — {_e(report.hostname)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}}
h1{{color:#38bdf8;margin-bottom:4px}}
.meta{{color:#94a3b8;font-size:0.85em;margin-bottom:16px}}
.summary{{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}}
.card{{background:#1e293b;border-radius:8px;padding:12px 18px;min-width:120px;text-align:center}}
.card .num{{font-size:1.8em;font-weight:700}}
.card.red .num{{color:#ef4444}} .card.green .num{{color:#22c55e}}
.card.yellow .num{{color:#eab308}} .card.gray .num{{color:#94a3b8}}
table{{width:100%;border-collapse:collapse;font-size:0.85em;background:#1e293b;border-radius:8px;overflow:hidden}}
th{{background:#334155;color:#cbd5e1;text-align:left;padding:8px 10px;position:sticky;top:0}}
td{{padding:6px 10px;border-top:1px solid #334155;vertical-align:top}}
tr:hover td{{background:#263347}}
.cat-header td{{background:#0f172a;color:#38bdf8;font-size:0.95em;padding:10px}}
.evidence{{max-width:420px;word-break:break-word;color:#94a3b8;font-size:0.82em}}
.rec{{color:#facc15;margin-top:4px;font-size:0.9em}}
.poc{{margin-top:4px;font-size:0.8em}}
.poc-link{{color:#38bdf8;text-decoration:none;margin-right:6px}}
.poc-link:hover{{text-decoration:underline}}
code{{background:#334155;padding:2px 5px;border-radius:3px;font-size:0.9em}}
</style>
</head>
<body>
<h1>CHtester — Windows Endpoint Hardening Assessment</h1>
<div class="meta">
  Cihaz: <strong>{_e(report.hostname)}</strong> |
  Profil: {_e(report.profile)} |
  Tier: {report.tier} ({_e(report.tier_reason)}) |
  OS: {_e(report.os_build)} / {_e(report.arch)} |
  EDR: {_e(report.edr_detected)} |
  Baslangic: {_e(report.started_at)} |
  Bitis: {_e(report.finished_at)} |
  Toplam vektor: {total}
</div>
<div class="summary">
  <div class="card red"><div class="num">{allowed}</div>Izin Verildi</div>
  <div class="card green"><div class="num">{blocked}</div>Engellendi</div>
  <div class="card yellow"><div class="num">{partial}</div>Kismi</div>
  <div class="card gray"><div class="num">{error + na}</div>Hata / N/A</div>
</div>
<table>
<thead>
<tr><th>Test ID</th><th>Test</th><th>Sonuc</th><th>Risk</th><th>Skor</th><th>Kanit & Oneri</th><th>MITRE</th></tr>
</thead>
<tbody>
{table_body}
</tbody>
</table>
<div class="meta" style="margin-top:16px;text-align:center">
  Uretildi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
  Schema: {schema.SCHEMA_VERSION} | Tool: {schema.TOOL_VERSION}
</div>
</body>
</html>"""


def _e(s: str) -> str:
    return html.escape(str(s)) if s else ""
