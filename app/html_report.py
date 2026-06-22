import html
from pathlib import Path

from app.models import ScanResult, SEVERITY_ORDER

SEVERITY_LABELS = {
    "kritik": "Kritik",
    "yuqori": "Yuqori",
    "o'rta": "O'rta",
    "past": "Past",
    "ma'lumot": "Ma'lumot",
}

CSS_PATH = Path(__file__).parent / "static" / "style.css"


def _risk_class(score: float) -> str:
    if score >= 80:
        return "risk-critical"
    if score >= 60:
        return "risk-high"
    if score >= 40:
        return "risk-medium"
    if score >= 20:
        return "risk-low"
    return "risk-minimal"


def generate_html(result: ScanResult) -> str:
    css = CSS_PATH.read_text(encoding="utf-8")
    data = result

    summary_html = ""
    summary_counts = {s.value: 0 for s in SEVERITY_ORDER}
    for f in data.findings:
        summary_counts[f.severity.value] += 1

    for sev in SEVERITY_ORDER:
        count = summary_counts[sev.value]
        summary_html += f"""
        <div class="summary-item sev-{sev.value}">
          <div class="summary-count">{count}</div>
          <div class="summary-label">{SEVERITY_LABELS[sev.value]}</div>
        </div>"""

    findings_html = ""
    if not data.findings:
        findings_html = '<p style="color: var(--text-muted)">Zaiflik topilmadi.</p>'
    else:
        for f in data.findings:
            label = SEVERITY_LABELS.get(f.severity.value, f.severity.value)
            rec = ""
            if f.recommendation:
                rec = f'<div class="finding-rec">💡 {html.escape(f.recommendation)}</div>'
            findings_html += f"""
        <div class="finding-card sev-{f.severity.value}">
          <div class="finding-header">
            <span class="finding-title">{html.escape(f.title)}</span>
            <span class="badge badge-{f.severity.value}">{label}</span>
          </div>
          <p class="finding-desc">{html.escape(f.description)}</p>
          <div class="finding-meta">Kategoriya: {html.escape(f.category)}</div>
          {rec}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="uz">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Zaiflik Skaneri — {html.escape(data.domain)}</title>
  <style>{css}</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <h1>Zaiflik Skaneri</h1>
      </div>
      <p class="subtitle">Hisobot: {html.escape(data.domain)}</p>
    </header>

    <div class="results">
      <div class="risk-card {_risk_class(data.risk_score)}">
        <div class="risk-score">
          <span class="score-value">{data.risk_score}</span>
          <span class="score-label">Xavf balli</span>
        </div>
        <div class="risk-info">
          <h2>{html.escape(data.risk_level)}</h2>
          <p>{html.escape(data.domain)} → {html.escape(data.url)}</p>
          <p class="scan-time">Tekshiruv vaqti: {data.scan_duration_ms / 1000:.1f}s</p>
        </div>
      </div>

      <div class="summary-grid">{summary_html}</div>

      <div class="findings-section">
        <h3>Topilgan zaifliklar</h3>
        <div id="findingsList">{findings_html}</div>
      </div>
    </div>
  </div>
</body>
</html>"""
