"""HTML report generation for integrity events."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from fim.models import IntegrityEvent, ScanStats, Severity

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)

_SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#16a34a",
}

_SEVERITY_BG = {
    Severity.CRITICAL: "#fef2f2",
    Severity.HIGH: "#fff7ed",
    Severity.MEDIUM: "#fffbeb",
    Severity.LOW: "#f0fdf4",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
}


def _escape(value: object | None) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _short_hash(value: str | None) -> str:
    if not value:
        return "—"
    return (value[:10] + "…") if len(value) > 10 else value


def _format_timestamp(timestamp: str | None) -> str:
    if not timestamp:
        return "—"
    return timestamp[:19].replace("T", " ")


def _svg_donut(counts: dict[str, int], total: int) -> str:
    if total == 0:
        return (
            '<svg viewBox="0 0 120 120" width="120" height="120">'
            '<circle cx="60" cy="60" r="50" fill="none" stroke="#e5e7eb" stroke-width="18"/>'
            '<text x="60" y="65" text-anchor="middle" font-size="13" fill="#9ca3af">None</text>'
            "</svg>"
        )

    radius, center = 50, 60
    circumference = 2 * 3.14159 * radius
    offset = 0.0
    circles = ""

    for severity in reversed(_SEVERITY_ORDER):
        count = counts.get(severity, 0)
        if count == 0:
            continue
        dash = (count / total) * circumference
        color = _SEVERITY_COLORS[severity]
        circles += (
            f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" '
            f'stroke="{color}" stroke-width="18" '
            f'stroke-dasharray="{dash:.2f} {circumference:.2f}" '
            f'stroke-dashoffset="-{offset:.2f}" '
            f'transform="rotate(-90 {center} {center})"/>'
        )
        offset += dash

    return (
        f'<svg viewBox="0 0 120 120" width="120" height="120">'
        f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" '
        f'stroke="#f3f4f6" stroke-width="18"/>'
        f"{circles}"
        f'<text x="{center}" y="{center - 6}" text-anchor="middle" font-size="20" '
        f'font-weight="bold" fill="#1e293b">{total}</text>'
        f'<text x="{center}" y="{center + 14}" text-anchor="middle" font-size="10" '
        f'fill="#6b7280">events</text>'
        f"</svg>"
    )


def build_html_report(
    events: list[IntegrityEvent],
    *,
    title: str = "FIM Scan Report",
    generated_at: str | None = None,
    stats: ScanStats | None = None,
) -> str:
    """Build a standalone HTML document styled like the FIM dashboard template."""
    now_str = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = {level: sum(1 for event in events if event.severity == level) for level in _SEVERITY_ORDER}
    total = len(events)

    cards_html = ""
    for severity in _SEVERITY_ORDER:
        count = counts[severity]
        color = _SEVERITY_COLORS[severity]
        background = _SEVERITY_BG[severity]
        label = _SEVERITY_ICONS[severity]
        cards_html += (
            f'<div class="card" style="border-left:4px solid {color};background:{background}">'
            f'<div class="card-count" style="color:{color}">{count}</div>'
            f'<div class="card-label">{_escape(label)}</div>'
            f"</div>"
        )

    rows_html = ""
    for event in events:
        color = _SEVERITY_COLORS.get(event.severity, "#6b7280")
        row_bg = _SEVERITY_BG.get(event.severity, "#ffffff")
        badge = f'<span class="badge" style="background:{color}">{_escape(event.severity)}</span>'
        rows_html += (
            f'<tr style="background:{row_bg}20">'
            f"<td class='mono small'>{_escape(_format_timestamp(event.timestamp))}</td>"
            f"<td>{badge}</td>"
            f"<td class='mono'>{_escape(event.event_type)}</td>"
            f"<td class='path'>{_escape(event.path)}</td>"
            f"<td class='small'>{_escape(event.description or '—')}</td>"
            f"<td class='mono small'>{_escape(_short_hash(event.old_hash))}</td>"
            f"<td class='mono small'>{_escape(_short_hash(event.new_hash))}</td>"
            "</tr>"
        )

    if not rows_html:
        rows_html = (
            '<tr><td colspan="7" class="empty">'
            "No integrity events recorded."
            "</td></tr>"
        )

    scan_meta = ""
    if stats is not None:
        scan_meta = (
            f" &nbsp;|&nbsp; Files scanned: {stats.files_scanned}"
            f" &nbsp;|&nbsp; New alerts: {stats.new_alerts_saved}"
            f" &nbsp;|&nbsp; Duration: {stats.duration_seconds:.2f} s"
        )

    donut = _svg_donut(counts, total)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_escape(title)} — {_escape(now_str)}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #f1f5f9; color: #0f172a; }}
    header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
      color: #fff; padding: 28px 40px; display: flex; align-items: center; gap: 16px;
    }}
    header .logo {{ font-size: 2em; }}
    header h1   {{ font-size: 1.4em; font-weight: 700; }}
    header p    {{ font-size: .85em; opacity: .7; margin-top: 4px; }}
    main {{ padding: 32px 40px; max-width: 1400px; margin: 0 auto; }}
    .summary {{ display: flex; gap: 20px; align-items: center; margin-bottom: 28px; flex-wrap: wrap; }}
    .cards   {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; flex: 1; min-width: 280px; }}
    .card    {{ padding: 16px 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
    .card-count {{ font-size: 2.2em; font-weight: 800; line-height: 1; }}
    .card-label {{ font-size: .85em; font-weight: 600; color: #475569; margin-top: 4px; }}
    .table-wrap {{ background: #fff; border-radius: 10px; box-shadow: 0 1px 4px rgba(0,0,0,.1); overflow: hidden; }}
    .table-header {{
      display: flex; justify-content: space-between; align-items: center;
      padding: 16px 20px; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; gap: 12px;
    }}
    .table-header h2 {{ font-size: 1em; font-weight: 700; }}
    #search {{
      padding: 6px 12px; border: 1px solid #e2e8f0; border-radius: 6px;
      font-size: .875em; width: 220px;
    }}
    #search:focus {{ border-color: #3b82f6; outline: none; }}
    table  {{ width: 100%; border-collapse: collapse; font-size: .875em; }}
    thead  {{ background: #1e293b; color: #fff; position: sticky; top: 0; }}
    th     {{ padding: 11px 14px; text-align: left; font-weight: 600;
               font-size: .8em; text-transform: uppercase; letter-spacing: .06em;
               cursor: pointer; user-select: none; }}
    th:hover {{ background: #334155; }}
    td {{ padding: 10px 14px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #f8fafc !important; }}
    .badge {{ display: inline-block; padding: 2px 9px; border-radius: 4px;
              color: #fff; font-size: .75em; font-weight: 700; }}
    .mono  {{ font-family: ui-monospace, 'JetBrains Mono', monospace; }}
    .small {{ font-size: .82em; color: #475569; }}
    .path  {{ word-break: break-all; font-size: .82em; font-family: monospace; }}
    .empty {{ text-align: center; padding: 48px; color: #94a3b8; font-size: 1.1em; }}
    footer {{ text-align: center; color: #94a3b8; font-size: .8em; padding: 24px; }}
    @media (max-width: 900px) {{
      .cards {{ grid-template-columns: repeat(2, 1fr); }}
      main, header {{ padding-left: 20px; padding-right: 20px; }}
    }}
  </style>
</head>
<body>
<header>
  <div class="logo">🛡️</div>
  <div>
    <h1>{_escape(title)}</h1>
    <p>Generated: {_escape(now_str)} &nbsp;|&nbsp; Total events: {total}{scan_meta}</p>
  </div>
</header>
<main>
  <div class="summary">
    <div>{donut}</div>
    <div class="cards">{cards_html}</div>
  </div>
  <div class="table-wrap">
    <div class="table-header">
      <h2>Events ({total})</h2>
      <input id="search" type="text" placeholder="Filter by path or type…"
             oninput="filterTable(this.value)">
    </div>
    <table id="tbl">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Time ↕</th>
          <th onclick="sortTable(1)">Severity ↕</th>
          <th onclick="sortTable(2)">Type ↕</th>
          <th>Path</th>
          <th>Description</th>
          <th>Old hash</th>
          <th>New hash</th>
        </tr>
      </thead>
      <tbody id="tbody">{rows_html}</tbody>
    </table>
  </div>
</main>
<footer>File Integrity Monitor</footer>
<script>
  const sevOrder = {{CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3}};
  let sortDir = {{}};
  function filterTable(q) {{
    q = q.toLowerCase();
    document.querySelectorAll('#tbody tr').forEach(tr => {{
      tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
    }});
  }}
  function sortTable(col) {{
    const tbody = document.getElementById('tbody');
    const rows = [...tbody.querySelectorAll('tr')];
    sortDir[col] = !sortDir[col];
    rows.sort((a, b) => {{
      let va = a.cells[col]?.textContent.trim() || '';
      let vb = b.cells[col]?.textContent.trim() || '';
      if (col === 1) {{
        va = sevOrder[va] ?? 9; vb = sevOrder[vb] ?? 9;
        return sortDir[col] ? va - vb : vb - va;
      }}
      return sortDir[col] ? va.localeCompare(vb) : vb.localeCompare(va);
    }});
    rows.forEach(r => tbody.appendChild(r));
  }}
</script>
</body>
</html>
"""


def export_html(
    events: list[IntegrityEvent],
    output_path: str,
    *,
    title: str = "FIM Scan Report",
    stats: ScanStats | None = None,
) -> Path:
    """Write events to a standalone HTML file and return the output path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    document = build_html_report(events, title=title, stats=stats)
    out.write_text(document, encoding="utf-8")
    return out.resolve()
