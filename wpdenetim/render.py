"""Raporu terminale (rich) ve bağımsız bir HTML dosyasına yazar."""
from __future__ import annotations

import html
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .model import Report, Severity

COLORS = {Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "white"}
GRADE_COLORS = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}


def to_console(report: Report, console: Console | None = None) -> None:
    c = console or Console()
    color = GRADE_COLORS[report.grade]
    wp = f"WordPress {report.wp_version or '(sürüm gizli)'}" if report.is_wordpress else "WordPress tespit edilmedi"
    c.print(Panel.fit(f"[bold]{report.url}[/]\n{wp}\nNot: [bold {color}]{report.grade}[/]  ·  Puan: {report.score}/100",
                      title="WP Denetim", border_style=color))
    if report.findings:
        t = Table(show_lines=False, header_style="bold")
        t.add_column("Önem", width=8)
        t.add_column("Bulgu")
        t.add_column("Öneri", style="dim")
        for f in report.sorted_findings():
            t.add_row(f"[{COLORS[f.severity]}]{f.severity.label}[/]",
                      f.title + (f"\n[dim]{f.detail}[/]" if f.detail else ""), f.fix)
        c.print(t)
    for p in report.passed:
        c.print(f"[green]✓[/] {p}")
    if report.plugins:
        c.print("\n[bold]Tespit edilen eklentiler:[/] " +
                ", ".join(f"{k}{' ' + v if v else ''}" for k, v in sorted(report.plugins.items())))


def to_html(report: Report) -> str:
    e = html.escape
    color = GRADE_COLORS[report.grade]
    sev_color = {"Yüksek": "#dc2626", "Orta": "#d97706", "Düşük": "#0891b2", "Bilgi": "#64748b"}
    rows = "".join(
        f'<tr><td><span class="sev" style="background:{sev_color[f.severity.label]}">{f.severity.label}</span></td>'
        f"<td><b>{e(f.title)}</b><div class=d>{e(f.detail)}</div></td><td class=fix>{e(f.fix)}</td></tr>"
        for f in report.sorted_findings())
    passed = "".join(f"<li>{e(p)}</li>" for p in report.passed)
    plugins = "".join(f"<span class=chip>{e(k)}{' · ' + e(v) if v else ''}</span>" for k, v in sorted(report.plugins.items()))
    wp = f"WordPress {e(report.wp_version or 'sürümü gizli')}" if report.is_wordpress else "WordPress tespit edilmedi"
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP Denetim — {e(report.url)}</title><style>
body{{font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;background:#f6f7f9;color:#14171c;margin:0}}
.w{{max-width:960px;margin:0 auto;padding:36px 20px}}
.top{{display:flex;gap:24px;align-items:center;background:#fff;border:1px solid #e6e8ec;border-radius:16px;padding:24px}}
.g{{width:92px;height:92px;border-radius:20px;display:grid;place-items:center;color:#fff;font:800 48px system-ui;background:{color}}}
h1{{font-size:22px;margin:0 0 4px}} .m{{color:#6b7380}}
.bar{{height:8px;background:#e6e8ec;border-radius:9px;margin-top:10px;overflow:hidden}}.bar i{{display:block;height:100%;width:{report.score}%;background:{color}}}
h2{{font-size:16px;margin:30px 0 12px}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e6e8ec;border-radius:14px;overflow:hidden}}
td{{padding:14px 16px;border-top:1px solid #eef0f3;vertical-align:top}} tr:first-child td{{border-top:0}}
.sev{{color:#fff;font-size:12px;font-weight:700;padding:3px 9px;border-radius:99px;white-space:nowrap}}
.d{{color:#6b7380;font-size:13px;margin-top:2px;word-break:break-all}} .fix{{color:#374151;font-size:13.5px;width:38%}}
ul{{background:#fff;border:1px solid #e6e8ec;border-radius:14px;padding:14px 18px 14px 38px;margin:0}} li{{margin:4px 0;color:#166534}}
.chip{{display:inline-block;background:#fff;border:1px solid #e6e8ec;border-radius:8px;padding:4px 10px;margin:0 6px 6px 0;font-size:13px}}
footer{{color:#6b7380;font-size:12.5px;margin-top:30px}}
</style></head><body><div class="w">
<div class="top"><div class="g">{report.grade}</div><div style="flex:1"><h1>{e(report.url)}</h1>
<div class="m">{wp}{' · tema: ' + e(report.theme) if report.theme else ''} · {len(report.findings)} bulgu · puan {report.score}/100</div>
<div class="bar"><i></i></div></div></div>
<h2>Bulgular</h2>{'<table>' + rows + '</table>' if rows else '<p class="m">Bulgu yok 🎉</p>'}
<h2>Geçen kontroller</h2><ul>{passed or '<li>—</li>'}</ul>
<h2>Tespit edilen eklentiler</h2><div>{plugins or '<span class="m">Tespit edilmedi</span>'}</div>
<footer>WP Denetim ile {datetime.now():%d.%m.%Y %H:%M} tarihinde oluşturuldu. Pasif tarama: yalnızca herkese açık sayfalar okundu.</footer>
</div></body></html>"""
