import json

from fake_site import client, vulnerable_site
from typer.testing import CliRunner

from wpdenetim import cli
from wpdenetim.model import Finding, Report, Severity
from wpdenetim.render import to_html
from wpdenetim.scanner import scan


def test_score_and_grade_boundaries():
    r = Report(url="https://x.test")
    assert (r.score, r.grade) == (100, "A")
    r.add(Finding("a", "a", Severity.MEDIUM))          # 90
    assert r.grade == "A"
    r.add(Finding("b", "b", Severity.LOW))             # 86
    assert r.grade == "B"
    for i in range(5):
        r.add(Finding(f"h{i}", "h", Severity.HIGH))
    assert r.score == 0 and r.grade == "F"


def test_findings_sorted_by_severity():
    r = Report(url="x")
    r.add(Finding("l", "l", Severity.LOW))
    r.add(Finding("h", "h", Severity.HIGH))
    r.add(Finding("m", "m", Severity.MEDIUM))
    assert [f.id for f in r.sorted_findings()] == ["h", "m", "l"]


def test_html_report_escapes_and_contains_grade():
    r = Report(url="https://x.test/<script>")
    r.add(Finding("x", "<b>kötü</b>", Severity.HIGH, "detay", "düzelt"))
    out = to_html(r)
    assert "&lt;script&gt;" in out and "<script>" not in out.split("<style>")[0]
    assert "&lt;b&gt;kötü&lt;/b&gt;" in out


def test_json_roundtrip():
    r = scan("https://site.test", client=client(vulnerable_site), ssl_probe=lambda h, p: 90)
    data = json.loads(json.dumps(r.to_dict(), ensure_ascii=False))
    assert data["grade"] == r.grade and data["findings"][0]["severity"] == "Yüksek"


def test_cli_writes_reports_and_fails_on_min_grade(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda url: scan(url, client=client(vulnerable_site), ssl_probe=lambda h, p: 90))
    html, js = tmp_path / "r.html", tmp_path / "r.json"
    res = CliRunner().invoke(cli.app, ["https://site.test", "--html", str(html), "--json", str(js), "--min-grade", "B"])
    assert res.exit_code == 1
    assert html.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert json.loads(js.read_text(encoding="utf-8"))["is_wordpress"] is True
