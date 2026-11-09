"""Komut satırı arayüzü.

    wp-denetim https://ornek.com --html rapor.html --json rapor.json
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from . import __version__
from .render import to_console, to_html
from .scanner import scan

app = typer.Typer(add_completion=False, help="WordPress siteleri için pasif güvenlik denetimi.")
console = Console()

GRADES = "ABCDF"


def _check_grade(value: Optional[str]) -> Optional[str]:
    """--min-grade'i tarama başlamadan doğrular; geçersizse kullanım hatası (çıkış kodu 2)."""
    if value is None:
        return None
    grade = value.strip().upper()
    if len(grade) != 1 or grade not in GRADES:
        raise typer.BadParameter(f"A, B, C, D ya da F olmalı (verilen: {value!r})")
    return grade


@app.command()
def main(
    url: str = typer.Argument(..., help="Denetlenecek site (yalnızca sahibi olduğunuz ya da izniniz olan siteler)"),
    html: Optional[Path] = typer.Option(None, "--html", help="HTML raporu yaz"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="JSON raporu yaz"),
    min_grade: Optional[str] = typer.Option(None, "--min-grade", callback=_check_grade,
        help="Not bundan kötüyse çıkış kodu 1 olur (CI için, ör. --min-grade B)"),
    version: bool = typer.Option(False, "--version", help="Sürümü göster"),
) -> None:
    if version:
        console.print(f"wp-denetim {__version__}")
        raise typer.Exit()
    with console.status(f"{url} taranıyor…"):
        report = scan(url)
    to_console(report, console)
    if html:
        html.write_text(to_html(report), encoding="utf-8")
        console.print(f"\nHTML rapor: [bold]{html}[/]")
    if json_out:
        json_out.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"JSON rapor: [bold]{json_out}[/]")
    if min_grade and GRADES.index(report.grade) > GRADES.index(min_grade):
        raise typer.Exit(code=1)


def run() -> None:
    app()


if __name__ == "__main__":
    run()
