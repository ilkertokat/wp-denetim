"""README görselleri: testlerdeki sahte "açıklı" siteden örnek rapor üretir (ağa çıkmaz)."""
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[1] / "tests")]

from fake_site import client, vulnerable_site  # noqa: E402
from rich.console import Console  # noqa: E402

from wpdenetim.render import to_console, to_html  # noqa: E402
from wpdenetim.scanner import scan  # noqa: E402

docs = Path(__file__).resolve().parents[1] / "docs"
report = scan("https://site.test", client=client(vulnerable_site), ssl_probe=lambda h, p: 9)
(docs / "ornek-rapor.html").write_text(to_html(report), encoding="utf-8")
console = Console(record=True, width=110)
to_console(report, console)
console.save_svg(str(docs / "terminal.svg"), title="wp-denetim https://site.test")
print("docs/ornek-rapor.html ve docs/terminal.svg yazıldı")
