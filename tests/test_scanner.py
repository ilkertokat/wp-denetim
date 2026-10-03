from fake_site import client, hardened_site, vulnerable_site

from wpdenetim.model import Severity
from wpdenetim.scanner import scan


def ids(report):
    return {f.id for f in report.findings}


def test_vulnerable_site_findings():
    r = scan("https://site.test", client=client(vulnerable_site), ssl_probe=lambda h, p: 5)
    found = ids(r)
    assert r.is_wordpress and r.wp_version == "6.4.2"
    for expected in ["http-redirect", "header-strict-transport-security", "server-version", "wp-version",
                     "wp-readme", "user-enum", "xmlrpc", "dir-listing", "file/.env",
                     "file/wp-content/debug.log", "cookies", "ssl-expiring"]:
        assert expected in found, expected
    assert r.grade == "F"


def test_plugin_and_theme_inventory():
    r = scan("https://site.test", client=client(vulnerable_site), ssl_probe=lambda h, p: 90)
    assert r.plugins == {"contact-form-7": "5.8.4", "elementor": "3.18.0"}
    assert r.theme == "astra"


def test_user_enum_lists_usernames():
    r = scan("https://site.test", client=client(vulnerable_site), ssl_probe=lambda h, p: 90)
    f = next(f for f in r.findings if f.id == "user-enum")
    assert "admin" in f.detail and "editor" in f.detail and f.severity == Severity.MEDIUM


def test_hardened_site_scores_a():
    r = scan("https://site.test", client=client(hardened_site), ssl_probe=lambda h, p: 120)
    assert r.is_wordpress and r.wp_version is None
    assert r.findings == []
    assert r.grade == "A" and r.score == 100
    assert "XML-RPC kapalı" in r.passed and "Kullanıcı adları listelenemiyor" in r.passed


def test_expired_certificate_is_high():
    r = scan("https://site.test", client=client(hardened_site), ssl_probe=lambda h, p: -2)
    f = next(f for f in r.findings if f.id == "ssl-expired")
    assert f.severity == Severity.HIGH


def test_url_without_scheme_defaults_to_https():
    r = scan("site.test", client=client(hardened_site), ssl_probe=lambda h, p: 120)
    assert r.url.startswith("https://")


def test_non_wordpress_site_skips_wp_checks():
    import httpx
    def plain(req):
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://site.test/"})
        return httpx.Response(200 if req.url.path == "/" else 404, text="<html>düz site</html>")
    r = scan("https://site.test", client=client(plain), ssl_probe=lambda h, p: 120)
    assert not r.is_wordpress
    assert not ids(r) & {"user-enum", "xmlrpc", "wp-version", "dir-listing"}
