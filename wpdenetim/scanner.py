"""Denetimler.

Tüm kontroller PASİFTİR: yalnızca herkese açık sayfalara GET/HEAD isteği atılır,
form gönderilmez, parola denenmez, açık istismar edilmez. Araç yalnızca sahibi
olduğunuz ya da test izniniz olan sitelerde kullanılmalıdır.
"""
from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urljoin, urlparse

import httpx

from .model import Finding, Report, Severity

USER_AGENT = "WP-Denetim/1.0 (+https://github.com/ilkertokat/wp-denetim)"

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", Severity.MEDIUM,
        "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "content-security-policy": ("Content-Security-Policy", Severity.LOW,
        "Önce Content-Security-Policy-Report-Only ile başlayıp kademeli sıkılaştırın"),
    "x-frame-options": ("X-Frame-Options", Severity.LOW,
        "X-Frame-Options: SAMEORIGIN (ya da CSP frame-ancestors)"),
    "x-content-type-options": ("X-Content-Type-Options", Severity.LOW,
        "X-Content-Type-Options: nosniff"),
    "referrer-policy": ("Referrer-Policy", Severity.INFO,
        "Referrer-Policy: strict-origin-when-cross-origin"),
    "permissions-policy": ("Permissions-Policy", Severity.INFO,
        "Permissions-Policy: camera=(), microphone=(), geolocation=()"),
}

SENSITIVE_PATHS = {
    "/.env": ("Ortam dosyası (.env) erişilebilir", Severity.HIGH, r"[A-Z_]+=."),
    "/.git/HEAD": ("Git deposu (.git) erişilebilir", Severity.HIGH, r"^ref: refs/"),
    "/wp-config.php.bak": ("wp-config yedeği erişilebilir", Severity.HIGH, r"DB_PASSWORD|DB_NAME"),
    "/wp-config.php~": ("wp-config yedeği erişilebilir", Severity.HIGH, r"DB_PASSWORD|DB_NAME"),
    "/wp-content/debug.log": ("Hata ayıklama günlüğü (debug.log) erişilebilir", Severity.MEDIUM, r"PHP (Notice|Warning|Fatal)"),
    "/phpinfo.php": ("phpinfo() sayfası açık", Severity.MEDIUM, r"PHP Version"),
}

GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', re.I)
VER_QUERY_RE = re.compile(r"(?:wp-includes|wp-admin)/[^\"'?]+\?ver=([\d.]+)")
PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9_\-]+)/[^\"'\s>]*?(?:\?ver=([\w.\-]+))?[\"'\s>]", re.I)
THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9_\-]+)/", re.I)
SERVER_VER_RE = re.compile(r"\d+\.\d+")


@dataclass
class Context:
    base: str
    client: httpx.Client
    home: httpx.Response
    report: Report

    def get(self, path: str, **kw) -> httpx.Response | None:
        try:
            return self.client.get(urljoin(self.base, path), **kw)
        except httpx.HTTPError:
            return None


Check = Callable[[Context], None]


# --- tek tek kontroller ------------------------------------------------------
def check_https(ctx: Context) -> None:
    p = urlparse(ctx.base)
    if p.scheme != "https":
        ctx.report.add(Finding("https", "Site HTTPS kullanmıyor", Severity.HIGH,
                               "Trafik şifrelenmeden taşınıyor.", "Let's Encrypt ile ücretsiz sertifika kurun."))
        return
    r = ctx.get(f"http://{p.netloc}/", follow_redirects=False)
    if r is not None and not (r.is_redirect and str(r.headers.get("location", "")).startswith("https://")):
        ctx.report.add(Finding("http-redirect", "HTTP isteği HTTPS'e yönlendirilmiyor", Severity.MEDIUM,
                               f"http://{p.netloc}/ → {r.status_code}", "Sunucuda 301 ile HTTPS yönlendirmesi ekleyin."))
    else:
        ctx.report.passed.append("HTTP → HTTPS yönlendirmesi var")


def check_headers(ctx: Context) -> None:
    h = {k.lower(): v for k, v in ctx.home.headers.items()}
    missing = []
    for key, (name, sev, fix) in SECURITY_HEADERS.items():
        if key == "strict-transport-security" and urlparse(ctx.base).scheme != "https":
            continue
        if key not in h:
            missing.append(name)
            ctx.report.add(Finding(f"header-{key}", f"{name} başlığı eksik", sev, "", fix))
    if not missing:
        ctx.report.passed.append("Tüm güvenlik başlıkları mevcut")


def check_server_disclosure(ctx: Context) -> None:
    leaks = []
    for key in ("server", "x-powered-by"):
        v = ctx.home.headers.get(key)
        if v and SERVER_VER_RE.search(v):
            leaks.append(f"{key}: {v}")
    if leaks:
        ctx.report.add(Finding("server-version", "Sunucu yazılım sürümü ifşa ediliyor", Severity.LOW,
                               "; ".join(leaks), "ServerTokens Prod / expose_php = Off ayarlarını kullanın."))


def check_wordpress(ctx: Context) -> None:
    html = ctx.home.text
    rep = ctx.report
    rep.is_wordpress = "/wp-content/" in html or "/wp-includes/" in html
    if not rep.is_wordpress:
        r = ctx.get("/wp-login.php")
        rep.is_wordpress = r is not None and r.status_code == 200 and "wp-submit" in r.text
    if not rep.is_wordpress:
        return

    m = GENERATOR_RE.search(html)
    version = m.group(1) if m else None
    if not version:
        vers = VER_QUERY_RE.findall(html)
        version = max(set(vers), key=vers.count) if vers else None
    if not version:
        r = ctx.get("/feed/")
        if r is not None and r.status_code == 200:
            fm = re.search(r"wordpress\.org/\?v=([\d.]+)", r.text)
            version = fm.group(1) if fm else None
    rep.wp_version = version
    if version:
        rep.add(Finding("wp-version", f"WordPress sürümü ifşa ediliyor ({version})", Severity.LOW,
                        "Sürüm bilgisi saldırganın bilinen açıkları hedeflemesini kolaylaştırır.",
                        "remove_action('wp_head', 'wp_generator'); ve ?ver= parametrelerini gizleyin."))

    for slug, ver in PLUGIN_RE.findall(html):
        rep.plugins.setdefault(slug.lower(), ver or None)
    tm = THEME_RE.search(html)
    rep.theme = tm.group(1) if tm else None

    readme = ctx.get("/readme.html")
    if readme is not None and readme.status_code == 200 and "WordPress" in readme.text:
        rep.add(Finding("wp-readme", "readme.html erişilebilir", Severity.LOW,
                        "WordPress kurulumu ve sürümü hakkında bilgi veriyor.", "Dosyayı silin ya da erişimi engelleyin."))


def check_user_enumeration(ctx: Context) -> None:
    if not ctx.report.is_wordpress:
        return
    users = []
    r = ctx.get("/wp-json/wp/v2/users")
    if r is not None and r.status_code == 200:
        try:
            users = [u.get("slug") for u in r.json() if isinstance(u, dict)]
        except ValueError:
            users = []
    if not users:
        r = ctx.get("/?author=1", follow_redirects=False)
        if r is not None and r.is_redirect:
            m = re.search(r"/author/([^/]+)/?", r.headers.get("location", ""))
            if m:
                users = [m.group(1)]
    if users:
        ctx.report.add(Finding("user-enum", "Kullanıcı adları listelenebiliyor", Severity.MEDIUM,
                               "Bulunan: " + ", ".join(u for u in users if u),
                               "REST API users ucunu ve ?author= yönlendirmesini kapatın; giriş denemelerini sınırlayın."))
    else:
        ctx.report.passed.append("Kullanıcı adları listelenemiyor")


def check_xmlrpc(ctx: Context) -> None:
    if not ctx.report.is_wordpress:
        return
    r = ctx.get("/xmlrpc.php")
    if r is not None and r.status_code in (200, 405) and "XML-RPC server accepts POST requests only" in r.text:
        ctx.report.add(Finding("xmlrpc", "XML-RPC açık", Severity.MEDIUM,
                               "Kaba kuvvet ve pingback kötüye kullanımına açık bir uç.",
                               "Kullanılmıyorsa sunucu ya da eklenti ile xmlrpc.php'yi kapatın."))
    else:
        ctx.report.passed.append("XML-RPC kapalı")


def check_directory_listing(ctx: Context) -> None:
    if not ctx.report.is_wordpress:
        return
    r = ctx.get("/wp-content/uploads/")
    if r is not None and r.status_code == 200 and "Index of" in r.text:
        ctx.report.add(Finding("dir-listing", "Dizin listeleme açık (/wp-content/uploads/)", Severity.MEDIUM,
                               "Yüklenen tüm dosyalar herkese listelenebiliyor.",
                               "Options -Indexes (Apache) ya da autoindex off (Nginx)."))


def check_sensitive_files(ctx: Context) -> None:
    found = 0
    for path, (title, sev, pattern) in SENSITIVE_PATHS.items():
        r = ctx.get(path, follow_redirects=False)
        if r is not None and r.status_code == 200 and re.search(pattern, r.text[:4000], re.M):
            ctx.report.add(Finding(f"file{path}", title, sev, path, "Dosyayı web kökünden kaldırın ya da erişimi engelleyin."))
            found += 1
    if not found:
        ctx.report.passed.append("Hassas dosyalar erişilemiyor")


def check_cookies(ctx: Context) -> None:
    bad = []
    for raw in ctx.home.headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0]
        low = raw.lower()
        if urlparse(ctx.base).scheme == "https" and "secure" not in low:
            bad.append(f"{name} (Secure yok)")
        if "httponly" not in low:
            bad.append(f"{name} (HttpOnly yok)")
    if bad:
        ctx.report.add(Finding("cookies", "Çerez güvenlik bayrakları eksik", Severity.LOW,
                               ", ".join(bad), "Çerezleri Secure; HttpOnly; SameSite=Lax ile gönderin."))


def ssl_days_left(host: str, port: int = 443) -> int:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        cert = t.getpeercert()
    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return (exp - datetime.now(timezone.utc)).days


def make_ssl_check(probe=ssl_days_left) -> Check:
    def check_ssl(ctx: Context) -> None:
        p = urlparse(ctx.base)
        if p.scheme != "https":
            return
        try:
            days = probe(p.hostname, p.port or 443)
        except (OSError, ssl.SSLError, ValueError, KeyError):
            return
        if days < 0:
            ctx.report.add(Finding("ssl-expired", "SSL sertifikasının süresi dolmuş", Severity.HIGH, f"{-days} gün önce"))
        elif days < 14:
            ctx.report.add(Finding("ssl-expiring", f"SSL sertifikası {days} gün içinde bitiyor", Severity.MEDIUM,
                                   "", "Otomatik yenilemeyi (certbot renew) kontrol edin."))
        else:
            ctx.report.passed.append(f"SSL sertifikası geçerli ({days} gün)")
    return check_ssl


ALL_CHECKS: list[Check] = [
    check_https, check_headers, check_server_disclosure, check_wordpress,
    check_user_enumeration, check_xmlrpc, check_directory_listing,
    check_sensitive_files, check_cookies,
]


def scan(url: str, client: httpx.Client | None = None, ssl_probe=ssl_days_left) -> Report:
    if not urlparse(url).scheme:
        url = "https://" + url
    base = url.rstrip("/") + "/"
    own = client is None
    client = client or httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=10, follow_redirects=True)
    try:
        home = client.get(base)
        report = Report(url=str(home.url))
        ctx = Context(base=str(home.url), client=client, home=home, report=report)
        for check in [*ALL_CHECKS, make_ssl_check(ssl_probe)]:
            check(ctx)
        return report
    finally:
        if own:
            client.close()
