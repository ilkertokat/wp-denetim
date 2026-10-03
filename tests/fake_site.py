"""Testler için ağa çıkmayan sahte WordPress siteleri (httpx.MockTransport)."""
import httpx

HOME_HTML = """<html><head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel='stylesheet' href='https://site.test/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2' />
<link rel='stylesheet' href='https://site.test/wp-content/themes/astra/style.css?ver=4.1' />
<script src='https://site.test/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.4'></script>
<script src='https://site.test/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.18.0'></script>
</head><body>Merhaba</body></html>"""

HARDENED_HTML = """<html><head>
<link rel='stylesheet' href='https://site.test/wp-content/themes/ozel-tema/style.css' />
</head><body>Merhaba</body></html>"""


def vulnerable_site(request: httpx.Request) -> httpx.Response:
    path, q = request.url.path, request.url.query.decode()
    if request.url.scheme == "http":
        return httpx.Response(200, text="http sürümü")  # HTTPS'e yönlendirmiyor
    if path == "/" and q == "author=1":
        return httpx.Response(301, headers={"location": "https://site.test/author/admin/"})
    routes = {
        "/": lambda: httpx.Response(200, text=HOME_HTML, headers=[
            ("server", "Apache/2.4.41 (Ubuntu)"), ("x-powered-by", "PHP/7.4.3"),
            ("set-cookie", "oturum=abc; path=/")]),
        "/readme.html": lambda: httpx.Response(200, text="<h1>WordPress</h1>"),
        "/wp-json/wp/v2/users": lambda: httpx.Response(200, json=[{"slug": "admin"}, {"slug": "editor"}]),
        "/xmlrpc.php": lambda: httpx.Response(405, text="XML-RPC server accepts POST requests only."),
        "/wp-content/uploads/": lambda: httpx.Response(200, text="<title>Index of /wp-content/uploads</title>"),
        "/.env": lambda: httpx.Response(200, text="DB_PASSWORD=gizli\nAPP_KEY=x"),
        "/wp-content/debug.log": lambda: httpx.Response(200, text="PHP Warning: Undefined variable"),
    }
    return routes.get(path, lambda: httpx.Response(404, text="yok"))()


def hardened_site(request: httpx.Request) -> httpx.Response:
    if request.url.scheme == "http":
        return httpx.Response(301, headers={"location": "https://site.test/"})
    if request.url.path == "/":
        return httpx.Response(200, text=HARDENED_HTML, headers=[
            ("server", "nginx"),
            ("strict-transport-security", "max-age=31536000"),
            ("content-security-policy", "default-src 'self'"),
            ("x-frame-options", "SAMEORIGIN"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
            ("permissions-policy", "camera=()"),
            ("set-cookie", "oturum=abc; Secure; HttpOnly; SameSite=Lax"),
        ])
    if request.url.path == "/xmlrpc.php":
        return httpx.Response(403, text="Forbidden")
    return httpx.Response(404, text="yok")


def client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
