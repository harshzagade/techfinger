"""Local fixture HTTP server serving canned pages for TechFinger tests.

No real target is ever contacted: every page is served by a threaded
http.server on 127.0.0.1 with fixed headers and bodies.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

WORDPRESS_HTML = """<!DOCTYPE html>
<html><head>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-content/themes/twentyfour/style.css">
<script src="/wp-includes/js/jquery/jquery.min.js"></script>
</head><body><p>Hello</p>
<a href="/wp-json/wp/v2/posts">posts</a>
</body></html>"""

NEXT_HTML = """<!DOCTYPE html>
<html><head><script src="/_next/static/chunks/app.js"></script></head>
<body><script id="__NEXT_DATA__" type="application/json">{}</script></body>
</html>"""

EXPRESS_HTML = "<html><body><h1>Express app</h1></body></html>"

DJANGO_HTML = """<html><body>
<form method="post"><input type="hidden" name="csrfmiddlewaretoken"
value="abc"></form></body></html>"""

PLAIN_HTML = "<html><body><p>Nothing to see here.</p></body></html>"

JQUERY_PAGE = """<html><head>
<script src="/static/jquery.min.js"></script>
<script src="https://cdn.example.com/evil.js"></script>
</head><body>jq</body></html>"""

BOOTSTRAP_PAGE = """<html><head>
<link rel="stylesheet" href="/static/bootstrap.css">
</head><body>bs</body></html>"""

BASE_PAGES = {
    "/wordpress": (200, {"Server": "nginx/1.24.0", "Content-Type": "text/html; charset=utf-8"}, WORDPRESS_HTML),
    "/next": (200, {"X-Powered-By": "Next.js", "Content-Type": "text/html"}, NEXT_HTML),
    "/express": (200, {"X-Powered-By": "Express", "Server": "nginx/1.24.0", "Content-Type": "text/html"}, EXPRESS_HTML),
    "/django": (200, {"Set-Cookie": "csrftoken=abc123; Path=/", "Content-Type": "text/html"}, DJANGO_HTML),
    "/plain": (200, {"Content-Type": "text/html"}, PLAIN_HTML),
    "/redirect": (302, {"Location": "/wordpress"}, ""),
    "/favicon.ico": (200, {"Content-Type": "image/x-icon"}, b"FAKE-FAVICON-BYTES-1234"),
    "/jquery-page": (200, {"Content-Type": "text/html"}, JQUERY_PAGE),
    "/static/jquery.min.js": (200, {"Content-Type": "application/javascript"},
                               "/*! jQuery v3.7.1 | (c) OpenJS Foundation */\nfunction jq(){}"),
    "/bootstrap-page": (200, {"Content-Type": "text/html"}, BOOTSTRAP_PAGE),
    "/static/bootstrap.css": (200, {"Content-Type": "text/css"},
                               "/*! Bootstrap v5.3.3 (https://getbootstrap.com/) */\n.btn{}"),
    "/bare-wp": (200, {"Content-Type": "text/html"}, "<html><body><p>Plain page, no markers.</p></body></html>"),
    "/bare-joomla": (200, {"Content-Type": "text/html"}, "<html><body><p>Plain page, no markers.</p></body></html>"),
}

PROBE_PAGES = {
    "/wp-json/": (200, {"Content-Type": "application/json"}, '{"name":"Test Site","routes":{"/wp/v2/posts":{}}}'),
    "/wp-login.php": (200, {"Content-Type": "text/html"}, "<html><body>WordPress login form</body></html>"),
    "/administrator/": (200, {"Content-Type": "text/html"}, "<html><body>Joomla administrator login</body></html>"),
}

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        pages = getattr(self.server, "pages", BASE_PAGES)
        status, headers, body = pages.get(
            self.path, (404, {"Content-Type": "text/html"}, "not found"))

        if isinstance(body, str):
            encoded = body.encode("utf-8")
        else:
            encoded = body

        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args):
        pass

def _run_server(pages):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.pages = pages
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    return server, url

@pytest.fixture(scope="module")
def fixture_server():
    server, url = _run_server(BASE_PAGES)
    yield url
    server.shutdown()
    server.server_close()

@pytest.fixture(scope="module")
def fixture_probe_server():
    pages = BASE_PAGES.copy()
    pages.update(PROBE_PAGES)
    server, url = _run_server(pages)
    yield url
    server.shutdown()
    server.server_close()
