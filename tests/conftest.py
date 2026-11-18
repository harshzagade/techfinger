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

PAGES = {
    "/wordpress": (200, {"Server": "nginx/1.24.0",
                         "Content-Type": "text/html; charset=utf-8"},
                   WORDPRESS_HTML),
    "/next": (200, {"X-Powered-By": "Next.js",
                    "Content-Type": "text/html"}, NEXT_HTML),
    "/express": (200, {"X-Powered-By": "Express",
                       "Server": "nginx/1.24.0",
                       "Content-Type": "text/html"}, EXPRESS_HTML),
    "/django": (200, {"Set-Cookie": "csrftoken=abc123; Path=/",
                      "Content-Type": "text/html"}, DJANGO_HTML),
    "/plain": (200, {"Content-Type": "text/html"}, PLAIN_HTML),
    "/redirect": (302, {"Location": "/wordpress"}, ""),
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib handler name
        status, headers, body = PAGES.get(
            self.path, (404, {"Content-Type": "text/html"}, "not found"))
        encoded = body.encode("utf-8")
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args):  # keep test output quiet
        pass


@pytest.fixture(scope="module")
def fixture_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
