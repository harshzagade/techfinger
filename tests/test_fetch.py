from techfinger.fetch import fetch_url
from techfinger.fingerprint import fingerprint


def test_fetch_wordpress_page(fixture_server):
    result = fetch_url(f"{fixture_server}/wordpress")
    assert result.status == 200
    assert result.error is None
    assert result.headers["server"] == "nginx/1.24.0"
    assert "WordPress 6.4.2" in result.body
    dets = fingerprint(result.headers, result.body)
    names = [d.name for d in dets]
    assert "WordPress" in names
    assert "Nginx" in names
    assert "jQuery" in names


def test_fetch_next_page(fixture_server):
    result = fetch_url(f"{fixture_server}/next")
    dets = fingerprint(result.headers, result.body)
    nxt = [d for d in dets if d.name == "Next.js"][0]
    assert nxt.confidence == 100
    assert nxt.level == "High"


def test_fetch_express_page(fixture_server):
    result = fetch_url(f"{fixture_server}/express")
    dets = fingerprint(result.headers, result.body)
    assert [d.name for d in dets] == ["Express", "Nginx", "Node.js"]


def test_fetch_django_page(fixture_server):
    result = fetch_url(f"{fixture_server}/django")
    dets = fingerprint(result.headers, result.body)
    assert [d.name for d in dets if d.name == "Django"]


def test_fetch_plain_page_detects_nothing(fixture_server):
    result = fetch_url(f"{fixture_server}/plain")
    assert result.status == 200
    assert fingerprint(result.headers, result.body) == []


def test_fetch_follows_redirect(fixture_server):
    result = fetch_url(f"{fixture_server}/redirect")
    assert result.status == 200
    assert result.final_url.endswith("/wordpress")
    assert "WordPress" in [d.name for d in
                            fingerprint(result.headers, result.body)]


def test_fetch_404_page_still_returns_body_and_headers(fixture_server):
    result = fetch_url(f"{fixture_server}/no-such-page")
    assert result.status == 404
    assert result.error is None


def test_fetch_rejects_non_http_scheme():
    result = fetch_url("ftp://example.com/file")
    assert result.status is None
    assert "only http" in result.error


def test_fetch_unreachable_host_reports_error():
    result = fetch_url("http://127.0.0.1:1/", timeout=2)
    assert result.status is None
    assert result.error is not None
