"""Fetch a URL with the standard library and return headers + body.

Only http(s) URLs are fetched. Redirects are followed by urllib's default
handler (up to 10 hops). The body is capped so a huge download cannot fill
memory; decoding uses the charset from Content-Type, falling back to UTF-8
with replacement characters.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

DEFAULT_USER_AGENT = "TechFinger/1.0 (+https://github.com/harshzagade/techfinger)"
DEFAULT_TIMEOUT = 10
MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB is plenty for fingerprinting


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: bytes = b""
    error: str | None = None


def _decode_body(raw: bytes, content_type: str) -> str:
    charset = "utf-8"
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            charset = part.split("=", 1)[1].strip().strip("\"'")
            break
    try:
        return raw.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")


def fetch_url(url: str, timeout: int = DEFAULT_TIMEOUT,
              user_agent: str = DEFAULT_USER_AGENT) -> FetchResult:
    """GET ``url`` and return its status, headers and body text."""
    if not url.startswith(("http://", "https://")):
        return FetchResult(url, url, None, error="only http:// and https:// "
                           "URLs are supported")
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=context) as response:
            raw = response.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
            headers = {k.lower(): v for k, v in response.headers.items()}
            return FetchResult(
                url=url,
                final_url=response.geturl(),
                status=response.status,
                headers=headers,
                body=_decode_body(raw, headers.get("content-type", "")),
                raw=raw,
            )
    except urllib.error.HTTPError as exc:
        # An error page still carries fingerprintable headers/body.
        raw = exc.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
        headers = {k.lower(): v for k, v in exc.headers.items()}
        return FetchResult(
            url=url,
            final_url=exc.geturl(),
            status=exc.code,
            headers=headers,
            body=_decode_body(raw, headers.get("content-type", "")),
            raw=raw,
        )
    except (urllib.error.URLError, TimeoutError, ssl.SSLError,
            OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return FetchResult(url, url, None, error=f"fetch failed: {reason}")
