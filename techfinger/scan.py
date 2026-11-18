"""Orchestrated scanning: page fetch plus favicon, asset and path surfaces.

The favicon hash is TechFinger's own SHA-256-based fingerprint (first 16
hex chars). It is NOT Wappalyzer's MurmurHash and is not compatible with
published Wappalyzer favicon hashes; it exists so custom rules can match
favicons a user has hashed with this tool.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from .fetch import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, fetch_url
from .fingerprint import Detection, fingerprint
from .rules import RULES, Technology

_ICON_RE = re.compile(
    r'<link[^>]*?rel\s*=\s*["\'](?:[^"\']*?\s+)?icon(?:\s+[^"\']*?)?["\'][^>]*?href\s*=\s*["\']([^"\']+)["\']'
    r'|<link[^>]*?href\s*=\s*["\']([^"\']+)["\'][^>]*?rel\s*=\s*["\'](?:[^"\']*?\s+)?icon(?:\s+[^"\']*?)?["\']',
    re.IGNORECASE)
_SCRIPT_RE = re.compile(r'<script\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_CSS_RE = re.compile(
    r'<link[^>]*?rel\s*=\s*["\']stylesheet["\'][^>]*?href\s*=\s*["\']([^"\']+)["\']'
    r'|<link[^>]*?href\s*=\s*["\']([^"\']+)["\'][^>]*?rel\s*=\s*["\']stylesheet["\']',
    re.IGNORECASE)


@dataclass
class ScanResult:
    url: str
    final_url: str
    status: int | None
    headers: dict[str, str]
    body: str
    error: str | None
    favicon_hash: str | None = None
    asset_urls: list[str] = field(default_factory=list)
    probes: dict[str, tuple[int | None, str]] = field(default_factory=dict)
    detections: list[Detection] = field(default_factory=list)


def favicon_hash(raw: bytes) -> str:
    """Return the first 16 hex chars of SHA-256. This is NOT MurmurHash."""
    return hashlib.sha256(raw).hexdigest()[:16]


def _is_same_origin(base_url: str, target_url: str) -> bool:
    b = urlparse(base_url)
    t = urlparse(target_url)
    if not t.netloc:
        return True
    return (b.scheme, b.netloc) == (t.scheme, t.netloc)


def scan_url(url: str, technologies: list[Technology] | None = None,
             timeout: int = DEFAULT_TIMEOUT,
             user_agent: str = DEFAULT_USER_AGENT,
             enable_favicon: bool = True,
             enable_assets: bool = True,
             enable_paths: bool = True) -> ScanResult:
    """Deep scan a URL for technologies using all available surfaces."""
    res = fetch_url(url, timeout=timeout, user_agent=user_agent)
    if res.error and not res.status:
        return ScanResult(url, res.final_url, None, {}, "", res.error)

    final_url = res.final_url
    parsed_final = urlparse(final_url)
    origin = f"{parsed_final.scheme}://{parsed_final.netloc}"

    fav_hash: str | None = None
    if enable_favicon:
        fav_candidates = []
        for m in _ICON_RE.finditer(res.body):
            href = m.group(1) or m.group(2)
            abs_url = urljoin(final_url, href)
            if _is_same_origin(final_url, abs_url):
                fav_candidates.append(abs_url)
        fav_candidates.append(urljoin(origin + "/", "favicon.ico"))

        for fav_url in fav_candidates:
            fres = fetch_url(fav_url, timeout=timeout, user_agent=user_agent)
            if fres.status == 200 and fres.raw:
                fav_hash = favicon_hash(fres.raw[:262144])  # 256 KiB cap
                break

    asset_urls: list[str] = []
    extra_surfaces: dict[str, list[str]] = {}
    if enable_assets:
        js_urls = list(dict.fromkeys(
            urljoin(final_url, src) for src in _SCRIPT_RE.findall(res.body)))
        css_urls = list(dict.fromkeys(
            urljoin(final_url, m.group(1) or m.group(2))
            for m in _CSS_RE.finditer(res.body)))

        for kind, urls in [("js", js_urls), ("css", css_urls)]:
            bodies = []
            count = 0
            for a_url in urls:
                if count >= 5:
                    break
                if _is_same_origin(final_url, a_url):
                    ares = fetch_url(a_url, timeout=timeout, user_agent=user_agent)
                    if ares.status == 200:
                        asset_urls.append(a_url)
                        bodies.append(ares.raw[:131072].decode("utf-8", errors="replace"))
                        count += 1
            if bodies:
                extra_surfaces[kind] = bodies

    probes: dict[str, tuple[int | None, str]] = {}
    if enable_paths:
        target_techs = technologies if technologies is not None else RULES
        paths = []
        for tech in target_techs:
            for rule in tech.rules:
                p = getattr(rule, "path", None)
                if rule.kind == "path" and p and p not in paths:
                    paths.append(p)

        path_results = []
        for path in paths[:10]:
            probe_url = urljoin(origin, path)
            pres = fetch_url(probe_url, timeout=timeout, user_agent=user_agent)
            snippet = pres.body[:2000]
            probes[path] = (pres.status, snippet)
            path_results.append(f"{path} {pres.status or 0} {snippet}")
        if path_results:
            extra_surfaces["path"] = path_results

    if fav_hash:
        extra_surfaces["favicon"] = [fav_hash]

    detections = fingerprint(res.headers, res.body,
                             technologies=technologies,
                             extra_surfaces=extra_surfaces)

    return ScanResult(
        url=url,
        final_url=final_url,
        status=res.status,
        headers=res.headers,
        body=res.body,
        error=res.error,
        favicon_hash=fav_hash,
        asset_urls=asset_urls,
        probes=probes,
        detections=detections
    )
