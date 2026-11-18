"""Offline technology rule set.

Each technology is a list of rules. A rule matches one surface of a page:

- ``header``: matched against ``name: value`` lines of the response headers
  (header names lower-cased, match is case-insensitive).
- ``html``: matched against the response body.
- ``script``: matched against every ``<script src="...">`` URL in the body.
- ``meta``: matched against ``name=content`` strings built from the page's
  ``<meta>`` tags (e.g. ``generator=WordPress 6.4.2``).
- ``cookie``: matched against the ``Set-Cookie`` header values.

``weight`` is the score a matched rule contributes (0-100 scale, capped).
Strong identifiers (a generator meta tag, ``X-Powered-By: Express``) score
60; characteristic paths score 40; weak hints score 20-25.

``version_group`` names the regex group holding the version string, when the
rule can capture one (e.g. ``WordPress 6.4.2``). The first matched rule with
a captured version wins.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

VALID_KINDS = ("header", "html", "script", "meta", "cookie")


@dataclass
class Rule:
    kind: str
    pattern: str
    weight: int
    description: str
    version_group: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in VALID_KINDS:
            raise ValueError(f"unknown rule kind: {self.kind!r}")
        if not 0 < self.weight <= 100:
            raise ValueError(f"rule weight must be 1-100, got {self.weight}")
        re.compile(self.pattern)  # fail fast on a bad regex


@dataclass
class Technology:
    name: str
    category: str
    rules: list[Rule] = field(default_factory=list)


def _r(kind: str, pattern: str, weight: int, description: str,
       version_group: int | None = None) -> Rule:
    return Rule(kind, pattern, weight, description, version_group)


# ---------------------------------------------------------------------------
# The offline rule set
# ---------------------------------------------------------------------------

RULES: list[Technology] = [
    Technology("WordPress", "CMS", [
        _r("meta", r"^generator=WordPress(?:\s+([\d.]+))?", 60,
           "generator meta tag", 1),
        _r("html", r"/wp-content/", 40, "wp-content path in page"),
        _r("html", r"/wp-includes/", 40, "wp-includes path in page"),
        _r("script", r"wp-includes/", 40, "script from wp-includes"),
        _r("html", r"wp-json", 25, "wp-json API reference"),
    ]),
    Technology("Drupal", "CMS", [
        _r("meta", r"^generator=Drupal(?:\s+([\d.]+))?", 60,
           "generator meta tag", 1),
        _r("header", r"^x-generator:\s*Drupal", 60, "X-Generator header"),
        _r("header", r"^x-drupal-cache:", 40, "X-Drupal-Cache header"),
        _r("html", r"Drupal\.settings", 40, "Drupal.settings in JS"),
        _r("html", r"/sites/(?:default|all)/files/", 25, "Drupal files path"),
    ]),
    Technology("Joomla", "CMS", [
        _r("meta", r"^generator=Joomla!?(?:\s+([\d.]+))?", 60,
           "generator meta tag", 1),
        _r("html", r"/media/jui/", 40, "Joomla media/jui path"),
        _r("html", r"Joomla!", 25, "Joomla! string in page"),
    ]),
    Technology("Ghost", "CMS", [
        _r("meta", r"^generator=Ghost(?:\s+([\d.]+))?", 60,
           "generator meta tag", 1),
        _r("html", r"/ghost/api/", 40, "Ghost content API reference"),
    ]),
    Technology("Shopify", "CMS", [
        _r("header", r"^x-shopid:", 60, "X-ShopId header"),
        _r("html", r"cdn\.shopify\.com", 40, "Shopify CDN reference"),
        _r("html", r"Shopify\.theme", 40, "Shopify.theme in JS"),
        _r("script", r"cdn\.shopify\.com", 40, "script from Shopify CDN"),
    ]),
    Technology("Wix", "CMS", [
        _r("meta", r"^generator=Wix\.com", 60, "generator meta tag"),
        _r("html", r"wix\.com", 40, "wix.com reference in page"),
        _r("header", r"^x-wix-request-id:", 60, "X-Wix-Request-Id header"),
    ]),
    Technology("Squarespace", "CMS", [
        _r("html", r"static\.squarespace\.com", 40, "Squarespace static host"),
        _r("html", r"Squarespace", 25, "Squarespace string in page"),
    ]),
    Technology("Magento", "CMS", [
        _r("html", r"Magento", 25, "Magento string in page"),
        _r("cookie", r"mage-cache", 40, "mage-cache cookie"),
        _r("header", r"^x-magento-", 40, "X-Magento-* header"),
    ]),
    Technology("Django", "Framework", [
        _r("cookie", r"csrftoken=", 40, "csrftoken cookie"),
        _r("html", r"csrfmiddlewaretoken", 40, "csrfmiddlewaretoken field"),
    ]),
    Technology("Flask", "Framework", [
        _r("header", r"^server:\s*Werkzeug", 60, "Werkzeug server header"),
    ]),
    Technology("Laravel", "Framework", [
        _r("cookie", r"laravel_session=", 60, "laravel_session cookie"),
        _r("cookie", r"XSRF-TOKEN=", 40, "XSRF-TOKEN cookie"),
        _r("html", r"laravel", 20, "laravel string in page"),
    ]),
    Technology("Ruby on Rails", "Framework", [
        _r("header", r"^x-runtime:", 40, "X-Runtime header"),
        _r("html", r"csrf-param", 25, "csrf-param meta tag"),
        _r("cookie", r"_.*_session=", 25, "Rails session cookie"),
    ]),
    Technology("Express", "Framework", [
        _r("header", r"^x-powered-by:\s*Express", 60, "X-Powered-By header"),
    ]),
    Technology("Next.js", "Framework", [
        _r("html", r"__NEXT_DATA__", 60, "__NEXT_DATA__ in page"),
        _r("html", r"/_next/static/", 40, "_next/static asset path"),
        _r("header", r"^x-powered-by:\s*Next\.js", 60, "X-Powered-By header"),
    ]),
    Technology("Nuxt", "Framework", [
        _r("html", r"__NUXT__", 60, "__NUXT__ in page"),
        _r("html", r"/_nuxt/", 40, "_nuxt asset path"),
    ]),
    Technology("Angular", "Framework", [
        _r("html", r"ng-version=\"([^\"]+)\"", 60, "ng-version attribute", 1),
        _r("html", r"ng-app", 40, "ng-app attribute"),
        _r("html", r"angular\.js", 25, "angular.js script reference"),
    ]),
    Technology("Vue.js", "Framework", [
        _r("html", r'data-v-[0-9a-f]{8}', 40, "scoped data-v-* attribute"),
        _r("html", r"__VUE__", 40, "__VUE__ in page"),
        _r("script", r"vue(\.min)?\.js", 40, "vue.js script"),
    ]),
    Technology("React", "Framework", [
        _r("html", r"data-reactroot", 40, "data-reactroot attribute"),
        _r("html", r"__REACT", 25, "__REACT marker"),
        _r("script", r"react-dom", 40, "react-dom script"),
        _r("html", r"react\.js", 25, "react.js script reference"),
    ]),
    Technology("Svelte", "Framework", [
        _r("html", r"svelte-[a-z0-9]{6,}", 40, "svelte-* class hash"),
    ]),
    Technology("ASP.NET", "Framework", [
        _r("header", r"^x-aspnet-version:\s*([\d.]+)", 60,
           "X-AspNet-Version header", 1),
        _r("header", r"^x-powered-by:\s*ASP\.NET", 60, "X-Powered-By header"),
        _r("cookie", r"ASP\.NET_SessionId=", 40, "ASP.NET_SessionId cookie"),
    ]),
    Technology("Spring", "Framework", [
        _r("header", r"^x-application-context:", 40,
           "X-Application-Context header"),
        _r("cookie", r"JSESSIONID=", 25, "JSESSIONID cookie"),
    ]),
    Technology("PHP", "Language", [
        _r("header", r"^x-powered-by:\s*PHP(?:/([\d.]+))?", 60,
           "X-Powered-By header", 1),
        _r("html", r"\.php", 20, ".php extension in page"),
    ]),
    Technology("Node.js", "Language", [
        _r("header", r"^x-powered-by:\s*Express", 60,
           "X-Powered-By: Express implies Node.js"),
    ]),
    Technology("jQuery", "JavaScript library", [
        _r("script", r"jquery(\.min)?\.js", 40, "jquery script"),
        _r("html", r"jQuery\(", 25, "jQuery( call in page"),
    ]),
    Technology("Bootstrap", "CSS framework", [
        _r("html", r"bootstrap(\.min)?\.(css|js)", 40, "bootstrap asset"),
        _r("html", r"bootstrap", 20, "bootstrap string in page"),
    ]),
    Technology("Tailwind CSS", "CSS framework", [
        _r("script", r"cdn\.tailwindcss\.com", 60, "Tailwind Play CDN script"),
        _r("html", r"tailwind", 20, "tailwind string in page"),
    ]),
    Technology("Nginx", "Web server", [
        _r("header", r"^server:\s*nginx(?:/([\d.]+))?", 60,
           "Server header", 1),
    ]),
    Technology("Apache", "Web server", [
        _r("header", r"^server:\s*Apache(?:/([\d.]+))?", 60,
           "Server header", 1),
    ]),
    Technology("Microsoft IIS", "Web server", [
        _r("header", r"^server:\s*Microsoft-IIS(?:/([\d.]+))?", 60,
           "Server header", 1),
    ]),
    Technology("LiteSpeed", "Web server", [
        _r("header", r"^server:\s*LiteSpeed", 60, "Server header"),
    ]),
    Technology("Caddy", "Web server", [
        _r("header", r"^server:\s*Caddy", 60, "Server header"),
    ]),
    Technology("Gunicorn", "Web server", [
        _r("header", r"^server:\s*gunicorn", 60, "Server header"),
    ]),
    Technology("Cloudflare", "CDN", [
        _r("header", r"^server:\s*cloudflare", 60, "Server header"),
        _r("header", r"^cf-ray:", 60, "CF-Ray header"),
        _r("cookie", r"__cf_bm=", 40, "__cf_bm cookie"),
    ]),
    Technology("CloudFront", "CDN", [
        _r("header", r"^x-amz-cf-id:", 60, "X-Amz-Cf-Id header"),
        _r("header", r"cloudfront", 40, "cloudfront in Via header"),
    ]),
    Technology("Fastly", "CDN", [
        _r("header", r"^x-served-by:.*fastly", 40, "X-Served-By Fastly"),
        _r("header", r"fastly", 40, "fastly in Via header"),
    ]),
    Technology("Akamai", "CDN", [
        _r("header", r"^server:\s*AkamaiGHost", 60, "Server header"),
    ]),
    Technology("Varnish", "CDN", [
        _r("header", r"^x-varnish:", 60, "X-Varnish header"),
        _r("header", r"varnish", 40, "varnish in Via header"),
    ]),
    Technology("Google Analytics", "Analytics", [
        _r("html", r"googletagmanager\.com/gtag/js", 60, "gtag.js loader"),
        _r("html", r"google-analytics\.com/analytics\.js", 60,
           "analytics.js loader"),
        _r("html", r"gtag\(", 25, "gtag( call in page"),
    ]),
    Technology("Google Tag Manager", "Analytics", [
        _r("html", r"googletagmanager\.com/gtm\.js", 60, "gtm.js loader"),
    ]),
    Technology("Hotjar", "Analytics", [
        _r("html", r"static\.hotjar\.com", 60, "Hotjar static host"),
    ]),
    Technology("reCAPTCHA", "Security", [
        _r("html", r"google\.com/recaptcha", 60, "reCAPTCHA script"),
    ]),
    Technology("hCaptcha", "Security", [
        _r("html", r"hcaptcha\.com", 60, "hCaptcha script"),
    ]),
]


def list_technologies() -> list[tuple[str, str]]:
    """Return (name, category) for every built-in technology, sorted."""
    return sorted((t.name, t.category) for t in RULES)


def load_rules_file(path: str) -> list[Technology]:
    """Load extra/override rules from a JSON file.

    Format::

        {"technologies": [{"name": "WordPress", "category": "CMS",
          "rules": [{"kind": "html", "pattern": "...", "weight": 40,
                     "description": "...", "version_group": 1}]}]}

    Technologies with a name already in the built-in set replace it;
    new names are added. Raises ValueError on malformed input.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise ValueError(f"cannot read rules file {path!r}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"rules file {path!r} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("technologies"), list):
        raise ValueError("rules file must be an object with a "
                         "'technologies' list")
    loaded: list[Technology] = []
    for entry in data["technologies"]:
        if not isinstance(entry, dict) or "name" not in entry \
                or "category" not in entry or "rules" not in entry:
            raise ValueError("each technology needs name, category and rules")
        try:
            rules = [Rule(r["kind"], r["pattern"], r["weight"],
                          r.get("description", r["pattern"]),
                          r.get("version_group"))
                     for r in entry["rules"]]
        except KeyError as exc:
            raise ValueError(f"rule in {entry['name']!r} missing {exc}") from exc
        except (TypeError, ValueError, re.error) as exc:
            raise ValueError(f"bad rule in {entry['name']!r}: {exc}") from exc
        loaded.append(Technology(entry["name"], entry["category"], rules))
    return loaded


def merged_rules(extra_path: str | None) -> list[Technology]:
    """Built-in rules plus any overrides/additions from a JSON file."""
    if not extra_path:
        return RULES
    merged = {t.name: t for t in RULES}
    for tech in load_rules_file(extra_path):
        merged[tech.name] = tech
    return list(merged.values())
