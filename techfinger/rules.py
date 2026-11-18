"""Offline technology rule set.

Each technology is a list of rules. A rule matches one surface of a page:

- ``header``: matched against ``name: value`` lines of the response headers
  (header names lower-cased, match is case-insensitive).
- ``html``: matched against the response body.
- ``script``: matched against every ``<script src="...">`` URL in the body.
- ``meta``: matched against ``name=content`` strings built from the page's
  ``<meta>`` tags (e.g. ``generator=WordPress 6.4.2``).
- ``cookie``: matched against the ``Set-Cookie`` header values.
- ``favicon``: matches the SHA-256-based favicon hash string.
- ``js`` / ``css``: match fetched same-origin script/stylesheet file contents.
- ``path``: matches strings of the form "{path} {status} {body snippet}"
  from known-path probes (requires the ``path`` field).

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

VALID_KINDS = ("header", "html", "script", "meta", "cookie", "favicon", "js", "css", "path")


@dataclass
class Rule:
    kind: str
    pattern: str
    weight: int
    description: str
    version_group: int | None = None
    path: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in VALID_KINDS:
            raise ValueError(f"unknown rule kind: {self.kind!r}")
        if self.kind == "path" and self.path is None:
            raise ValueError("kind 'path' requires a path")
        if self.kind != "path" and self.path is not None:
            raise ValueError(f"kind {self.kind!r} cannot have a path")
        if not 0 < self.weight <= 100:
            raise ValueError(f"rule weight must be 1-100, got {self.weight}")
        re.compile(self.pattern)  # fail fast on a bad regex


@dataclass
class Technology:
    name: str
    category: str
    rules: list[Rule] = field(default_factory=list)


def _r(kind: str, pattern: str, weight: int, description: str,
       version_group: int | None = None, path: str | None = None) -> Rule:
    return Rule(kind, pattern, weight, description, version_group, path)


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
        _r("path", r" 200 .*wp/v2", 40, "wp-json API responds", None, path="/wp-json/"),
        _r("path", r" 200 .*WordPress", 40, "wp-login.php page", None, path="/wp-login.php"),
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
        _r("path", r" 200 .*Joomla", 40, "administrator login page", None, path="/administrator/"),
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
        _r("js", r"jQuery(?: JavaScript Library)? v([\d.]+)", 60, "jQuery version banner in JS file", 1),
    ]),
    Technology("Bootstrap", "CSS framework", [
        _r("html", r"bootstrap(\.min)?\.(css|js)", 40, "bootstrap asset"),
        _r("html", r"bootstrap", 20, "bootstrap string in page"),
        _r("css", r"Bootstrap v([\d.]+)", 60, "Bootstrap version banner in CSS file", 1),
        _r("js", r"Bootstrap v([\d.]+)", 60, "Bootstrap version banner in JS file", 1),
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
    Technology("PrestaShop", "E-commerce", [
        _r("meta", r"^generator=PrestaShop", 60, "generator meta tag"),
        _r("cookie", r"PrestaShop-", 40, "PrestaShop cookie"),
        _r("html", r"PrestaShop", 20, "PrestaShop mention"),
    ]),
    Technology("OpenCart", "E-commerce", [
        _r("cookie", r"OCSESSID", 60, "OpenCart session cookie"),
        _r("html", r"index\.php\?route=common/home", 40, "OpenCart internal route pattern"),
    ]),
    Technology("WooCommerce", "E-commerce", [
        _r("script", r"woocommerce\.min\.js", 60, "WooCommerce script"),
        _r("html", r"class=\"[^\"]*woocommerce-", 40, "WooCommerce CSS classes"),
        _r("meta", r"^generator=WooCommerce\s+([\d.]+)", 60, "WooCommerce generator tag", 1),
    ]),
    Technology("BigCommerce", "E-commerce", [
        _r("script", r"cdn11\.bigcommerce\.com", 60, "BigCommerce CDN reference"),
        _r("html", r"var\s+BC_CONFIG", 60, "BigCommerce JS global"),
    ]),
    Technology("TYPO3", "CMS", [
        _r("meta", r"^generator=TYPO3\s+CMS", 60, "TYPO3 generator tag"),
        _r("header", r"^x-typo3-generated:", 60, "X-TYPO3-Generated header"),
        _r("html", r"typo3conf/ext/", 40, "TYPO3 extension path"),
    ]),
    Technology("Concrete CMS", "CMS", [
        _r("meta", r"^generator=concrete5\s+-\s+([\d.]+)", 60, "Concrete5 generator tag", 1),
        _r("meta", r"^generator=Concrete\s+CMS\s+-\s+([\d.]+)", 60, "Concrete CMS generator tag", 1),
        _r("script", r"concrete/js/", 40, "Concrete CMS JS directory"),
    ]),
    Technology("Grav", "CMS", [
        _r("meta", r"^generator=GravCMS", 60, "Grav generator tag"),
        _r("header", r"^x-powered-by:\s*Grav", 60, "X-Powered-By Grav header"),
    ]),
    Technology("Hugo", "CMS", [
        _r("meta", r"^generator=Hugo\s+([\d.]+)", 60, "Hugo generator tag", 1),
        _r("html", r"Hugo\s+([\d.]+)", 40, "Hugo version in comments", 1),
    ]),
    Technology("Jekyll", "CMS", [
        _r("meta", r"^generator=Jekyll\s+v([\d.]+)", 60, "Jekyll generator tag", 1),
    ]),
    Technology("Gatsby", "CMS", [
        _r("meta", r"^generator=Gatsby\s+([\d.]+)", 60, "Gatsby generator tag", 1),
        _r("html", r"id=\"___gatsby\"", 60, "Gatsby root element"),
    ]),
    Technology("Craft CMS", "CMS", [
        _r("cookie", r"CraftSessionId", 60, "Craft CMS session cookie"),
        _r("header", r"^x-powered-by:\s*Craft\s+CMS", 60, "X-Powered-By Craft header"),
    ]),
    Technology("Umbraco", "CMS", [
        _r("header", r"^x-umbraco-version:", 60, "X-Umbraco-Version header"),
        _r("cookie", r"UMB_UCONTEXT", 60, "Umbraco auth cookie"),
    ]),
    Technology("Sitecore", "CMS", [
        _r("cookie", r"SC_ANALYTICS_GLOBAL_COOKIE", 60, "Sitecore analytics cookie"),
        _r("html", r"__SC_VARS", 60, "Sitecore JS variables"),
    ]),
    Technology("Adobe Experience Manager", "CMS", [
        _r("html", r"/etc/clientlibs/", 60, "AEM clientlibs path"),
        _r("html", r"/content/dam/", 40, "AEM digital asset manager path"),
    ]),
    Technology("Liferay", "CMS", [
        _r("header", r"^liferay-portal:", 60, "Liferay-Portal header"),
        _r("html", r"Liferay\.Browser", 40, "Liferay JS object"),
    ]),
    Technology("Kentico", "CMS", [
        _r("meta", r"^generator=Kentico\s+([\d.]+)", 60, "Kentico generator tag", 1),
        _r("cookie", r"CMSPreferredCulture", 40, "Kentico culture cookie"),
    ]),
    Technology("MODX", "CMS", [
        _r("html", r"MODX_CONFIG_URL", 60, "MODX configuration JS"),
        _r("header", r"^x-powered-by:\s*MODX", 60, "X-Powered-By MODX header"),
    ]),
    Technology("Statamic", "CMS", [
        _r("meta", r"^generator=Statamic", 60, "Statamic generator tag"),
        _r("header", r"^x-statamic-cache:", 40, "Statamic cache header"),
    ]),
    Technology("Kirby", "CMS", [
        _r("header", r"^x-kirby-version:", 60, "X-Kirby-Version header"),
    ]),
    Technology("ProcessWire", "CMS", [
        _r("cookie", r"wire", 60, "ProcessWire session cookie"),
        _r("html", r"ProcessWire", 20, "ProcessWire mention"),
    ]),
    Technology("Symfony", "Framework", [
        _r("cookie", r"symfony", 60, "Symfony session cookie"),
        _r("header", r"^x-debug-token:", 40, "Symfony debug token header"),
    ]),
    Technology("CodeIgniter", "Framework", [
        _r("cookie", r"ci_session", 60, "CodeIgniter session cookie"),
    ]),
    Technology("CakePHP", "Framework", [
        _r("cookie", r"cakephp", 60, "CakePHP session cookie"),
    ]),
    Technology("Laminas", "Framework", [
        _r("header", r"^x-powered-by:\s*Laminas", 60, "X-Powered-By Laminas header"),
    ]),
    Technology("FastAPI", "Framework", [
        _r("header", r"^server:\s*uvicorn", 60, "Uvicorn server header (FastAPI)"),
    ]),
    Technology("Gin", "Framework", [
        _r("header", r"^x-gin-version:", 60, "X-Gin-Version header"),
    ]),
    Technology("Play Framework", "Framework", [
        _r("cookie", r"PLAY_SESSION", 60, "Play Framework session cookie"),
    ]),
    Technology("Grails", "Framework", [
        _r("header", r"^x-grails-version:", 60, "X-Grails-Version header"),
    ]),
    Technology("Blazor", "Framework", [
        _r("script", r"_framework/blazor\.(?:server|webassembly)\.js", 60, "Blazor runtime script"),
        _r("html", r"<!--\s*Blazor:", 60, "Blazor marker comment"),
    ]),
    Technology("Vaadin", "Framework", [
        _r("script", r"vaadinBootstrap\.js", 60, "Vaadin bootstrap script"),
        _r("html", r"vaadin-", 40, "Vaadin components"),
    ]),
    Technology("JavaServer Faces", "Framework", [
        _r("cookie", r"javax\.faces\.ViewState", 60, "JSF ViewState cookie"),
        _r("html", r"javax\.faces\.ViewState", 60, "JSF ViewState hidden input"),
    ]),
    Technology("Apache Struts", "Framework", [
        _r("html", r"\.action", 40, "Struts action extension"),
        _r("cookie", r"JSESSIONID", 20, "Generic Java session cookie"),
    ]),
    Technology("Apache Tomcat", "Web server", [
        _r("header", r"^server:\s*Apache-Coyote/([\d.]+)", 60, "Apache-Coyote server header", 1),
    ]),
    Technology("Jetty", "Web server", [
        _r("header", r"^server:\s*jetty\(([\d.]+)\)", 60, "Jetty server header", 1),
    ]),
    Technology("WildFly", "Web server", [
        _r("header", r"^x-powered-by:\s*WildFly/([\d.]+)", 60, "X-Powered-By WildFly header", 1),
    ]),
    Technology("Oracle WebLogic", "Web server", [
        _r("header", r"^x-powered-by:\s*WebLogic", 60, "X-Powered-By WebLogic header"),
    ]),
    Technology("Kestrel", "Web server", [
        _r("header", r"^server:\s*Kestrel", 60, "Kestrel server header"),
    ]),
    Technology("OpenResty", "Web server", [
        _r("header", r"^server:\s*openresty/([\d.]+)", 60, "OpenResty server header", 1),
    ]),
    Technology("Phusion Passenger", "Web server", [
        _r("header", r"^x-powered-by:\s*Phusion\s+Passenger(?:\s+([\d.]+))?", 60, "X-Powered-By Passenger header", 1),
    ]),
    Technology("Puma", "Web server", [
        _r("header", r"^server:\s*puma\s+([\d.]+)", 60, "Puma server header", 1),
    ]),
    Technology("Unicorn", "Web server", [
        _r("header", r"^server:\s*unicorn", 60, "Unicorn server header"),
    ]),
    Technology("Tornado", "Web server", [
        _r("header", r"^server:\s*TornadoServer/([\d.]+)", 60, "Tornado server header", 1),
    ]),
    Technology("uWSGI", "Web server", [
        _r("header", r"^server:\s*uWSGI", 60, "uWSGI server header"),
    ]),
    Technology("Netlify", "Hosting", [
        _r("header", r"^server:\s*Netlify", 60, "Netlify server header"),
        _r("header", r"^x-nf-request-id:", 60, "Netlify request ID header"),
    ]),
    Technology("Vercel", "Hosting", [
        _r("header", r"^server:\s*Vercel", 60, "Vercel server header"),
        _r("header", r"^x-vercel-id:", 60, "Vercel ID header"),
    ]),
    Technology("Heroku", "Hosting", [
        _r("header", r"^via:\s*[\d.]+\s+vegur", 60, "Heroku proxy header (Vegur)"),
    ]),
    Technology("GitHub Pages", "Hosting", [
        _r("header", r"^server:\s*GitHub\.com", 60, "GitHub Pages server header"),
        _r("header", r"^x-github-request-id:", 60, "GitHub request ID header"),
    ]),
    Technology("Firebase Hosting", "Hosting", [
        _r("header", r"^x-firebase-host:", 60, "Firebase host header"),
    ]),
    Technology("Render", "Hosting", [
        _r("header", r"^server:\s*Render", 60, "Render server header"),
    ]),
    Technology("Fly.io", "Hosting", [
        _r("header", r"^server:\s*Fly\.io", 60, "Fly.io server header"),
        _r("header", r"^fly-request-id:", 60, "Fly.io request ID header"),
    ]),
    Technology("AWS Elastic Load Balancing", "Hosting", [
        _r("cookie", r"AWSELB", 60, "AWS ELB cookie"),
        _r("header", r"^server:\s*awselb/([\d.]+)", 60, "AWS ELB server header", 1),
    ]),
    Technology("Azure Front Door", "Hosting", [
        _r("header", r"^x-azure-ref:", 60, "Azure Front Door ref header"),
    ]),
    Technology("Discourse", "CMS", [
        _r("header", r"^x-discourse-route:", 60, "X-Discourse-Route header"),
        _r("meta", r"^generator=Discourse", 60, "Discourse generator tag"),
    ]),
    Technology("phpMyAdmin", "Database", [
        _r("path", r" 200 .*phpMyAdmin", 60, "phpMyAdmin detected at path", None, path="/phpmyadmin/"),
    ]),
    Technology("Roundcube", "CMS", [
        _r("path", r" 200 .*Roundcube\s+Webmail", 60, "Roundcube detected at path", None, path="/roundcube/"),
    ]),
Technology("Lodash", "JavaScript library", [
    _r("script", r"lodash(?:\.min)?\.js", 60, "Lodash script filename"),
    _r("js", r"/\*![\s\S]*?Lodash v([\d.]+)", 80, "Lodash version banner", version_group=1),
]),
Technology("Moment.js", "JavaScript library", [
    _r("script", r"moment(?:\.min)?\.js", 60, "Moment.js script filename"),
    _r("js", r"/\*![\s\S]*?moment\.js v([\d.]+)", 80, "Moment.js version banner", version_group=1),
]),
Technology("Axios", "JavaScript library", [
    _r("script", r"axios(?:\.min)?\.js", 60, "Axios script filename"),
    _r("js", r"axios\.version\s*=\s*['\"]([\d.]+)['\"]", 80, "Axios version in source", version_group=1),
]),
Technology("D3.js", "JavaScript library", [
    _r("script", r"d3(?:\.v\d+)?(?:\.min)?\.js", 60, "D3.js script filename"),
    _r("html", r"d3\.version\s*=\s*['\"]([\d.]+)['\"]", 40, "D3 version global", version_group=1),
]),
Technology("Three.js", "JavaScript library", [
    _r("script", r"three(?:\.min)?\.js", 60, "Three.js script filename"),
    _r("js", r"REVISION\s*:\s*['\"](\d+)['\"]", 60, "Three.js revision", version_group=1),
]),
Technology("Chart.js", "JavaScript library", [
    _r("script", r"Chart(?:\.min)?\.js", 60, "Chart.js script filename"),
    _r("js", r"/\*![\s\S]*?Chart\.js v([\d.]+)", 80, "Chart.js version banner", version_group=1),
]),
Technology("Leaflet", "JavaScript library", [
    _r("script", r"leaflet(?:\.min)?\.js", 60, "Leaflet script filename"),
    _r("css", r"/\*![\s\S]*?Leaflet ([\d.]+)", 80, "Leaflet version banner", version_group=1),
]),
Technology("Mapbox GL JS", "JavaScript library", [
    _r("script", r"mapbox-gl(?:\.min)?\.js", 100, "Mapbox GL JS script"),
]),
Technology("Socket.IO", "JavaScript library", [
    _r("script", r"socket\.io(?:\.min)?\.js", 100, "Socket.IO client script"),
]),
Technology("Redux", "JavaScript library", [
    _r("script", r"redux(?:\.min)?\.js", 60, "Redux script filename"),
]),
Technology("GSAP", "JavaScript library", [
    _r("script", r"gsap(?:\.min)?\.js", 60, "GSAP (GreenSock) script filename"),
    _r("script", r"TweenMax(?:\.min)?\.js", 60, "GSAP TweenMax filename"),
]),
Technology("Alpine.js", "JavaScript library", [
    _r("script", r"alpine(?:\.min)?\.js", 60, "Alpine.js script filename"),
    _r("html", r"x-data\s*=", 60, "Alpine.js x-data attribute"),
]),
Technology("HTMX", "JavaScript library", [
    _r("script", r"htmx(?:\.min)?\.js", 60, "HTMX script filename"),
    _r("html", r"hx-(?:get|post|target|swap)\s*=", 60, "HTMX attribute"),
]),
Technology("Stimulus", "JavaScript library", [
    _r("script", r"stimulus(?:\.min)?\.js", 60, "Stimulus script filename"),
    _r("html", r"data-controller\s*=", 60, "Stimulus controller attribute"),
]),
Technology("Ember.js", "JavaScript library", [
    _r("meta", r"^ember-variant: (.+)", 80, "Ember variant meta", version_group=1),
    _r("html", r"id=[\"']ember\d+[\"']", 40, "Ember dynamic ID"),
]),
Technology("Backbone.js", "JavaScript library", [
    _r("script", r"backbone(?:\.min)?\.js", 80, "Backbone.js script filename"),
]),
Technology("Preact", "JavaScript library", [
    _r("script", r"preact(?:\.min)?\.js", 80, "Preact script filename"),
]),
Technology("Solid.js", "JavaScript library", [
    _r("html", r"_\$HY", 80, "Solid.js hydration marker"),
]),
Technology("Lit", "JavaScript library", [
    _r("script", r"lit-element(?:\.min)?\.js", 80, "LitElement script filename"),
    _r("script", r"lit-all(?:\.min)?\.js", 80, "Lit bundle script filename"),
]),
Technology("Bulma", "CSS framework", [
    _r("html", r"bulma(?:\.min)?\.css", 100, "Bulma CSS filename"),
]),
Technology("Foundation", "CSS framework", [
    _r("html", r"foundation(?:\.min)?\.css", 60, "Foundation CSS filename"),
    _r("js", r"Foundation\.version\s*=\s*['\"]([\d.]+)['\"]", 80, "Foundation version in JS", version_group=1),
]),
Technology("Semantic UI", "CSS framework", [
    _r("html", r"semantic(?:\.min)?\.css", 80, "Semantic UI CSS filename"),
]),
Technology("Materialize", "CSS framework", [
    _r("html", r"materialize(?:\.min)?\.css", 60, "Materialize CSS filename"),
    _r("js", r"Materialize\.version\s*=\s*['\"]([\d.]+)['\"]", 80, "Materialize version in JS", version_group=1),
]),
Technology("UIkit", "CSS framework", [
    _r("html", r"uikit(?:\.min)?\.css", 60, "UIkit CSS filename"),
    _r("js", r"UIkit\.version\s*=\s*['\"]([\d.]+)['\"]", 80, "UIkit version in JS", version_group=1),
]),
Technology("BunnyCDN", "CDN", [
    _r("header", r"^server: bunnycdn", 100, "BunnyCDN server header"),
]),
Technology("KeyCDN", "CDN", [
    _r("header", r"^x-edge-location:", 100, "KeyCDN edge location header"),
]),
Technology("StackPath", "CDN", [
    _r("header", r"^x-sp-edge:", 100, "StackPath edge header"),
]),
Technology("Sucuri", "Security", [
    _r("header", r"^x-sucuri-id:", 100, "Sucuri Firewall header"),
    _r("header", r"^x-sucuri-cache:", 40, "Sucuri cache header"),
]),
Technology("Imperva", "Security", [
    _r("header", r"^x-iinfo:", 80, "Imperva info header"),
    _r("cookie", r"visid_incap", 80, "Imperva Incapsula cookie"),
]),
Technology("Matomo", "Analytics", [
    _r("html", r"matomo\.js|piwik\.js", 80, "Matomo tracking script"),
    _r("html", r"_paq\.push\(", 40, "Matomo tracking call"),
]),
Technology("Plausible", "Analytics", [
    _r("script", r"plausible(?:\.hash)?\.js", 100, "Plausible analytics script"),
]),
Technology("Mixpanel", "Analytics", [
    _r("script", r"mixpanel-\d+\.\d+\.min\.js", 100, "Mixpanel tracking script"),
]),
Technology("Amplitude", "Analytics", [
    _r("script", r"amplitude-\d+\.\d+\.min\.js", 100, "Amplitude tracking script"),
]),
Technology("Segment", "Analytics", [
    _r("script", r"analytics\.js/v1/([^/]+)/analytics\.min\.js", 100, "Segment analytics script"),
]),
Technology("Intercom", "Marketing", [
    _r("script", r"widget\.intercom\.io", 100, "Intercom widget loader"),
]),
Technology("Drift", "Marketing", [
    _r("script", r"js\.driftt\.com", 100, "Drift widget loader"),
]),
Technology("Zendesk", "Marketing", [
    _r("script", r"static\.zdassets\.com", 100, "Zendesk assets loader"),
]),
Technology("HubSpot", "Marketing", [
    _r("script", r"js\.hs-scripts\.com", 100, "HubSpot scripts loader"),
]),
Technology("Mailchimp", "Marketing", [
    _r("script", r"chimpstatic\.com", 80, "Mailchimp static assets"),
    _r("html", r"mc-embedded-subscribe-form", 40, "Mailchimp embedded form"),
]),
Technology("Facebook Pixel", "Marketing", [
    _r("html", r"connect\.facebook\.net/[a-z_A-Z]+/fbevents\.js", 100, "Facebook Pixel loader"),
]),
Technology("LinkedIn Insight Tag", "Marketing", [
    _r("script", r"snap\.licdn\.com/li\.lms-analytics/insight\.min\.js", 100, "LinkedIn Insight script"),
]),
Technology("TikTok Pixel", "Marketing", [
    _r("script", r"analytics\.tiktok\.com/i18n/pixel/events\.js", 100, "TikTok Pixel script"),
]),
Technology("Sentry", "Security", [
    _r("script", r"browser\.sentry-cdn\.com", 100, "Sentry browser SDK"),
]),
Technology("New Relic", "Analytics", [
    _r("script", r"js-agent\.newrelic\.com", 100, "New Relic browser agent"),
]),
Technology("Stripe", "E-commerce", [
    _r("script", r"js\.stripe\.com/v3", 100, "Stripe.js V3 loader"),
]),
Technology("PayPal", "E-commerce", [
    _r("script", r"paypal\.com/sdk/js", 100, "PayPal JS SDK loader"),
]),
Technology("YouTube", "Video", [
    _r("html", r"youtube\.com/embed/", 100, "YouTube video embed"),
]),
Technology("Vimeo", "Video", [
    _r("html", r"player\.vimeo\.com/video/", 100, "Vimeo video embed"),
]),
Technology("Video.js", "Video", [
    _r("script", r"(vjs\.zencdn\.net|/video\.js/\d)", 80, "Video.js CDN script"),
]),
Technology("Font Awesome", "Fonts", [
    _r("script", r"kit\.fontawesome\.com/[a-z0-9]+\.js", 80, "Font Awesome Kit"),
    _r("html", r"font-awesome(?:\.min)?\.css", 60, "Font Awesome CSS filename"),
]),
Technology("Disqus", "Widgets", [
    _r("script", r"disqus\.com/count\.js", 80, "Disqus comment count"),
    _r("html", r"disqus_thread", 60, "Disqus thread ID"),
]),
Technology("Elementor", "CMS", [
    _r("html", r"elementor-widget-container", 100, "Elementor widget class"),
    _r("html", r"elementor-default", 60, "Elementor default class"),
]),
Technology("Yoast SEO", "CMS", [
    _r("html", r"<!-- This site is optimized with the Yoast SEO plugin v([\d.]+)", 100, "Yoast SEO comment", version_group=1),
]),
Technology("Jetpack", "CMS", [
    _r("header", r"^x-jetpack-version: ([\d.]+)", 100, "Jetpack version header", version_group=1),
]),
Technology("Wordfence", "Security", [
    _r("path", r" 200 .*Wordfence Security", 100, "Wordfence readme", path="/wp-content/plugins/wordfence/readme.txt"),
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
                     "description": "...", "version_group": 1, "path": "/..."}]}]}

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
                          r.get("version_group"),
                          r.get("path"))
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
