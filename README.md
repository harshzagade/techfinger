# TechFinger

Wappalyzer-lite: fingerprint a website's technologies from its response
headers and HTML, using an offline rule set. No third-party service, no API
key, no dependencies — just Python's standard library.

Built for recon work where you need to know what a site runs (CMS,
framework, web server, analytics) before you point heavier tools at it.

## Install

Python 3.11+ — nothing to install.

```bash
git clone https://github.com/harshzagade/techfinger.git
cd techfinger
python3 -m techfinger --help
```

## Usage

```bash
# Fingerprint a site
python3 -m techfinger https://example.com

# Machine-readable output for pipelines
python3 -m techfinger https://example.com --json

# Custom User-Agent and timeout
python3 -m techfinger https://example.com --user-agent "Mozilla/5.0" --timeout 5

# List the 42 technologies the built-in rule set knows
python3 -m techfinger --list

# Add your own rules (or override a built-in technology)
python3 -m techfinger https://example.com --rules my-rules.json
```

## Sample output

Run against a local WordPress-like test page (served by the test fixture):

```
TechFinger report for http://127.0.0.1:40771/
HTTP status: 200
Server header: nginx/1.24.0

Detected technologies (4):
  [HIGH 100] WordPress 6.4.2 (CMS)
    - generator meta tag: generator=WordPress 6.4.2
    - wp-content path in page: <link rel="stylesheet" href="/wp-content/themes/twentyfour/style.css">
    - wp-includes path in page: four/style.css"> <script src="/wp-includes/js/jquery/jquery.min.js"></scr
    - script from wp-includes: /wp-includes/js/jquery/jquery.min.js
  [MEDIUM 60] Google Analytics (Analytics)
    - gtag.js loader: ipt> <script src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></scrip...
  [MEDIUM 60] Nginx 1.24.0 (Web server)
    - Server header: server: nginx/1.24.0
  [MEDIUM 40] jQuery (JavaScript library)
    - jquery script: /wp-includes/js/jquery/jquery.min.js
```

Confidence is the sum of matched rule weights (capped at 100):
**High** >= 70, **Medium** >= 40, **Low** below that. A version is shown
when a rule captures one (generator meta tags, `Server` / `X-Powered-By`
headers, `ng-version` attributes).

## How it works

Five match surfaces, one offline rule set (`techfinger/rules.py`):

| Rule kind | Matched against |
|-----------|-----------------|
| `header` | `name: value` lines of the response headers |
| `html` | the response body |
| `script` | every `<script src="...">` URL |
| `meta` | `name=content` strings from the page's `<meta>` tags |
| `cookie` | `Set-Cookie` header values |

42 technologies ship in the rule set: WordPress, Drupal, Joomla, Ghost,
Shopify, Wix, Squarespace, Magento, Django, Flask, Laravel, Ruby on Rails,
Express, Next.js, Nuxt, Angular, Vue.js, React, Svelte, ASP.NET, Spring,
PHP, Node.js, jQuery, Bootstrap, Tailwind CSS, Nginx, Apache, Microsoft
IIS, LiteSpeed, Caddy, Gunicorn, Cloudflare, CloudFront, Fastly, Akamai,
Varnish, Google Analytics, Google Tag Manager, Hotjar, reCAPTCHA, hCaptcha.

## Custom rules

`--rules` takes a JSON file. A technology with a name already in the
built-in set replaces it; a new name is added.

```json
{"technologies": [{"name": "MyCMS", "category": "CMS", "rules": [
  {"kind": "html", "pattern": "mycms", "weight": 60,
   "description": "mycms marker", "version_group": null}
]}]}
```

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `url` | — | URL to fingerprint (http:// or https://) |
| `--json` | off | Print JSON instead of the text report |
| `--timeout` | `10` | Request timeout in seconds |
| `--user-agent` | `TechFinger/1.0 ...` | User-Agent header to send |
| `--rules` | — | JSON file with extra/override rules |
| `--list` | off | List known technologies and exit |

## Scope and limits

- Only fingerprint what the site volunteers: headers, HTML, script URLs,
  meta tags, cookies. A site that hides its stack (stripped `Server`
  header, no generator tag) reports less — that is a finding in itself.
- Detections are heuristic, not proof: a `wp-content` path means the page
  references WordPress paths, not that the whole site is WordPress.
  Confidence levels say how strong the evidence is.
- Only scan targets you are authorized to test. TechFinger sends a single
  GET request and follows redirects; it never logs in, submits forms, or
  sends payloads.

## Tests

```bash
python3 -m pytest
```

The suite runs against a local fixture HTTP server — no real target is
ever contacted.
