# TechFinger

Wappalyzer-lite: fingerprint a website's technologies from its response
headers, HTML, scripts, cookies, favicon hash, JS/CSS file contents and
known-path probes, using an offline rule set of 152 technologies. No
third-party service, no API key, no dependencies — just Python's standard
library.

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

# List the 152 technologies the built-in rule set knows
python3 -m techfinger --list

# Add your own rules (or override a built-in technology)
python3 -m techfinger https://example.com --rules my-rules.json

# Quiet mode: page fetch only, no favicon, asset or path requests
python3 -m techfinger https://example.com --no-favicon --no-assets --no-paths
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
headers, `ng-version` attributes, JS/CSS version banners).

## How it works

Nine match surfaces, one offline rule set (`techfinger/rules.py`):

| Rule kind | Matched against |
|-----------|-----------------|
| `header` | `name: value` lines of the response headers |
| `html` | the response body |
| `script` | every `<script src="...">` URL |
| `meta` | `name=content` strings from the page's `<meta>` tags |
| `cookie` | `Set-Cookie` header values |
| `favicon` | the favicon hash string (see below) |
| `js` | fetched same-origin `<script>` file contents (max 5, 128 KiB each) |
| `css` | fetched same-origin stylesheet contents (max 5, 128 KiB each) |
| `path` | `"{path} {status} {body snippet}"` from known-path probes (max 10) |

152 technologies ship in the rule set across CMS, e-commerce, frameworks,
languages, web servers, hosting, CDNs, analytics, marketing, security,
video, fonts and widgets. Run `--list` for the full list.

The favicon hash is TechFinger's own fingerprint: the first 16 hex chars
of the SHA-256 of the favicon bytes. It is NOT Wappalyzer's MurmurHash
and is not compatible with published Wappalyzer favicon hashes. The
report prints the hash so you can write your own `favicon` rules for it;
no built-in rules use it.

## Custom rules

`--rules` takes a JSON file. A technology with a name already in the
built-in set replaces it; a new name is added.

```json
{"technologies": [{"name": "MyCMS", "category": "CMS", "rules": [
  {"kind": "html", "pattern": "mycms", "weight": 60,
   "description": "mycms marker", "version_group": null}
]}]}
```

`path` rules need a `"path"` field with the path to probe; the pattern
matches `"{path} {status} {body snippet}"` and should require a `200`
status plus a distinctive body marker. `favicon` rules match the hash
string printed in the report.

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `url` | — | URL to fingerprint (http:// or https://) |
| `--json` | off | Print JSON instead of the text report |
| `--timeout` | `10` | Request timeout in seconds |
| `--user-agent` | `TechFinger/1.1 ...` | User-Agent header to send |
| `--rules` | — | JSON file with extra/override rules |
| `--no-favicon` | off | Skip the favicon fetch and hash |
| `--no-assets` | off | Skip same-origin JS/CSS content fetching |
| `--no-paths` | off | Skip known-path probes |
| `--list` | off | List known technologies and exit |

## Scope and limits

- Only fingerprint what the site volunteers: headers, HTML, script URLs,
  meta tags, cookies, favicon, same-origin asset files, known paths. A
  site that hides its stack (stripped `Server` header, no generator tag)
  reports less — that is a finding in itself.
- Detections are heuristic, not proof: a `wp-content` path means the page
  references WordPress paths, not that the whole site is WordPress.
  Confidence levels say how strong the evidence is. Rule patterns are
  checked against local fixtures; real-world accuracy varies by site.
- Only scan targets you are authorized to test. TechFinger sends one page
  GET plus a favicon fetch, up to 10 same-origin asset fetches and up to
  10 known-path probes, and follows redirects; it never logs in, submits
  forms, or sends payloads. Use `--no-favicon --no-assets --no-paths`
  for a single-request scan.

## Tests

```bash
python3 -m pytest
```

The suite runs against a local fixture HTTP server — no real target is
ever contacted.
