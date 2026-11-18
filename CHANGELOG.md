# Changelog

## 1.1.0

### Added
- Three new detection surfaces: favicon hash (TechFinger's own SHA-256
  fingerprint, not Wappalyzer MurmurHash), same-origin JS/CSS file
  content matching, and known-path probes driven by `path` rules.
- CLI flags `--no-favicon`, `--no-assets`, `--no-paths`.
- Rule set expanded from 42 to 152 technologies.
- Favicon hash and probed paths in text and JSON reports.

## 1.0.0

- Initial release: offline rule set with 42 technologies, five match
  surfaces (headers, HTML, script URLs, meta tags, cookies), text and
  JSON output, custom rules via `--rules`.
