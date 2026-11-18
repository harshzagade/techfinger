"""Command-line interface for TechFinger."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .fetch import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT
from .report import render_json, render_text
from .rules import list_technologies, merged_rules
from .scan import scan_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="techfinger",
        description="Fingerprint a website's technologies from its "
                    "headers and HTML, using an offline rule set.")
    parser.add_argument("url", nargs="?",
                        help="URL to fingerprint (http:// or https://)")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of text")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"request timeout in seconds "
                             f"(default {DEFAULT_TIMEOUT})")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT,
                        help="User-Agent header to send")
    parser.add_argument("--rules",
                        help="JSON file with extra/override technology rules")
    parser.add_argument("--no-favicon", action="store_false", dest="favicon",
                        default=True, help="disable favicon fingerprinting")
    parser.add_argument("--no-assets", action="store_false", dest="assets",
                        default=True, help="disable same-origin JS/CSS scanning")
    parser.add_argument("--no-paths", action="store_false", dest="paths",
                        default=True, help="disable known-path probing")
    parser.add_argument("--list", action="store_true",
                        help="list the technologies the rule set knows "
                             "and exit")
    parser.add_argument("--version", action="version",
                        version=f"techfinger {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list:
        for name, category in list_technologies():
            print(f"{name} ({category})")
        return 0

    if not args.url:
        parser.error("a URL is required (or use --list)")

    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")

    try:
        technologies = merged_rules(args.rules)
    except ValueError as exc:
        print(f"techfinger: {exc}", file=sys.stderr)
        return 2

    scan = scan_url(args.url, technologies=technologies,
                    timeout=args.timeout, user_agent=args.user_agent,
                    enable_favicon=args.favicon, enable_assets=args.assets,
                    enable_paths=args.paths)
    if scan.error is not None:
        print(f"techfinger: {scan.error}", file=sys.stderr)
        return 1

    if args.json:
        print(render_json(scan, scan.detections), end="")
    else:
        print(render_text(scan, scan.detections), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
