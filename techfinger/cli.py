"""Command-line interface for TechFinger."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .fetch import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, fetch_url
from .fingerprint import fingerprint
from .report import render_json, render_text
from .rules import list_technologies, merged_rules


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

    result = fetch_url(args.url, timeout=args.timeout,
                       user_agent=args.user_agent)
    if result.error is not None:
        print(f"techfinger: {result.error}", file=sys.stderr)
        return 1

    detections = fingerprint(result.headers, result.body,
                             technologies=technologies)
    if args.json:
        print(render_json(result, detections), end="")
    else:
        print(render_text(result, detections), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
