"""Match the offline rule set against a fetched page.

Confidence is the sum of matched rule weights, capped at 100:
``High`` >= 70, ``Medium`` >= 40, ``Low`` below that. A technology is only
reported when at least one rule matched. The version comes from the first
matched rule that captures one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .rules import RULES, Technology

_META_RE = re.compile(
    r'<meta\s[^>]*?(?:name|property)\s*=\s*["\']([^"\']+)["\']'
    r'[^>]*?content\s*=\s*["\']([^"\']*)["\']'
    r'|<meta\s[^>]*?content\s*=\s*["\']([^"\']*)["\']'
    r'[^>]*?(?:name|property)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(
    r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


@dataclass
class Detection:
    name: str
    category: str
    confidence: int
    level: str
    version: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence,
            "level": self.level,
            "version": self.version,
            "evidence": self.evidence,
        }


def confidence_level(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _surfaces(headers: dict[str, str], body: str) -> dict[str, list[str]]:
    """Build the matchable strings for each rule kind."""
    header_lines = [f"{name}: {value}" for name, value in headers.items()]
    cookies = [v for k, v in headers.items() if k == "set-cookie"]
    scripts = _SCRIPT_SRC_RE.findall(body)
    metas = []
    for m in _META_RE.finditer(body):
        name, content = (m.group(1), m.group(2)) if m.group(1) else \
            (m.group(4), m.group(3))
        metas.append(f"{name.lower()}={content}")
    return {
        "header": header_lines,
        "html": [body],
        "script": scripts,
        "meta": metas,
        "cookie": cookies,
    }


def fingerprint(headers: dict[str, str], body: str,
                technologies: list[Technology] | None = None, *,
                extra_surfaces: dict[str, list[str]] | None = None) -> list[Detection]:
    """Return detections sorted by confidence (highest first)."""
    surfaces = _surfaces(headers, body)
    if extra_surfaces:
        for kind, items in extra_surfaces.items():
            surfaces.setdefault(kind, []).extend(items)

    detections: list[Detection] = []
    for tech in (technologies if technologies is not None else RULES):
        score = 0
        version: str | None = None
        evidence: list[str] = []
        for rule in tech.rules:
            matched = None
            for candidate in surfaces.get(rule.kind, []):
                match = re.search(rule.pattern, candidate, re.IGNORECASE)
                if match:
                    matched = (match, candidate)
                    break
            if matched is None:
                continue
            match, candidate = matched
            score += rule.weight
            if version is None and rule.version_group is not None:
                try:
                    captured = match.group(rule.version_group)
                except IndexError:
                    captured = None
                if captured:
                    version = captured
            # Show the matched text with a little context around it, not
            # the whole candidate (a full HTML body is useless as evidence).
            start = max(0, match.start() - 30)
            end = min(len(candidate), match.end() + 30)
            snippet = " ".join(candidate[start:end].split())
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            evidence.append(f"{rule.description}: {snippet}")
        if score:
            score = min(score, 100)
            detections.append(Detection(
                name=tech.name,
                category=tech.category,
                confidence=score,
                level=confidence_level(score),
                version=version,
                evidence=evidence,
            ))
    detections.sort(key=lambda d: (-d.confidence, d.name))
    return detections
