"""Render fingerprint results as human-readable text or JSON."""

from __future__ import annotations

import json
from typing import Any

from .fetch import FetchResult
from .fingerprint import Detection


def render_text(result: FetchResult, detections: list[Detection], scan: Any = None) -> str:
    lines = [f"TechFinger report for {result.url}"]
    if result.final_url != result.url:
        lines.append(f"Final URL: {result.final_url}")
    if result.status is not None:
        lines.append(f"HTTP status: {result.status}")
    server = result.headers.get("server")
    if server:
        lines.append(f"Server header: {server}")

    fav = scan.favicon_hash if scan else getattr(result, "favicon_hash", None)
    if fav:
        lines.append(f"Favicon hash: {fav}")

    lines.append("")
    if not detections:
        lines.append("No known technologies detected.")
        return "\n".join(lines) + "\n"
    lines.append(f"Detected technologies ({len(detections)}):")
    for det in detections:
        label = det.name
        if det.version:
            label += f" {det.version}"
        lines.append(f"  [{det.level.upper()} {det.confidence}] "
                     f"{label} ({det.category})")
        for item in det.evidence:
            lines.append(f"    - {item}")
    return "\n".join(lines) + "\n"


def render_json(result: FetchResult, detections: list[Detection], scan: Any = None) -> str:
    payload = {
        "url": result.url,
        "final_url": result.final_url,
        "status": result.status,
        "favicon_hash": scan.favicon_hash if scan else getattr(result, "favicon_hash", None),
        "probed_paths": sorted(scan.probes.keys()) if scan else sorted(getattr(result, "probes", {}).keys()),
        "technologies": [d.to_dict() for d in detections],
    }
    return json.dumps(payload, indent=2) + "\n"
