"""Known Ollama vulnerabilities that matter when a stranger can reach the API.

Ranges are from the CVE records (NVD, CVE.org, the CNA's advisory) as of 27 November 2026. None of
these is in CISA's Known Exploited Vulnerabilities catalog (checked against catalog 2026.11.25).
CVE-2025-63389 ("endpoints without authentication", listed for versions up to 0.12.3) is left out
on purpose: no later release added authentication, so a version check would wrongly look fixed.
"""
from __future__ import annotations

import re

# (cve, first affected or None, first fixed or None, last affected or None, what it does)
KNOWN = (
    ("CVE-2024-28224", None, "0.1.29", None,
     "DNS rebinding: a web page could reach the API on 127.0.0.1"),
    ("CVE-2024-37032", None, "0.1.34", None,
     "Probllama: path traversal through /api/pull and /api/push, file write and read"),
    ("CVE-2026-7482", None, "0.17.1", None,
     "heap over-read through /api/create, sent out through /api/push"),
    ("CVE-2026-103663", "0.14.3", "0.35.0", None,
     "path traversal in /api/pull layer digests writes files outside the model store; "
     "code execution as root in many Docker images"),
    ("CVE-2026-85180", "0.30.0", None, "0.33.2",
     "pulls follow redirects to internal hosts, cloud metadata included (SSRF)"),
    ("CVE-2026-108836", None, "0.34.2", None,
     "SSRF through crafted model names in pulls"),
)

SAFE_FLOOR = "0.35.0"   # first version with none of the above


def parse(version: str) -> tuple | None:
    """'0.40.19-rc0' -> (0, 40, 19, 0, 0); a release sorts after its release candidates."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:-(?:rc)?(\d+))?", (version or "").strip())
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if m.group(4) is not None:
        return (major, minor, patch, 0, int(m.group(4)))
    return (major, minor, patch, 1, 0)


def affected(version: str) -> list[tuple[str, str, str]]:
    """[(cve, fixed in, summary)] for the version. Unknown or dev versions ('0.0.0') -> []."""
    v = parse(version)
    if v is None or v[:3] == (0, 0, 0):
        return []
    out = []
    for cve, first, fixed, last, summary in KNOWN:
        if first and v < parse(first):
            continue
        if fixed and v >= parse(fixed):
            continue
        if last and v > parse(last):
            continue
        out.append((cve, fixed or f"after {last}", summary))
    return out
