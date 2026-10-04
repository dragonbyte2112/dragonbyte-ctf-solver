"""
Web CTF static source review. This backend never makes outbound requests
to a user-supplied target on its own — that would need an explicitly
authorized scope per the project's security rules, and arbitrary egress
isn't available in this environment anyway. What it DOES do for real:
statically review HTML/JS/source the user uploads or pastes for the
classic leftover-artifact bugs that solve a lot of web CTF challenges.
"""
import re

PATTERNS = [
    (r"<!--.*?-->", "HTML comment"),
    (r'type=["\']hidden["\'][^>]*>', "Hidden form field"),
    (r'(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*["\'][^"\']{3,}["\']', "Hardcoded credential-like value"),
    (r'(?i)flag\s*[:=]', "Literal 'flag' assignment"),
    (r'/\*.*?debug.*?\*/', "Debug comment block"),
    (r'(?i)(TODO|FIXME|XXX)[: ].{0,80}', "Developer TODO note"),
    (r'[A-Za-z0-9+/]{40,}={0,2}', "Long Base64-looking blob"),
]


def static_source_review(source: str) -> dict:
    findings = []
    for pattern, label in PATTERNS:
        for m in re.finditer(pattern, source, re.DOTALL):
            findings.append({"type": label, "match": m.group(0)[:200]})
    return {
        "tool": "static_source_review",
        "command": "Python/regex: scan provided HTML/JS source for leftover comments, "
                   "hidden fields, hardcoded secrets, and encoded blobs",
        "status": "ran",
        "findings_count": len(findings),
        "findings": findings[:60],
        "note": "This reviews only the source you provided. Live scanning of a target URL "
                "requires an explicitly authorized scope and is not performed automatically.",
    }
