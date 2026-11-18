"""Turn a Lynis report into findings.

Lynis (CISOfy, GPL-3.0) is run on the endpoint by the collector when
`lynis.enabled` is set; this module only parses its report format
(`warning[]=ID|text|...`, `suggestion[]=ID|text|details|solution|`).
"""
from __future__ import annotations

from .analyzer import Finding, Severity
from ..collector.base import CollectionResult

_MAX_SUGGESTIONS = 40


def lynis_findings(result: CollectionResult) -> list[Finding]:
    out = result.outputs.get("lynis")
    if out is None or not out.stdout:
        return []
    findings: list[Finding] = []
    suggestions = 0
    for line in out.stdout.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        parts = [p for p in value.split("|")]
        test_id = parts[0] if parts else ""
        text = parts[1] if len(parts) > 1 else ""
        extra = " ".join(p for p in parts[2:] if p and p != "-")
        ref = f"https://cisofy.com/lynis/controls/{test_id}/" if test_id else ""
        if key == "warning[]":
            findings.append(Finding(
                result.host, Severity.MEDIUM, f"Lynis-advarsel {test_id}: {text}",
                extra or text, "hardening", "lynis", line[:300],
                "Se Lynis-kontrollen for anbefalt tiltak.", [ref] if ref else []))
        elif key == "suggestion[]" and suggestions < _MAX_SUGGESTIONS:
            suggestions += 1
            findings.append(Finding(
                result.host, Severity.LOW, f"Lynis-forslag {test_id}: {text}",
                extra or text, "hardening", "lynis", line[:300],
                extra or "Se Lynis-kontrollen.", [ref] if ref else []))
        elif key == "hardening_index":
            findings.append(Finding(
                result.host, Severity.INFO, f"Lynis herdingsindeks: {value}/100",
                "Samlet herdingsscore fra Lynis (høyere er bedre).",
                "hardening", "lynis", line))
    return findings
