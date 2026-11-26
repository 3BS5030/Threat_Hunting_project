"""Read-only helpers the assistant can use to reason about a hunt report."""

from __future__ import annotations

from collections import Counter
from typing import Any

from hunting.rule_engine import load_attack


def _techniques(finding: dict[str, Any]) -> list[str]:
    values = finding.get("techniques")
    if not isinstance(values, list) or not values:
        legacy = finding.get("technique")
        values = [legacy] if legacy else []
    return sorted({str(value).upper() for value in values if value})


def summarize_findings(report: dict[str, Any]) -> str:
    findings = report.get("findings", [])
    if not findings:
        return "No findings in the current report."
    severities = Counter(item.get("severity", "info") for item in findings)
    techniques = sorted(
        {technique for item in findings for technique in _techniques(item)}
    )
    return (
        f"{len(findings)} finding(s) "
        + ", ".join(f"{name}={count}" for name, count in sorted(severities.items()))
        + f"; techniques: {', '.join(techniques) if techniques else 'none'}."
    )


def top_findings(report: dict[str, Any], limit: int = 5) -> str:
    lines = []
    for finding in report.get("findings", [])[:limit]:
        techniques = ", ".join(_techniques(finding)) or "none"
        lines.append(
            f"- [{finding.get('severity', 'info')}] {finding.get('rule', '')} "
            f"({techniques}): {finding.get('evidence', '')[:120]}"
        )
    return "\n".join(lines) if lines else "No findings to list."


def lookup_technique(technique_id: str) -> str:
    technique = load_attack().get("techniques", {}).get(technique_id.strip().upper())
    if not technique:
        return f"Unknown technique: {technique_id}"
    tactics = technique.get("tactics") or [technique.get("tactic", "")]
    return f"{technique_id}: {technique.get('name', '')} ({', '.join(tactics)})"


TOOLS = {
    "summarize_findings": summarize_findings,
    "top_findings": top_findings,
    "lookup_technique": lookup_technique,
}
