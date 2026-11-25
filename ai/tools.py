"""Read-only helpers the assistant can use to reason about a hunt report."""

from __future__ import annotations

from collections import Counter
from typing import Any

from hunting.rule_engine import load_attack


def summarize_findings(report: dict[str, Any]) -> str:
    findings = report.get("findings", [])
    if not findings:
        return "No findings in the current report."
    severities = Counter(item.get("severity", "info") for item in findings)
    techniques = sorted(
        {item.get("technique", "") for item in findings if item.get("technique")}
    )
    return (
        f"{len(findings)} finding(s) "
        + ", ".join(f"{name}={count}" for name, count in sorted(severities.items()))
        + f"; techniques: {', '.join(techniques) if techniques else 'none'}."
    )


def top_findings(report: dict[str, Any], limit: int = 5) -> str:
    lines = []
    for finding in report.get("findings", [])[:limit]:
        lines.append(
            f"- [{finding.get('severity', 'info')}] {finding.get('rule', '')} "
            f"({finding.get('technique', '')}): {finding.get('evidence', '')[:120]}"
        )
    return "\n".join(lines) if lines else "No findings to list."


def lookup_technique(technique_id: str) -> str:
    technique = load_attack().get("techniques", {}).get(technique_id.strip().upper())
    if not technique:
        return f"Unknown technique: {technique_id}"
    return f"{technique_id}: {technique.get('name', '')} ({technique.get('tactic', '')})"


TOOLS = {
    "summarize_findings": summarize_findings,
    "top_findings": top_findings,
    "lookup_technique": lookup_technique,
}
