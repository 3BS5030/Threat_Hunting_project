"""Small agent that answers questions about the current hunt report."""

from __future__ import annotations

import re
from typing import Any

from ai.client import LLMClient
from ai.tools import lookup_technique, summarize_findings, top_findings

SYSTEM_PROMPT = (
    "You are a concise threat hunting assistant. Use the supplied report context "
    "and MITRE ATT&CK references. Prioritise concrete next investigation steps."
)


def build_context(report: dict[str, Any]) -> str:
    return (
        f"VM: {report.get('vm', 'unknown')}\n"
        f"Summary: {summarize_findings(report)}\n"
        f"Top findings:\n{top_findings(report)}\n"
        f"Collection errors: {report.get('errors', [])[:3]}"
    )


def local_answer(question: str, report: dict[str, Any]) -> str:
    lowered = question.lower()
    technique_ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", question, flags=re.IGNORECASE)
    if technique_ids:
        return " ".join(lookup_technique(item) for item in technique_ids)
    if "summar" in lowered or "report" in lowered or "finding" in lowered:
        return summarize_findings(report)
    if "top" in lowered or "priority" in lowered or "next" in lowered:
        return "Prioritised findings:\n" + top_findings(report)
    return (
        summarize_findings(report)
        + " Ask for a summary, the top findings, or an ATT&CK ID such as T1059.001. "
        "Set AI_API_KEY to enable free-form remote answers."
    )


def answer(
    question: str,
    report: dict[str, Any] | None = None,
    client: LLMClient | None = None,
) -> str:
    report = report or {}
    context = build_context(report)
    llm = client if client is not None else LLMClient()
    if llm.configured:
        try:
            return llm.complete(f"{context}\n\nQuestion: {question}", SYSTEM_PROMPT)
        except Exception:
            pass
    return local_answer(question, report)
