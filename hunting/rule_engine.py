"""Load the regex rule pack and evaluate it against collected host data."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

RULES_PATH = Path(__file__).with_name("rules.json")
ATTACK_PATH = Path(__file__).with_name("attack.json")


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_rules(path: str | Path | None = None) -> list[dict[str, Any]]:
    data = _read_json(Path(path) if path else RULES_PATH)
    return list(data.get("rules", []))


def load_attack(path: str | Path | None = None) -> dict[str, Any]:
    return _read_json(Path(path) if path else ATTACK_PATH)


def compile_rule(rule: dict[str, Any]) -> re.Pattern[str]:
    return re.compile(rule["pattern"])


def run_rules(
    data: dict[str, Iterable[str]],
    rules: list[dict[str, Any]] | None = None,
    attack: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return one finding per matching rule/target line."""
    rules = rules if rules is not None else load_rules()
    attack = attack if attack is not None else load_attack()
    techniques = attack.get("techniques", {})
    findings: list[dict[str, Any]] = []

    for rule in rules:
        target = rule.get("target", "processes")
        pattern = compile_rule(rule)
        for raw_line in data.get(target, []) or []:
            line = str(raw_line)
            match = pattern.search(line)
            if not match:
                continue
            technique_id = rule.get("technique", "")
            technique = techniques.get(technique_id, {})
            findings.append(
                {
                    "rule": rule.get("id", "UNNAMED"),
                    "description": rule.get("description", ""),
                    "severity": rule.get("severity", "info"),
                    "technique": technique_id,
                    "technique_name": technique.get("name", ""),
                    "tactic": technique.get("tactic", ""),
                    "target": target,
                    "evidence": line[:500],
                    "match": match.group(0)[:200],
                    "source": "rule",
                }
            )
    return findings


def run_rule_tests(rules: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Execute the test cases embedded in rules.json."""
    results: list[dict[str, Any]] = []
    for rule in rules if rules is not None else load_rules():
        pattern = compile_rule(rule)
        for case in rule.get("tests", []):
            matched = bool(pattern.search(case.get("text", "")))
            results.append(
                {
                    "rule": rule.get("id", "UNNAMED"),
                    "text": case.get("text", ""),
                    "expected": case.get("expect"),
                    "matched": matched,
                    "passed": matched == case.get("expect"),
                }
            )
    return results
