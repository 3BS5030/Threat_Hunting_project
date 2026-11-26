"""Export hunt findings as an ATT&CK Navigator layer."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from hunting.rule_engine import load_attack
from mitre.attack import attack_version

SEVERITY_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 0}
SEVERITY_COLOR = {
    "critical": "#c00000",
    "high": "#ff6666",
    "medium": "#ffe766",
    "low": "#b6d7a8",
    "info": "#8ec843",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
VALID_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _finding_techniques(finding: dict[str, Any]) -> list[str]:
    values = finding.get("techniques")
    if not isinstance(values, list) or not values:
        legacy = finding.get("technique")
        values = [legacy] if legacy else []
    result: list[str] = []
    for value in values:
        technique_id = str(value).strip().upper()
        if technique_id and technique_id not in result:
            result.append(technique_id)
    return result


def _layer_version(report: dict[str, Any], attack: dict[str, Any]) -> str:
    mitre = report.get("mitre", {}) if isinstance(report.get("mitre"), dict) else {}
    return (
        str(mitre.get("version") or "")
        or attack_version(attack)
        or str(attack.get("dataset_version") or "")
        or "14"
    )


def build_layer(
    report: dict[str, Any], name: str | None = None, attack: dict[str, Any] | None = None
) -> dict[str, Any]:
    dataset = attack if attack is not None else load_attack()
    known = dataset.get("techniques", {}) if isinstance(dataset, dict) else {}
    known = known if isinstance(known, dict) else {}

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unknown: set[str] = set()
    for finding in report.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        for technique_id in _finding_techniques(finding):
            if not VALID_TECHNIQUE_ID.match(technique_id):
                unknown.add(technique_id)
                continue
            if known and technique_id not in known:
                unknown.add(technique_id)
                continue
            grouped[technique_id].append(finding)

    techniques = []
    for technique_id, findings in sorted(grouped.items()):
        severities = Counter(item.get("severity", "info") for item in findings)
        rules = sorted({str(item.get("rule", "")) for item in findings if item.get("rule")})
        top = next((level for level in SEVERITY_ORDER if severities.get(level)), "info")
        metadata = next(
            (
                item.get("technique_metadata", [])
                for item in findings
                if isinstance(item.get("technique_metadata"), list)
                and any(entry.get("id") == technique_id for entry in item["technique_metadata"])
            ),
            [],
        )
        tactic_values: list[str] = []
        for entry in metadata:
            if entry.get("id") != technique_id:
                continue
            values = entry.get("tactics") or ([entry.get("tactic")] if entry.get("tactic") else [])
            for value in values or []:
                if value and value not in tactic_values:
                    tactic_values.append(str(value))
        techniques.append(
            {
                "techniqueID": technique_id,
                "color": SEVERITY_COLOR.get(top, SEVERITY_COLOR["info"]),
                "comment": (
                    f"{len(findings)} finding(s): "
                    + ", ".join(f"{key}={value}" for key, value in sorted(severities.items()))
                    + (f"; rules: {', '.join(rules)}" if rules else "")
                    + (f"; tactics: {', '.join(tactic_values)}" if tactic_values else "")
                ),
                "enabled": True,
                "metadata": [],
                "showSubtechniques": True,
                "score": SEVERITY_SCORE.get(top, 0),
            }
        )

    layer_metadata: list[dict[str, str]] = []
    if unknown:
        layer_metadata.append(
            {
                "name": "unmapped_techniques",
                "value": ", ".join(sorted(unknown)),
            }
        )
    mitre = report.get("mitre", {}) if isinstance(report.get("mitre"), dict) else {}
    if mitre.get("status"):
        layer_metadata.append({"name": "mitre_status", "value": str(mitre["status"])})
    if mitre.get("sync_error"):
        layer_metadata.append({"name": "mitre_sync_error", "value": str(mitre["sync_error"])[:300]})

    return {
        "name": name or f"{report.get('vm', 'hunt')} threat hunt",
        "versions": {
            "attack": _layer_version(report, dataset),
            "navigator": "4.5",
            "layer": "4.5",
        },
        "domain": str(dataset.get("domain", "enterprise-attack")) if isinstance(dataset, dict) else "enterprise-attack",
        "description": f"Generated from hunt at {report.get('timestamp', '')}",
        "filters": {"platforms": ["windows", "linux", "macos"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": layer_metadata,
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def save_layer(
    report: dict[str, Any],
    path: str | Path | None = None,
    attack: dict[str, Any] | None = None,
) -> Path:
    target = Path(path) if path else Path(f"{report.get('vm', 'hunt')}_layer.json")
    target.write_text(
        json.dumps(build_layer(report, attack=attack), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return target
