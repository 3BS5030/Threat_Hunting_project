"""Export hunt findings as an ATT&CK Navigator layer."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SEVERITY_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 0}
SEVERITY_COLOR = {
    "critical": "#c00000",
    "high": "#ff6666",
    "medium": "#ffe766",
    "low": "#b6d7a8",
    "info": "#8ec843",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def build_layer(report: dict[str, Any], name: str | None = None) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in report.get("findings", []):
        technique_id = finding.get("technique")
        if technique_id:
            grouped[technique_id].append(finding)

    techniques = []
    for technique_id, findings in sorted(grouped.items()):
        severities = Counter(item.get("severity", "info") for item in findings)
        top = next(
            (level for level in SEVERITY_ORDER if severities.get(level)), "info"
        )
        techniques.append(
            {
                "techniqueID": technique_id,
                "color": SEVERITY_COLOR.get(top, "#8ec843"),
                "comment": f"{len(findings)} finding(s): "
                + ", ".join(f"{k}={v}" for k, v in sorted(severities.items())),
                "enabled": True,
                "metadata": [],
                "showSubtechniques": True,
                "score": SEVERITY_SCORE.get(top, 0),
            }
        )

    return {
        "name": name or f"{report.get('vm', 'hunt')} threat hunt",
        "versions": {"attack": "14", "navigator": "4.5", "layer": "4.5"},
        "domain": "enterprise-attack",
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
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def save_layer(report: dict[str, Any], path: str | Path | None = None) -> Path:
    target = Path(path) if path else Path(f"{report.get('vm', 'hunt')}_layer.json")
    target.write_text(
        json.dumps(build_layer(report), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return target
