from __future__ import annotations

from hunting.navigator import build_layer


def _dataset() -> dict:
    return {
        "domain": "enterprise-attack",
        "source_version": "18.1",
        "dataset_version": "2026-11-25T10:00:00Z",
        "techniques": {
            "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
            "T1098.007": {
                "name": "Additional Local or Domain Groups",
                "tactic": "Persistence",
            },
        },
    }


def _report() -> dict:
    return {
        "vm": "multi-technique",
        "timestamp": "2026-11-25T10:05:00+00:00",
        "mitre": {"status": "live", "version": "18.1", "sync_error": ""},
        "findings": [
            {
                "rule": "MULTI_RULE",
                "severity": "high",
                "technique": "T1110",
                "techniques": ["T1110", "T1098.007", "T9999"],
                "technique_metadata": [
                    {"id": "T1110", "tactics": ["Credential Access"]},
                    {
                        "id": "T1098.007",
                        "tactics": ["Persistence", "Privilege Escalation"],
                    },
                ],
            }
        ],
    }


def test_build_layer_exports_every_valid_technique() -> None:
    layer = build_layer(_report(), attack=_dataset())

    assert [item["techniqueID"] for item in layer["techniques"]] == [
        "T1098.007",
        "T1110",
    ]
    assert all(item["score"] == 75 for item in layer["techniques"])
    assert layer["versions"]["attack"] == "18.1"
    assert layer["domain"] == "enterprise-attack"


def test_build_layer_tracks_unknown_techniques_without_exporting_them() -> None:
    layer = build_layer(_report(), attack=_dataset())
    metadata = {item["name"]: item["value"] for item in layer["metadata"]}

    assert metadata["unmapped_techniques"] == "T9999"
    assert "T9999" not in {item["techniqueID"] for item in layer["techniques"]}


def test_build_layer_uses_dynamic_version_without_report_metadata() -> None:
    report = _report()
    report.pop("mitre")
    layer = build_layer(report, attack=_dataset())

    assert layer["versions"]["attack"] == "18.1"
