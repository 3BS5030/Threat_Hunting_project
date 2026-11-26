from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mitre.attack import (
    compare_datasets,
    fetch_live_dataset,
    parse_stix_bundle,
    sync_attack_data,
)


class Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self.payload

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def _bundle(name: str = "Test Technique", modified: str = "2026-11-25T10:00:00.000Z") -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--11111111-1111-4111-8111-111111111111",
                "name": "Credential Access",
                "description": "Test tactic",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "TA0006",
                        "url": "https://attack.mitre.org/tactics/TA0006/",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--22222222-2222-4222-8222-222222222222",
                "name": name,
                "description": "Official test technique metadata",
                "modified": modified,
                "x_mitre_is_subtechnique": True,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T9999.001",
                        "url": "https://attack.mitre.org/techniques/T9999/001/",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
                ],
            },
        ],
    }


def _opener(bundle: dict[str, Any] | None = None):
    def open_url(request: Any, timeout: int = 30) -> Response:
        if "api.github.com" in request.full_url:
            return Response({"tag_name": "v18.1"})
        return Response(bundle or _bundle())

    return open_url


def test_fetch_live_dataset_parses_stix_bundle() -> None:
    dataset = fetch_live_dataset(opener=_opener(), timeout=1, now="2026-11-25T10:00:00+00:00")

    assert dataset["status"] == "live"
    assert dataset["source_version"] == "18.1"
    assert dataset["tactics"] == ["Credential Access"]
    assert dataset["techniques"]["T9999.001"]["name"] == "Test Technique"
    assert dataset["techniques"]["T9999.001"]["parent"] == "T9999"
    assert dataset["techniques"]["T9999.001"]["reference"].endswith("/T9999/001/")


def test_parse_stix_bundle_rejects_non_bundle() -> None:
    try:
        parse_stix_bundle({"type": "list", "objects": []})
    except ValueError as exc:
        assert "bundle" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_sync_detects_new_techniques_and_deduplicates(tmp_path: Path) -> None:
    cache = tmp_path / "attack_cache.json"
    first = sync_attack_data(
        force=True,
        cache_path=cache,
        opener=_opener(),
        timeout=1,
        now="2026-11-25T10:00:00+00:00",
    )

    assert cache.exists()
    assert first["status"] == "live"
    assert any(
        item["technique_id"] == "T9999.001" and item["change_type"] == "new_technique"
        for item in first["notifications"]
    )

    second = sync_attack_data(
        force=True,
        cache_path=cache,
        opener=_opener(),
        timeout=1,
        now="2026-11-25T10:00:00+00:00",
    )
    assert second["notifications"] == []


def test_sync_falls_back_to_offline_cache(tmp_path: Path) -> None:
    cache = tmp_path / "attack_cache.json"
    sync_attack_data(
        force=True,
        cache_path=cache,
        opener=_opener(),
        timeout=1,
        now="2026-11-25T10:00:00+00:00",
    )

    def broken_opener(_: Any, timeout: int = 30) -> Response:
        raise OSError("network unavailable")

    offline = sync_attack_data(force=True, cache_path=cache, opener=broken_opener, timeout=1)
    assert offline["status"] == "offline_cache"
    assert "network unavailable" in offline["sync_error"]
    assert offline["techniques"]["T9999.001"]["name"] == "Test Technique"


def test_compare_datasets_detects_modified_and_revoked() -> None:
    previous = {
        "techniques": {
            "T1000": {
                "name": "Old name",
                "modified": "2026-01-01",
                "tactics": ["Execution"],
                "status": "active",
            },
            "T1001": {
                "name": "Still active",
                "modified": "2026-01-01",
                "tactics": ["Execution"],
                "status": "active",
            },
        }
    }
    current = {
        "synchronization_timestamp": "2026-11-25T10:00:00+00:00",
        "techniques": {
            "T1000": {
                "name": "New name",
                "modified": "2026-02-01",
                "tactics": ["Execution"],
                "status": "active",
            },
            "T1001": {
                "name": "Still active",
                "modified": "2026-01-01",
                "tactics": ["Execution"],
                "status": "revoked",
                "revoked": True,
            },
        },
    }

    notifications = compare_datasets(previous, current, seen_keys=set())
    changes = {item["technique_id"]: item["change_type"] for item in notifications}

    assert changes["T1000"] == "modified_technique"
    assert changes["T1001"] == "revoked_technique"
