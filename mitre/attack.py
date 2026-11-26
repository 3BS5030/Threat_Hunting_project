"""Dynamic MITRE ATT&CK Enterprise STIX integration with cache and change detection."""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Callable

from urllib.request import Request, urlopen

ROOT_DIR = Path(__file__).resolve().parent.parent
CACHE_PATH = ROOT_DIR / "mitre" / "attack_cache.json"
STATIC_CATALOG_PATH = ROOT_DIR / "hunting" / "attack.json"
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
RELEASE_URL = "https://api.github.com/repos/mitre/cti/releases/latest"
DOMAIN = "enterprise-attack"
DEFAULT_REFRESH_MINUTES = 60


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _fetch(url: str, opener: Callable[..., Any] | None = None, timeout: int = 30) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "VM-Threat-Hunting-Dashboard/1.0",
            "Accept": "application/json",
        },
    )
    response = opener(request, timeout=timeout) if opener else urlopen(request, timeout=timeout)
    with response as handle:
        raw = handle.read()
    return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)


def _external_id(obj: dict[str, Any], prefix: str) -> str:
    for reference in obj.get("external_references", []) or []:
        if not isinstance(reference, dict):
            continue
        if reference.get("source_name") != "mitre-attack":
            continue
        external_id = str(reference.get("external_id", "")).upper()
        if external_id.startswith(prefix):
            return external_id
    return ""


def _reference_url(obj: dict[str, Any]) -> str:
    for reference in obj.get("external_references", []) or []:
        if isinstance(reference, dict) and reference.get("url"):
            return str(reference["url"])
    return ""


def _kill_chain_phases(obj: dict[str, Any]) -> list[str]:
    phases: list[str] = []
    for item in obj.get("kill_chain_phases", []) or []:
        if not isinstance(item, dict):
            continue
        if item.get("kill_chain_name") not in (None, "mitre-attack"):
            continue
        phase = str(item.get("phase_name", ""))
        if phase:
            phases.append(phase)
    return phases


def _is_revoked(obj: dict[str, Any]) -> bool:
    return obj.get("revoked") is True


def _is_deprecated(obj: dict[str, Any]) -> bool:
    return obj.get("x_mitre_deprecated") is True


def _status(obj: dict[str, Any]) -> str:
    if _is_revoked(obj):
        return "revoked"
    if _is_deprecated(obj):
        return "deprecated"
    return "active"


def parse_stix_bundle(
    bundle: Any, source_version: str = "", fetched_at: str | None = None
) -> dict[str, Any]:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError("STIX data: expected a bundle object")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("STIX data: bundle objects must be a list")

    tactic_map: dict[str, str] = {}
    tactics: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "x-mitre-tactic":
            continue
        tactic_id = _external_id(obj, "TA")
        phases = _kill_chain_phases(obj)
        shortname = phases[0] if phases else ""
        if not tactic_id or not shortname:
            continue
        name = str(obj.get("name", ""))
        tactic_map[shortname] = name
        tactics[tactic_id] = {
            "id": tactic_id,
            "name": name,
            "shortname": shortname,
            "description": str(obj.get("description", "")),
            "created": str(obj.get("created", "")),
            "modified": str(obj.get("modified", "")),
            "revoked": _is_revoked(obj),
            "deprecated": _is_deprecated(obj),
            "reference": _reference_url(obj),
        }

    techniques: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        technique_id = _external_id(obj, "T")
        if not technique_id:
            continue
        phases = _kill_chain_phases(obj)
        tactic_names = [tactic_map.get(phase, phase.replace("-", " ").title()) for phase in phases]
        is_subtechnique = obj.get("x_mitre_is_subtechnique") is True
        techniques[technique_id] = {
            "id": technique_id,
            "name": str(obj.get("name", "")),
            "tactic": tactic_names[0] if tactic_names else "",
            "tactics": tactic_names,
            "description": str(obj.get("description", "")),
            "reference": _reference_url(obj),
            "created": str(obj.get("created", "")),
            "modified": str(obj.get("modified", "")),
            "revoked": _is_revoked(obj),
            "deprecated": _is_deprecated(obj),
            "status": _status(obj),
            "is_subtechnique": is_subtechnique,
            "parent": technique_id.rsplit(".", 1)[0] if is_subtechnique else "",
        }

    groups: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "intrusion-set":
            continue
        group_id = _external_id(obj, "G")
        if not group_id:
            continue
        groups[group_id] = {
            "id": group_id,
            "name": str(obj.get("name", "")),
            "aliases": list(obj.get("aliases", []) or []),
            "description": str(obj.get("description", "")),
            "created": str(obj.get("created", "")),
            "modified": str(obj.get("modified", "")),
            "revoked": _is_revoked(obj),
            "deprecated": _is_deprecated(obj),
            "reference": _reference_url(obj),
        }

    software: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") not in ("malware", "tool"):
            continue
        software_id = _external_id(obj, "S")
        if not software_id:
            continue
        software[software_id] = {
            "id": software_id,
            "name": str(obj.get("name", "")),
            "type": obj.get("type"),
            "description": str(obj.get("description", "")),
            "created": str(obj.get("created", "")),
            "modified": str(obj.get("modified", "")),
            "revoked": _is_revoked(obj),
            "deprecated": _is_deprecated(obj),
            "reference": _reference_url(obj),
        }

    if not techniques or not tactic_map:
        raise ValueError("STIX data: no Enterprise techniques or tactics found")
    modified_values = [
        value.get("modified", "")
        for collection in (techniques, tactics, groups, software)
        for value in collection.values()
        if value.get("modified")
    ]
    return {
        "domain": DOMAIN,
        "source": STIX_URL,
        "source_version": source_version,
        "dataset_version": max(modified_values) if modified_values else "",
        "synchronization_timestamp": fetched_at or _utc_now(),
        "tactics": [item["name"] for item in tactics.values()],
        "tactic_metadata": tactics,
        "techniques": techniques,
        "groups": groups,
        "software": software,
        "status": "live",
        "sync_error": "",
        "notifications": [],
        "notification_keys": [],
    }


def _source_version(opener: Callable[..., Any] | None, timeout: int) -> str:
    try:
        payload = json.loads(_fetch(RELEASE_URL, opener, timeout))
    except Exception:
        return ""
    tag = str(payload.get("tag_name", "")) if isinstance(payload, dict) else ""
    match = re.search(r"v?(\d+(?:\.\d+)?)", tag, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def fetch_live_dataset(
    opener: Callable[..., Any] | None = None, timeout: int = 30, now: str | None = None
) -> dict[str, Any]:
    payload = json.loads(_fetch(STIX_URL, opener, timeout))
    version = _source_version(opener, timeout)
    dataset = parse_stix_bundle(payload, source_version=version, fetched_at=now or _utc_now())
    dataset["status"] = "live"
    return dataset


def read_cache(cache_path: str | Path | None = None) -> dict[str, Any] | None:
    path = Path(cache_path) if cache_path else CACHE_PATH
    try:
        cached = _read_json(path)
    except (OSError, ValueError):
        return None
    return cached if isinstance(cached, dict) and isinstance(cached.get("techniques"), dict) else None


def write_cache(dataset: dict[str, Any], cache_path: str | Path | None = None) -> Path:
    path = Path(cache_path) if cache_path else CACHE_PATH
    return _write_json(path, dataset)


def static_catalog() -> dict[str, Any]:
    catalog = _read_json(STATIC_CATALOG_PATH)
    techniques: dict[str, dict[str, Any]] = {}
    for technique_id, source in catalog.get("techniques", {}).items():
        tactics = source.get("tactics") or ([source["tactic"]] if source.get("tactic") else [])
        techniques[technique_id] = {
            "id": technique_id,
            "name": source.get("name", ""),
            "tactic": tactics[0] if tactics else "",
            "tactics": tactics,
            "description": source.get("description", ""),
            "reference": source.get("reference", ""),
            "created": source.get("created", ""),
            "modified": source.get("modified", ""),
            "revoked": bool(source.get("revoked", False)),
            "deprecated": bool(source.get("deprecated", False)),
            "status": source.get("status", "active"),
            "is_subtechnique": "." in technique_id,
            "parent": technique_id.rsplit(".", 1)[0] if "." in technique_id else "",
        }
    return {
        "domain": DOMAIN,
        "source": str(STATIC_CATALOG_PATH),
        "source_version": "",
        "dataset_version": "",
        "synchronization_timestamp": "",
        "tactics": list(catalog.get("tactics", [])),
        "tactic_metadata": {},
        "techniques": techniques,
        "groups": {},
        "software": {},
        "status": "static_migration",
        "sync_error": "",
        "notifications": [],
        "notification_keys": [],
    }


def current_dataset(cache_path: str | Path | None = None) -> dict[str, Any]:
    return read_cache(cache_path) or static_catalog()


def _entry_signature(entry: dict[str, Any]) -> str:
    fields = ("name", "tactic", "tactics", "description", "reference", "modified", "status")
    return json.dumps({key: entry.get(key) for key in fields}, sort_keys=True, ensure_ascii=False)


def compare_datasets(
    previous: dict[str, Any],
    current: dict[str, Any],
    seen_keys: set[str] | None = None,
    detected_at: str | None = None,
) -> list[dict[str, Any]]:
    old_techniques = previous.get("techniques", {}) if isinstance(previous, dict) else {}
    new_techniques = current.get("techniques", {}) if isinstance(current, dict) else {}
    if not isinstance(old_techniques, dict):
        old_techniques = {}
    if not isinstance(new_techniques, dict):
        new_techniques = {}
    seen = set(seen_keys or [])
    if not seen and isinstance(previous, dict):
        seen = set(previous.get("notification_keys", []) or [])
    timestamp = detected_at or current.get("synchronization_timestamp") or _utc_now()
    notifications: list[dict[str, Any]] = []

    def add(technique_id: str, entry: dict[str, Any], change_type: str) -> None:
        key = f"{technique_id}:{change_type}:{entry.get('modified', '')}"
        if key in seen:
            return
        seen.add(key)
        notifications.append(
            {
                "technique_id": technique_id,
                "technique_name": entry.get("name", ""),
                "change_type": change_type,
                "detected_at": timestamp,
                "source_version": current.get("source_version", ""),
                "metadata": {
                    "tactics": entry.get("tactics", []),
                    "modified": entry.get("modified", ""),
                    "reference": entry.get("reference", ""),
                    "status": entry.get("status", ""),
                    "description": entry.get("description", ""),
                },
                "key": key,
            }
        )

    for technique_id, entry in sorted(new_techniques.items()):
        if not isinstance(entry, dict):
            continue
        prior = old_techniques.get(technique_id)
        if not isinstance(prior, dict):
            if not entry.get("revoked") and not entry.get("deprecated"):
                add(technique_id, entry, "new_technique")
            continue
        if entry.get("revoked") and not prior.get("revoked"):
            add(technique_id, entry, "revoked_technique")
        elif entry.get("deprecated") and not prior.get("deprecated"):
            add(technique_id, entry, "deprecated_technique")
        elif entry.get("revoked") or entry.get("deprecated"):
            continue
        elif _entry_signature(entry) != _entry_signature(prior):
            add(technique_id, entry, "modified_technique")
    return notifications


def merge_notifications(
    previous: dict[str, Any], notifications: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    combined: dict[str, dict[str, Any]] = {}
    for item in previous.get("notifications", []) or []:
        if isinstance(item, dict) and item.get("key"):
            combined[item["key"]] = item
    for item in notifications:
        if isinstance(item, dict) and item.get("key"):
            combined[item["key"]] = item
    ordered = sorted(combined.values(), key=lambda item: (item.get("detected_at", ""), item["key"]))
    return ordered, [item["key"] for item in ordered]


def _cache_age_minutes(cached: dict[str, Any], now: dt.datetime) -> float | None:
    timestamp = cached.get("synchronization_timestamp")
    if not timestamp:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(timestamp))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return (now - parsed).total_seconds() / 60


def sync_attack_data(
    force: bool = False,
    refresh_minutes: int = DEFAULT_REFRESH_MINUTES,
    cache_path: str | Path | None = None,
    opener: Callable[..., Any] | None = None,
    timeout: int = 30,
    now: str | None = None,
) -> dict[str, Any]:
    path = Path(cache_path) if cache_path else CACHE_PATH
    cached = read_cache(path)
    current_time = dt.datetime.now(dt.timezone.utc)
    if not force and cached and cached.get("status") == "live":
        age = _cache_age_minutes(cached, current_time)
        if age is not None and age <= refresh_minutes:
            result = dict(cached)
            result["status"] = "cache"
            result["notifications"] = []
            return result

    previous = cached or static_catalog()
    try:
        live = fetch_live_dataset(opener=opener, timeout=timeout, now=now)
        notifications = compare_datasets(previous, live, detected_at=live["synchronization_timestamp"])
        history, keys = merge_notifications(previous, notifications)
        live["notifications"] = notifications
        live["all_notifications"] = history
        live["notification_keys"] = keys
        write_cache(live, path)
        return live
    except Exception as exc:
        if cached:
            offline = dict(cached)
            offline["status"] = "offline_cache"
            offline["sync_error"] = f"{type(exc).__name__}: {exc}"
            offline["notifications"] = []
            return offline
        fallback = static_catalog()
        fallback["status"] = "unavailable"
        fallback["sync_error"] = f"{type(exc).__name__}: {exc}"
        return fallback


def sync_if_due(
    refresh_minutes: int = DEFAULT_REFRESH_MINUTES,
    cache_path: str | Path | None = None,
    opener: Callable[..., Any] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    return sync_attack_data(
        force=False,
        refresh_minutes=refresh_minutes,
        cache_path=cache_path,
        opener=opener,
        timeout=timeout,
    )


def attack_version(dataset: dict[str, Any]) -> str:
    return str(dataset.get("source_version") or dataset.get("dataset_version") or "")
