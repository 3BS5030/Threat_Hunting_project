"""Load, validate, and evaluate the detection rule pack."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterable

from hunting import colleague_rule_engine as _colleague
from hunting.checks import DATA_KEYS, SEVERITY_RANK

RULES_PATH = Path(__file__).with_name("rules.json")
ADVANCED_RULES_PATH = Path(__file__).resolve().parent.parent / "log collection" / "rules.json"
ATTACK_PATH = Path(__file__).with_name("attack.json")
REQUIRED_RULE_FIELDS = ("id", "target", "pattern", "technique", "severity", "tests")
DETECTION_TYPES = {
    "regex",
    "threshold",
    "time_window",
    "sequence_correlation",
    "baseline_comparison",
}


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _rule_pack(path: str | Path | None = None) -> dict[str, Any]:
    return _read_json(Path(path) if path else RULES_PATH)


def _allowed_targets(path: str | Path | None = None) -> set[str]:
    targets = set(DATA_KEYS)
    schema = _rule_pack(path).get("schema", {})
    field = schema.get("fields", {}).get("log_source", {})
    allowed = field.get("allowed") if isinstance(field, dict) else None
    if isinstance(allowed, list):
        targets.update(str(item) for item in allowed)
    return targets


def _colleague_load_rules(
    path: str | Path | None = None, include_disabled: bool = False
) -> dict[str, Any]:
    target = str(path) if path is not None else str(ADVANCED_RULES_PATH)
    result = _colleague.load_rules(target, include_disabled=include_disabled)
    if path is not None and any(
        "root must be a JSON array" in str(item.get("error", ""))
        for item in result.get("errors", [])
    ):
        result = _colleague.load_rules(
            str(ADVANCED_RULES_PATH), include_disabled=include_disabled
        )
    return result


def load_rules(
    path: str | Path | None = None,
    validate: bool = False,
    include_disabled: bool = False,
) -> Any:
    if path is not None or include_disabled:
        return _colleague_load_rules(path, include_disabled)
    rules = list(_rule_pack().get("rules", []))
    if validate:
        issues = validate_rules(rules, targets=_allowed_targets())
        if issues:
            raise ValueError("invalid rules: " + "; ".join(issues))
    return rules


def load_attack(
    path: str | Path | None = None,
    validate: bool = False,
    refresh: bool = False,
    cache_path: str | Path | None = None,
) -> dict[str, Any]:
    if path is not None:
        attack = _read_json(Path(path))
    elif refresh:
        from mitre.attack import sync_attack_data

        attack = sync_attack_data(force=True, cache_path=cache_path)
    else:
        from mitre.attack import current_dataset

        attack = current_dataset(cache_path)
    if validate:
        issues = validate_attack(attack)
        if issues:
            raise ValueError("invalid attack metadata: " + "; ".join(issues))
    return attack


def _first(rule: dict[str, Any], canonical: str, legacy: str) -> Any:
    if canonical in rule:
        return rule[canonical]
    return rule.get(legacy)


def _rule_id(rule: dict[str, Any]) -> str:
    return str(_first(rule, "rule_id", "id") or "UNNAMED")


def _rule_target(rule: dict[str, Any]) -> str:
    return str(_first(rule, "log_source", "target") or "processes")


def _rule_pattern(rule: dict[str, Any]) -> str:
    return str(_first(rule, "regex_pattern", "pattern") or "")


def _rule_techniques(rule: dict[str, Any]) -> list[str]:
    values = rule.get("mitre_techniques")
    if not isinstance(values, list) or not values:
        legacy = rule.get("technique")
        values = [legacy] if legacy else []
    result: list[str] = []
    for value in values:
        technique = str(value).strip().upper()
        if technique and technique not in result:
            result.append(technique)
    return result


def _is_enabled(rule: dict[str, Any]) -> bool:
    return rule.get("enabled", True) is not False


def _detection_type(rule: dict[str, Any]) -> str:
    return str(rule.get("detection_type") or "regex")


def compile_rule(rule: dict[str, Any]) -> re.Pattern[str]:
    return re.compile(_rule_pattern(rule))


def validate_rules(
    rules: list[dict[str, Any]] | None = None,
    attack: dict[str, Any] | None = None,
    targets: Iterable[str] | None = None,
) -> list[str]:
    if rules is None:
        rules = load_rules()
    if attack is None:
        attack = load_attack()
    if not isinstance(attack, dict):
        return ["attack metadata: expected an object"]
    allowed_targets = set(targets if targets is not None else _allowed_targets())
    techniques = attack.get("techniques", {})
    issues: list[str] = []
    seen: set[str] = set()

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            issues.append(f"#{index}: rule is not an object")
            continue
        label = _rule_id(rule)
        for field in REQUIRED_RULE_FIELDS:
            if field not in rule:
                issues.append(f"{label}: missing field {field}")
        if label in seen:
            issues.append(f"{label}: duplicate rule id")
        seen.add(label)

        target = _rule_target(rule)
        if target not in allowed_targets:
            issues.append(f"{label}: unsupported target {target!r}")
        severity = rule.get("severity")
        if severity not in SEVERITY_RANK:
            issues.append(f"{label}: unsupported severity {severity!r}")
        for technique in _rule_techniques(rule):
            if technique not in techniques:
                issues.append(f"{label}: unknown technique {technique!r}")
        if _detection_type(rule) not in DETECTION_TYPES:
            issues.append(f"{label}: unsupported detection type {_detection_type(rule)!r}")

        aliases = (
            ("rule_id", "id"),
            ("log_source", "target"),
            ("regex_pattern", "pattern"),
        )
        for canonical, legacy in aliases:
            if canonical in rule and legacy in rule and rule[canonical] != rule[legacy]:
                issues.append(f"{label}: {canonical} and {legacy} disagree")
        canonical_techniques = rule.get("mitre_techniques")
        if isinstance(canonical_techniques, list) and canonical_techniques:
            if rule.get("technique") != canonical_techniques[0]:
                issues.append(f"{label}: legacy technique must match the first canonical technique")
        threshold = rule.get("threshold", 1)
        if not isinstance(threshold, int) or threshold < 1:
            issues.append(f"{label}: threshold must be a positive integer")
        window = rule.get("time_window_minutes", 0)
        if not isinstance(window, int) or window < 0:
            issues.append(f"{label}: time_window_minutes must be non-negative")

        try:
            compile_rule(rule)
        except (KeyError, TypeError, re.error) as exc:
            issues.append(f"{label}: invalid pattern: {exc}")

        cases = rule.get("tests", [])
        if not isinstance(cases, list):
            issues.append(f"{label}: tests is not a list")
            continue
        for case_index, case in enumerate(cases):
            if not isinstance(case, dict):
                issues.append(f"{label}: test #{case_index} is not an object")
            elif "text" not in case or not isinstance(case.get("expect"), bool):
                issues.append(f"{label}: test #{case_index} needs text and boolean expect")

    return issues


def validate_attack(attack: dict[str, Any] | None = None) -> list[str]:
    attack = attack if attack is not None else load_attack()
    issues: list[str] = []
    tactics = attack.get("tactics", [])
    techniques = attack.get("techniques", {})
    if not isinstance(tactics, list):
        issues.append("tactics: expected a list")
    if not isinstance(techniques, dict):
        issues.append("techniques: expected an object")
        return issues
    valid_tactics = set(str(item) for item in tactics) if isinstance(tactics, list) else set()
    for technique_id, technique in techniques.items():
        if not isinstance(technique, dict):
            issues.append(f"{technique_id}: technique is not an object")
            continue
        if not isinstance(technique.get("name"), str) or not technique["name"]:
            issues.append(f"{technique_id}: missing name")
        tactic_values = technique.get("tactics")
        if not isinstance(tactic_values, list) or not tactic_values:
            tactic_values = [technique.get("tactic")]
        if not tactic_values or not all(isinstance(item, str) and item for item in tactic_values):
            issues.append(f"{technique_id}: missing tactic")
            continue
        if valid_tactics:
            for tactic in tactic_values:
                if tactic not in valid_tactics:
                    issues.append(f"{technique_id}: tactic {tactic!r} is not listed")
    return issues


def _line_text(event: Any) -> str:
    if isinstance(event, dict):
        return str(event.get("raw") or event.get("text") or event.get("normalized_line") or "")
    return str(event)


def _field(event: Any, match: re.Match[str] | None, name: str) -> Any:
    source = event if isinstance(event, dict) else {}
    if name in source and source[name] not in (None, ""):
        return source[name]
    if match:
        groups = match.groupdict()
        if name in groups and groups[name] not in (None, ""):
            return groups[name]
    lowered = name.lower()
    for key, value in source.items():
        if key.lower() == lowered and value not in (None, ""):
            return value
    if lowered == "user":
        for key in ("username", "auth_user", "command_user"):
            if source.get(key) not in (None, ""):
                return source[key]
    return ""


def _event_fields(event: Any, match: re.Match[str] | None) -> dict[str, Any]:
    fields: dict[str, Any] = dict(event) if isinstance(event, dict) else {}
    if match:
        fields.update({key: value for key, value in match.groupdict().items() if value not in (None, "")})
    return fields


def _parse_timestamp(value: Any) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if not value:
        return None
    text = str(value)
    try:
        parsed = dt.datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        pass
    for fmt in ("%b %d %H:%M:%S", "%Y %b %d %H:%M:%S"):
        try:
            parsed = dt.datetime.strptime(text, fmt)
            if "%Y" not in fmt:
                parsed = parsed.replace(year=dt.datetime.now(dt.timezone.utc).year)
            return parsed.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


def _timestamp_of(event: Any, match: re.Match[str] | None) -> dt.datetime | None:
    fields = _event_fields(event, match)
    for key in ("normalized_timestamp", "timestamp", "event_timestamp"):
        parsed = _parse_timestamp(fields.get(key))
        if parsed:
            return parsed
    return None


def _raw_timestamp(fields: dict[str, Any]) -> str:
    for key in ("timestamp", "normalized_timestamp", "event_timestamp"):
        if fields.get(key):
            return str(fields[key])
    return ""


def _group_key(rule: dict[str, Any], fields: dict[str, Any]) -> str:
    configured = rule.get("group_by")
    names = configured if isinstance(configured, list) and configured else ["source_ip", "username"]
    parts: list[str] = []
    for name in names:
        value = _field(fields, None, str(name))
        if value not in (None, ""):
            parts.append(f"{name}={value}")
    return "|".join(parts) or "__all__"


def _internal_ip(value: str, ranges: list[Any]) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    for item in ranges:
        try:
            if address in ipaddress.ip_network(str(item), strict=False):
                return True
        except ValueError:
            continue
    return False


def _severity(rule: dict[str, Any], base: str, fields: dict[str, Any], baseline: dict[str, Any], count: int) -> str:
    mapping = rule.get("severity_map")
    if not isinstance(mapping, dict):
        return base
    threshold = rule.get("threshold", 1) if isinstance(rule.get("threshold", 1), int) else 1
    internal_ranges = baseline.get("allowed_internal_ip_ranges", [])
    internal_ranges = internal_ranges if isinstance(internal_ranges, list) else []
    source_ip = str(fields.get("source_ip", ""))
    values = {str(value).lower() for value in fields.values() if isinstance(value, (str, int, float))}
    privileged_groups = {str(item).lower() for item in rule.get("privileged_groups", []) or []}
    for key, value in mapping.items():
        if value not in SEVERITY_RANK:
            continue
        lowered = str(key).lower()
        if lowered == "external" and source_ip and not _internal_ip(source_ip, internal_ranges):
            return str(value)
        if lowered == "internal" and source_ip and _internal_ip(source_ip, internal_ranges):
            return str(value)
        if lowered == "unauthorized" and fields.get("unauthorized"):
            return str(value)
        if lowered == "privileged" and (
            fields.get("privileged")
            or str(fields.get("groupname", "")).lower() in privileged_groups
            or str(fields.get("gpasswd_group", "")).lower() in privileged_groups
        ):
            return str(value)
        if lowered == "repeated_auth_failure" and count >= threshold:
            return str(value)
        if lowered in values:
            return str(value)
    return base


def _technique_metadata(technique_id: str, attack: dict[str, Any]) -> dict[str, Any]:
    techniques = attack.get("techniques", {}) if isinstance(attack, dict) else {}
    entry = techniques.get(technique_id, {}) if isinstance(techniques, dict) else {}
    entry = entry if isinstance(entry, dict) else {}
    tactics = entry.get("tactics")
    if not isinstance(tactics, list) or not tactics:
        tactics = [entry.get("tactic")] if entry.get("tactic") else []
    return {
        "id": technique_id,
        "name": entry.get("name", ""),
        "tactic": entry.get("tactic", ""),
        "tactics": tactics,
        "description": entry.get("description", ""),
        "reference": entry.get("reference", ""),
        "status": entry.get("status", "active"),
        "modified": entry.get("modified", ""),
        "resolved": bool(entry),
    }


def _make_finding(
    rule: dict[str, Any],
    attack: dict[str, Any],
    baseline: dict[str, Any],
    events: list[Any],
    matches: list[re.Match[str] | None],
    fields: dict[str, Any],
    count: int,
) -> dict[str, Any]:
    technique_ids = _rule_techniques(rule)
    primary = technique_ids[0] if technique_ids else ""
    metadata = [_technique_metadata(item, attack) for item in technique_ids]
    timestamp = _raw_timestamp(fields)
    evidence_events = [item for item in events if _line_text(item)]
    evidence = _line_text(evidence_events[-1]) if evidence_events else ""
    groups = {
        key: value
        for key, value in fields.items()
        if isinstance(value, (str, int, float, bool)) and value not in (None, "")
    }
    match_text = ""
    for match in reversed(matches):
        if match:
            match_text = match.group(0)
            break
    severity = _severity(rule, str(rule.get("severity", "info")), fields, baseline, count)
    return {
        "rule": _rule_id(rule),
        "description": rule.get("description", ""),
        "severity": severity,
        "technique": primary,
        "techniques": technique_ids,
        "technique_name": metadata[0].get("name", "") if metadata else "",
        "technique_metadata": metadata,
        "tactic": metadata[0].get("tactic", "") if metadata else "",
        "target": _rule_target(rule),
        "evidence": evidence[:500],
        "events": [_line_text(item)[:500] for item in evidence_events],
        "match": match_text[:200],
        "groups": groups,
        "named_groups": groups,
        "event_type": str(fields.get("event_type", "")),
        "event_timestamp": timestamp,
        "timestamp": timestamp,
        "detection_timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "detection_type": _detection_type(rule),
        "match_count": count,
        "mitre_status": attack.get("status", "") if isinstance(attack, dict) else "",
        "mitre_source_version": attack.get("source_version", "") if isinstance(attack, dict) else "",
        "source": "rule",
    }


def _regex_matches(rule: dict[str, Any], data: dict[str, Iterable[Any]]) -> list[tuple[Any, re.Match[str]]]:
    pattern = compile_rule(rule)
    matches: list[tuple[Any, re.Match[str]]] = []
    for event in data.get(_rule_target(rule), []) or []:
        match = pattern.search(_line_text(event))
        if match:
            matches.append((event, match))
    return matches


def _classified_fields(rule: dict[str, Any], fields: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    result = dict(fields)
    users: set[str] = set()
    for key in rule.get("baseline_keys", []) or []:
        values = baseline.get(str(key), [])
        if isinstance(values, list):
            users.update(str(item).lower() for item in values)
    if "users" not in (rule.get("baseline_keys") or []):
        users.update(str(item).lower() for item in baseline.get("users", []) or [])
    user = _field(result, None, "username") or _field(result, None, "auth_user") or _field(result, None, "command_user")
    user_text = str(user)
    if user_text:
        if user_text.lower() in users:
            result["baseline_classification"] = "trusted"
            result["unauthorized"] = False
        elif users:
            result["baseline_classification"] = "untrusted"
            result["unauthorized"] = True
        else:
            result["baseline_classification"] = "unknown"
            result["unauthorized"] = False
    else:
        result["baseline_classification"] = "unknown"
    privileged = {str(item).lower() for item in rule.get("privileged_groups", []) or []}
    group = str(_field(result, None, "groupname") or _field(result, None, "gpasswd_group"))
    if group.lower() in privileged:
        result["privileged"] = True
    return result


def _baseline_matches(
    rule: dict[str, Any], data: dict[str, Iterable[Any]], baseline: dict[str, Any]
) -> list[tuple[Any, re.Match[str] | None]]:
    matches: list[tuple[Any, re.Match[str] | None]] = []
    for event in data.get(_rule_target(rule), []) or []:
        fields = _classified_fields(rule, _event_fields(event, None), baseline)
        unauthorized = fields.get("unauthorized") is True
        privileged = fields.get("privileged") is True
        expected_cron = str(event.get("event_type", "")) == "scheduled_task" if isinstance(event, dict) else False
        if unauthorized or privileged or expected_cron:
            matches.append((event, None))
    return matches


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    unique: list[dict[str, Any]] = []
    for finding in findings:
        key = (
            finding.get("rule"),
            finding.get("target"),
            finding.get("evidence"),
            tuple(finding.get("techniques", [])),
            finding.get("event_timestamp"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _emit_matches(
    rule: dict[str, Any],
    matches: list[tuple[Any, re.Match[str] | None]],
    attack: dict[str, Any],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    detection_type = _detection_type(rule)
    threshold = rule.get("threshold", 1) if isinstance(rule.get("threshold", 1), int) else 1
    window_minutes = rule.get("time_window_minutes", 0) if isinstance(rule.get("time_window_minutes", 0), int) else 0

    prepared: list[tuple[dt.datetime | None, Any, re.Match[str] | None, dict[str, Any], str]] = []
    for event, match in matches:
        fields = _classified_fields(rule, _event_fields(event, match), baseline)
        prepared.append((_timestamp_of(event, match), event, match, fields, _group_key(rule, fields)))

    if detection_type == "regex":
        for _timestamp, event, match, fields, _key in prepared:
            findings.append(_make_finding(rule, attack, baseline, [event], [match], fields, 1))
        return findings

    grouped: dict[str, list[tuple[dt.datetime | None, Any, re.Match[str] | None, dict[str, Any]]]] = {}
    for timestamp, event, match, fields, key in prepared:
        grouped.setdefault(key, []).append((timestamp, event, match, fields))

    for items in grouped.values():
        ordered = sorted(items, key=lambda item: item[0] or dt.datetime.max.replace(tzinfo=dt.timezone.utc))
        if detection_type == "threshold":
            if len(ordered) < threshold:
                continue
            selected = ordered
        else:
            selected = []
            index = 0
            while index < len(ordered):
                window_end = ordered[index][0]
                candidate: list[tuple[dt.datetime | None, Any, re.Match[str] | None, dict[str, Any]]] = []
                cursor = index
                while cursor < len(ordered):
                    current_time = ordered[cursor][0]
                    if window_end and current_time:
                        if (current_time - window_end).total_seconds() / 60 > window_minutes:
                            break
                    candidate.append(ordered[cursor])
                    cursor += 1
                if len(candidate) >= threshold:
                    selected = candidate
                    index = cursor
                    break
                index += 1
            if not selected:
                continue
        events = [item[1] for item in selected]
        match_objects = [item[2] for item in selected]
        fields = dict(selected[-1][3])
        fields["match_count"] = len(selected)
        findings.append(
            _make_finding(rule, attack, baseline, events, match_objects, fields, len(selected))
        )
    return findings


def _sequence_findings(
    rule: dict[str, Any],
    data: dict[str, Iterable[Any]],
    attack: dict[str, Any],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    correlation = rule.get("correlation") if isinstance(rule.get("correlation"), dict) else {}
    preceding_pattern_value = str(correlation.get("preceding_pattern", ""))
    if not preceding_pattern_value:
        return []
    try:
        preceding_pattern = re.compile(preceding_pattern_value)
    except re.error:
        return []
    preceding_threshold = correlation.get("preceding_threshold", 1)
    if not isinstance(preceding_threshold, int) or preceding_threshold < 1:
        preceding_threshold = 1
    window_minutes = correlation.get("time_window_minutes", rule.get("time_window_minutes", 0))
    if not isinstance(window_minutes, int) or window_minutes < 0:
        window_minutes = 0
    group_names = correlation.get("group_by") or rule.get("group_by") or ["source_ip"]

    all_events = list(data.get(_rule_target(rule), []) or [])
    preceding: dict[str, list[tuple[dt.datetime | None, Any, dict[str, Any]]]] = {}
    for event in all_events:
        match = preceding_pattern.search(_line_text(event))
        if not match:
            continue
        fields = _event_fields(event, match)
        grouped_rule = dict(rule)
        grouped_rule["group_by"] = group_names
        key = _group_key(grouped_rule, fields)
        preceding.setdefault(key, []).append((_timestamp_of(event, match), event, fields))

    findings: list[dict[str, Any]] = []
    for event, match in _regex_matches(rule, data):
        fields = _classified_fields(rule, _event_fields(event, match), baseline)
        grouped_rule = dict(rule)
        grouped_rule["group_by"] = group_names
        key = _group_key(grouped_rule, fields)
        success_time = _timestamp_of(event, match)
        candidates = [
            item
            for item in preceding.get(key, [])
            if success_time is None
            or item[0] is None
            or 0 <= (success_time - item[0]).total_seconds() / 60 <= window_minutes
        ]
        if len(candidates) < preceding_threshold:
            continue
        all_related = [item[1] for item in candidates] + [event]
        combined_fields = dict(fields)
        combined_fields["preceding_count"] = len(candidates)
        combined_fields["unauthorized"] = True
        findings.append(
            _make_finding(rule, attack, baseline, all_related, [match], combined_fields, len(candidates))
        )
    return findings


def run_rules(
    data: dict[str, Iterable[Any]],
    rules: list[dict[str, Any]] | None = None,
    attack: dict[str, Any] | None = None,
    baseline: dict[str, Any] | None = None,
    errors: list[str] | None = None,
) -> list[dict[str, Any]]:
    active_rules = rules if rules is not None else load_rules()
    attack = attack if attack is not None else load_attack()
    baseline = baseline or {}
    error_list = errors if errors is not None else []
    findings: list[dict[str, Any]] = []

    for rule in active_rules:
        label = _rule_id(rule)
        try:
            if not isinstance(rule, dict) or not _is_enabled(rule):
                continue
            detection_type = _detection_type(rule)
            if detection_type == "sequence_correlation":
                findings.extend(_sequence_findings(rule, data, attack, baseline))
            elif detection_type == "baseline_comparison":
                findings.extend(_emit_matches(rule, _baseline_matches(rule, data, baseline), attack, baseline))
            elif detection_type in ("regex", "threshold", "time_window"):
                findings.extend(_emit_matches(rule, _regex_matches(rule, data), attack, baseline))
            else:
                error_list.append(f"{label}: unsupported detection type {detection_type!r}")
        except Exception as exc:
            error_list.append(f"{label}: {type(exc).__name__}: {exc}")
            continue

    return _dedupe_findings(findings)


def run_rule_tests(rules: list[dict[str, Any]] | None = None) -> Any:
    active_rules = rules if rules is not None else load_rules()
    if any(
        isinstance(item, dict) and isinstance(item.get("tests"), dict)
        for item in active_rules
    ):
        return _colleague.run_rule_tests(active_rules)
    results: list[dict[str, Any]] = []
    for rule in active_rules:
        pattern = compile_rule(rule)
        for case_index, case in enumerate(rule.get("tests", [])):
            matched = bool(pattern.search(str(case.get("text", ""))))
            results.append(
                {
                    "rule": _rule_id(rule),
                    "case": case_index,
                    "text": case.get("text", ""),
                    "expected": case.get("expect"),
                    "matched": matched,
                    "passed": matched == case.get("expect"),
                }
            )
    return results


def advanced_rule_findings(
    data: dict[str, Iterable[Any]],
    attack: dict[str, Any] | None = None,
    skip_rule_ids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    active_attack = attack if attack is not None else load_attack()
    skipped_ids = set(skip_rule_ids or set())
    loaded = _colleague_load_rules()
    errors = [
        f"advanced rules: {item.get('error')}"
        for item in loaded.get("errors", [])
        if item.get("error")
    ]
    rules = [
        rule
        for rule in loaded.get("rules", [])
        if str(rule.get("id", "")) not in skipped_ids
    ]
    logs = {
        str(key): list(data.get(key, []) or [])
        for key in _colleague.VALID_LOG_TYPES
    }
    evaluated = _colleague.evaluate_all(rules, logs)
    errors.extend(
        f"advanced {item.get('rule_id')}: {item.get('error')}"
        for item in evaluated.get("errors", [])
        if item.get("error")
    )

    findings: list[dict[str, Any]] = []
    for rule in rules:
        rule_id = str(rule.get("id", "ADVANCED"))
        result = evaluated.get("results", {}).get(rule_id, {})
        for hit in result.get("hits", []):
            technique_ids = [str(item) for item in rule.get("mitre", []) if item]
            primary = technique_ids[0] if technique_ids else ""
            metadata = [_technique_metadata(item, active_attack) for item in technique_ids]
            evidence_lines = [str(item) for item in hit.get("evidence", [])]
            timestamp = str(hit.get("first_seen") or "")
            severity = str(hit.get("severity", "MEDIUM")).lower()
            if severity not in SEVERITY_RANK:
                severity = "info"
            groups = {
                str(key): value
                for key, value in dict(hit.get("groups", {}) or {}).items()
                if isinstance(value, (str, int, float, bool)) and value not in (None, "")
            }
            findings.append(
                {
                    "rule": rule_id,
                    "description": str(rule.get("description", "")),
                    "severity": severity,
                    "technique": primary,
                    "techniques": technique_ids,
                    "technique_name": metadata[0].get("name", "") if metadata else "",
                    "technique_metadata": metadata,
                    "tactic": metadata[0].get("tactic", "") if metadata else "",
                    "target": str(rule.get("log_type", "")),
                    "evidence": "\n".join(evidence_lines)[:500],
                    "events": [item[:500] for item in evidence_lines],
                    "match": evidence_lines[0][:200] if evidence_lines else "",
                    "groups": groups,
                    "named_groups": groups,
                    "event_type": "",
                    "event_timestamp": timestamp,
                    "timestamp": timestamp,
                    "detection_timestamp": dt.datetime.now(
                        dt.timezone.utc
                    ).isoformat(timespec="seconds"),
                    "detection_type": "threshold"
                    if int(hit.get("count", 1)) > 1
                    else "regex",
                    "match_count": int(hit.get("count", 1)),
                    "mitre_status": active_attack.get("status", "")
                    if isinstance(active_attack, dict)
                    else "",
                    "mitre_source_version": active_attack.get("source_version", "")
                    if isinstance(active_attack, dict)
                    else "",
                    "source": "advanced_rule_engine",
                }
            )
    return _dedupe_findings(findings), errors


parse_timestamp = _colleague.parse_timestamp
apply_rule = _colleague.apply_rule
group_and_window = _colleague.group_and_window
evaluate_rule = _colleague.evaluate_rule
evaluate_all = _colleague.evaluate_all
get_rules_for_check = _colleague.get_rules_for_check
get_rule = _colleague.get_rule
validate_mitre_ids = _colleague.validate_mitre_ids
coverage_summary = _colleague.coverage_summary
_is_ip_internal = _colleague._is_ip_internal
