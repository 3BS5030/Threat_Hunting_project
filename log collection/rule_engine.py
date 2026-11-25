"""Rule Engine for VM Threat Hunting Dashboard.

Implements regex-based detection rule loading, compilation, timestamp extraction,
sliding window evaluation, threshold grouping, internal network detection, and test execution.
Designed according to strict functional programming guidelines (no custom classes).
"""

import argparse
from datetime import datetime, timedelta
import ipaddress
import json
import logging
from pathlib import Path
import re
import shlex
import sys
from typing import Any

logger = logging.getLogger(__name__)

# Heuristic patterns for catastrophic backtracking regexes (nested quantifiers)
_CATASTROPHIC_RE = re.compile(r"\([^)]*[\*\+][^)]*\)[\*\+]")
_ID_PATTERN = re.compile(r"^[A-Z]{3}-[A-Z]{2,4}-\d{3}$")
_MITRE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

VALID_LOG_TYPES = {
    "auth",
    "syslog",
    "audit",
    "cron",
    "package",
    "history",
    "web_access",
    "web_error",
    "windows_security",
    "windows_powershell",
    "windows_system",
}

VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}

DEFAULT_INTERNAL_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
]

# Regex for timestamps in logs
_AUDITD_RE = re.compile(r"msg=audit\((\d+(?:\.\d+)?):")
_ISO8601_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)
_SYSLOG_RE = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def load_rules(path: str = "hunting/rules.json", include_disabled: bool = False) -> dict[str, Any]:
    """Load and validate detection rules from a JSON file.

    Input:
        path (str): File path to rules.json.
        include_disabled (bool): Whether to include rules with "enabled": false.

    Output:
        dict: {
            "rules": list of validated rule dicts with compiled regex in "_re",
            "errors": list of dicts [{"id": str|None, "error": str}]
        }
    """
    rule_path = Path(path)
    if not rule_path.is_file():
        err_msg = f"Rules file not found: {path}"
        logger.error(err_msg)
        return {"rules": [], "errors": [{"id": None, "error": err_msg}]}

    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as exc:
        err_msg = f"Failed to parse JSON in {path}: {exc}"
        logger.error(err_msg)
        return {"rules": [], "errors": [{"id": None, "error": err_msg}]}

    if not isinstance(raw_data, list):
        err_msg = "Rules file root must be a JSON array of rule objects"
        logger.error(err_msg)
        return {"rules": [], "errors": [{"id": None, "error": err_msg}]}

    loaded_rules: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for idx, raw_rule in enumerate(raw_data):
        if not isinstance(raw_rule, dict):
            errors.append({"id": None, "error": f"Rule at index {idx} is not a dictionary"})
            continue

        rule_id = raw_rule.get("id")
        if not rule_id or not isinstance(rule_id, str):
            errors.append({"id": None, "error": f"Rule at index {idx} missing valid 'id'"})
            continue

        if not _ID_PATTERN.match(rule_id):
            errors.append({"id": rule_id, "error": f"Rule id '{rule_id}' does not match pattern ^[A-Z]{{3}}-[A-Z]{{2,4}}-\\d{{3}}$"})
            continue

        if rule_id in seen_ids:
            errors.append({"id": rule_id, "error": f"Duplicate rule id '{rule_id}'"})
            continue
        seen_ids.add(rule_id)

        # Validate required fields
        title = raw_rule.get("title")
        if not title or not isinstance(title, str):
            errors.append({"id": rule_id, "error": "Missing or invalid 'title'"})
            continue

        log_type = raw_rule.get("log_type")
        if log_type not in VALID_LOG_TYPES:
            errors.append({"id": rule_id, "error": f"Invalid log_type '{log_type}'. Must be one of {sorted(VALID_LOG_TYPES)}"})
            continue

        severity = raw_rule.get("severity")
        if severity not in VALID_SEVERITIES:
            errors.append({"id": rule_id, "error": f"Invalid severity '{severity}'. Must be one of {sorted(VALID_SEVERITIES)}"})
            continue

        sev_internal = raw_rule.get("severity_internal")
        if sev_internal is not None and sev_internal not in VALID_SEVERITIES:
            errors.append({"id": rule_id, "error": f"Invalid severity_internal '{sev_internal}'"})
            continue

        mitre_list = raw_rule.get("mitre")
        if not isinstance(mitre_list, list) or len(mitre_list) == 0:
            errors.append({"id": rule_id, "error": "'mitre' must be a non-empty list of ATT&CK IDs"})
            continue

        bad_mitre = [m for m in mitre_list if not isinstance(m, str) or not _MITRE_PATTERN.match(m)]
        if bad_mitre:
            errors.append({"id": rule_id, "error": f"Invalid MITRE ATT&CK ID format: {bad_mitre}"})
            continue

        raw_regex = raw_rule.get("regex")
        if not raw_regex or not isinstance(raw_regex, str):
            errors.append({"id": rule_id, "error": "Missing or invalid 'regex'"})
            continue

        if len(raw_regex) > 1000:
            errors.append({"id": rule_id, "error": f"Regex exceeds maximum length of 1000 chars ({len(raw_regex)} chars)"})
            continue

        # Heuristic check for catastrophic backtracking
        if _CATASTROPHIC_RE.search(raw_regex):
            errors.append({"id": rule_id, "error": f"Regex rejected: potential catastrophic backtracking pattern detected"})
            continue

        # Flags
        flags = 0
        rule_flags = raw_rule.get("flags", [])
        if isinstance(rule_flags, list):
            for flag_name in rule_flags:
                if flag_name == "IGNORECASE":
                    flags |= re.IGNORECASE
                elif flag_name == "MULTILINE":
                    flags |= re.MULTILINE
                elif flag_name == "DOTALL":
                    flags |= re.DOTALL

        try:
            compiled_re = re.compile(raw_regex, flags)
        except re.error as r_err:
            errors.append({"id": rule_id, "error": f"Failed to compile regex: {r_err}"})
            continue

        # Validate named groups for group_by and count_distinct
        named_groups = set(compiled_re.groupindex.keys())
        group_by = raw_rule.get("group_by")
        if group_by is not None and group_by not in named_groups:
            errors.append({"id": rule_id, "error": f"group_by '{group_by}' is not a named group in the regex: {named_groups}"})
            continue

        count_distinct = raw_rule.get("count_distinct")
        if count_distinct is not None and count_distinct not in named_groups:
            errors.append({"id": rule_id, "error": f"count_distinct '{count_distinct}' is not a named group in the regex: {named_groups}"})
            continue

        threshold = raw_rule.get("threshold", 1)
        if not isinstance(threshold, int) or threshold < 1:
            errors.append({"id": rule_id, "error": f"threshold must be an integer >= 1 (got {threshold})"})
            continue

        window_minutes = raw_rule.get("window_minutes")
        if window_minutes is not None and (not isinstance(window_minutes, int) or window_minutes < 1):
            errors.append({"id": rule_id, "error": f"window_minutes must be an integer >= 1 or null (got {window_minutes})"})
            continue

        enabled = raw_rule.get("enabled", True)
        if not enabled and not include_disabled:
            continue

        # Copy rule and store compiled pattern
        valid_rule = dict(raw_rule)
        valid_rule["_re"] = compiled_re
        loaded_rules.append(valid_rule)

    return {"rules": loaded_rules, "errors": errors}


def parse_timestamp(line: str, now: datetime | None = None) -> datetime | None:
    """Parse timestamp from a log line with strict anchoring.

    Order of parsing:
    1. ISO‑8601 timestamps **only when they appear at the very start** of the line.
       This prevents attacker‑controlled strings in the message body (e.g. a username
       that looks like a timestamp) from being mistakenly used.
    2. Syslog timestamps that appear at the start of the line (e.g. "Jan 15 03:41:09").
    3. Auditd epoch timestamps, but only when the line begins with ``type=``
       (the typical auditd log prefix).
    The function returns a naive ``datetime`` object in the local timezone.
    """
    if not line:
        return None

    # Limit length for safety and performance
    snippet = line[:4096]
    ref_now = now or datetime.now()

    # 1. ISO‑8601 at line start
    iso_start_match = re.match(r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)", snippet)
    if iso_start_match:
        iso_str = iso_start_match.group("iso")
        try:
            # Normalise Z and offset formats for fromisoformat
            iso_clean = iso_str.rstrip("Z")
            # Ensure offset contains a colon ("+0200" -> "+02:00")
            if re.search(r"[+-]\d{4}$", iso_clean):
                iso_clean = iso_clean[:-2] + ":" + iso_clean[-2:]
            dt = datetime.fromisoformat(iso_clean)
            return dt.replace(tzinfo=None)
        except Exception:
            pass

    # 2. Syslog timestamp at line start
    syslog_match = _SYSLOG_RE.match(snippet)
    if syslog_match:
        parts = syslog_match.group(1).split()
        if len(parts) == 3:
            month_str, day_str, time_str = parts
            month = _MONTHS.get(month_str)
            if month:
                try:
                    day = int(day_str)
                    hour, minute, second = [int(v) for v in time_str.split(":")]
                    candidate = datetime(ref_now.year, month, day, hour, minute, second)
                    # If candidate is more than a day in the future, assume previous year
                    if candidate > ref_now + timedelta(days=1):
                        candidate = datetime(ref_now.year - 1, month, day, hour, minute, second)
                    return candidate
                except Exception:
                    pass

    # 3. Auditd epoch, only when line starts with "type="
    if snippet.startswith("type="):
        audit_match = _AUDITD_RE.search(snippet)
        if audit_match:
            try:
                epoch = float(audit_match.group(1))
                return datetime.fromtimestamp(epoch)
            except Exception:
                pass

    return None
    """Parse timestamp from a log line.

    Supports:
    (a) Auditd epoch: msg=audit(1700000000.123:456)
    (b) ISO 8601: 2026-11-25T14:00:00.123456+02:00 or 2026-11-25 12:00:00
    (c) Syslog: 'Jan 15 03:41:09' or 'Jan  5 03:41:09' (with year inference)

    Input:
        line (str): Raw log line.
        now (datetime, optional): Reference time for year inference.

    Output:
        datetime | None: Parsed naive datetime object or None if unparsable.
    """
    if not line:
        return None

    # Enforce safe line length limit
    line_snippet = line[:4096]
    ref_now = now or datetime.now()

    # 1. Auditd epoch
    audit_m = _AUDITD_RE.search(line_snippet)
    if audit_m:
        try:
            epoch = float(audit_m.group(1))
            return datetime.fromtimestamp(epoch)
        except Exception:
            pass

    # 2. ISO 8601
    iso_m = _ISO8601_RE.search(line_snippet)
    if iso_m:
        iso_str = iso_m.group(1)
        try:
            # Replace trailing Z
            clean_iso = iso_str.rstrip("Z")
            # If there is a timezone offset e.g. +02:00, parse and strip tzinfo
            dt = datetime.fromisoformat(clean_iso)
            return dt.replace(tzinfo=None)
        except Exception:
            pass

    # 3. Syslog (e.g. 'Jan 15 03:41:09' or 'Jan  5 03:41:09')
    syslog_m = _SYSLOG_RE.match(line_snippet)
    if syslog_m:
        parts = syslog_m.group(1).split()
        if len(parts) == 3:
            month_str, day_str, time_str = parts[0], parts[1], parts[2]
            month = _MONTHS.get(month_str)
            if month:
                try:
                    day = int(day_str)
                    h, m, s = [int(v) for v in time_str.split(":")]
                    candidate = datetime(ref_now.year, month, day, h, m, s)
                    # If candidate is more than 1 day in the future, infer previous year
                    if candidate > ref_now + timedelta(days=1):
                        candidate = datetime(ref_now.year - 1, month, day, h, m, s)
                    return candidate
                except Exception:
                    pass

    return None


def apply_rule(rule: dict[str, Any], lines: list[str], now: datetime | None = None) -> list[dict[str, Any]]:
    """Apply a compiled rule's regex to a list of log lines.

    Input:
        rule (dict): Rule dict containing "_re" and "id".
        lines (list[str]): List of raw log lines.
        now (datetime, optional): Reference time for timestamp parsing.

    Output:
        list of match dicts: [
            {
                "rule_id": str,
                "line_no": int,
                "line": str,
                "timestamp": datetime | None,
                "groups": dict
            }, ...
        ]
    """
    re_obj = rule.get("_re")
    if not re_obj:
        return []

    rule_id = rule.get("id", "")
    matches: list[dict[str, Any]] = []

    for line_no, raw_line in enumerate(lines, start=1):
        clean_line = raw_line.rstrip("\r\n")[:4096]
        m = re_obj.search(clean_line)
        if m:
            ts = parse_timestamp(clean_line, now=now)
            matches.append({
                "rule_id": rule_id,
                "line_no": line_no,
                "line": clean_line,
                "timestamp": ts,
                "groups": m.groupdict(),
            })

    return matches


def group_and_window(
    matches: list[dict[str, Any]],
    group_by: str | None,
    threshold: int,
    window_minutes: int | None,
    count_distinct: str | None = None,
) -> list[dict[str, Any]]:
    """Group matches by key and evaluate sliding window thresholds.

    Input:
        matches (list): Match dicts from apply_rule.
        group_by (str, optional): Named capture group to group by.
        threshold (int): Minimum count to trigger a hit.
        window_minutes (int, optional): Sliding window duration in minutes.
        count_distinct (str, optional): Named group to count distinct values for.

    Output:
        list of group dicts: [
            {
                "key": str,
                "count": int,
                "first_seen": datetime | None,
                "last_seen": datetime | None,
                "window_start": datetime | None,
                "window_end": datetime | None,
                "matches": list of match dicts,
                "no_timestamp": bool
            }, ...
        ]
    """
    if not matches:
        return []

    # Partition matches by key
    grouped_matches: dict[str, list[dict[str, Any]]] = {}
    for m in matches:
        if group_by:
            key = m["groups"].get(group_by)
            if key is None:
                continue
            key_str = str(key)
        else:
            key_str = "__all__"
        grouped_matches.setdefault(key_str, []).append(m)

    results: list[dict[str, Any]] = []

    for key, key_matches in grouped_matches.items():
        # Check if timestamps are missing or window_minutes is None
        has_missing_ts = any(m["timestamp"] is None for m in key_matches)

        if window_minutes is None or has_missing_ts:
            # Fall back to evaluating all matches for this key together
            if count_distinct:
                distinct_vals = {
                    m["groups"].get(count_distinct)
                    for m in key_matches
                    if m["groups"].get(count_distinct) is not None
                }
                count = len(distinct_vals)
            else:
                count = len(key_matches)

            if count >= threshold:
                valid_ts = [m["timestamp"] for m in key_matches if m["timestamp"] is not None]
                first_seen = min(valid_ts) if valid_ts else None
                last_seen = max(valid_ts) if valid_ts else None
                results.append({
                    "key": key,
                    "count": count,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "window_start": first_seen,
                    "window_end": last_seen,
                    "matches": key_matches,
                    "no_timestamp": has_missing_ts,
                })
        else:
            # Sliding window over time-sorted matches
            sorted_m = sorted(key_matches, key=lambda x: x["timestamp"])  # type: ignore
            max_delta = timedelta(minutes=window_minutes)

            best_count = 0
            best_window: list[dict[str, Any]] = []
            n = len(sorted_m)

            for left in range(n):
                right = left
                while right < n and (sorted_m[right]["timestamp"] - sorted_m[left]["timestamp"]) <= max_delta:  # type: ignore
                    right += 1

                window_m = sorted_m[left:right]
                if count_distinct:
                    cnt = len({
                        m["groups"].get(count_distinct)
                        for m in window_m
                        if m["groups"].get(count_distinct) is not None
                    })
                else:
                    cnt = len(window_m)

                if cnt >= threshold and cnt > best_count:
                    best_count = cnt
                    best_window = window_m

            if best_window and best_count >= threshold:
                results.append({
                    "key": key,
                    "count": best_count,
                    "first_seen": best_window[0]["timestamp"],
                    "last_seen": best_window[-1]["timestamp"],
                    "window_start": best_window[0]["timestamp"],
                    "window_end": best_window[-1]["timestamp"],
                    "matches": best_window,
                    "no_timestamp": False,
                })

    return results


def _is_ip_internal(ip_val: Any, internal_networks: list[str] | None = None) -> bool | None:
    """Check if an IP address belongs to RFC 1918 / loopback / configured internal networks.

    Returns:
        True: IP is internal.
        False: IP is external.
        None: Value is not a valid IP string.
    """
    if not ip_val or not isinstance(ip_val, str):
        return None

    try:
        ip_obj = ipaddress.ip_address(ip_val.strip())
    except ValueError:
        return None

    nets = internal_networks if internal_networks is not None else DEFAULT_INTERNAL_NETWORKS
    for net_str in nets:
        try:
            net_obj = ipaddress.ip_network(net_str, strict=False)
            if ip_obj in net_obj:
                return True
        except ValueError:
            continue

    return False


def build_evidence(matches: list[dict[str, Any]], limit: int = 10) -> list[str]:
    """Extract raw evidence lines from matches up to limit.

    Input:
        matches (list): List of match dicts.
        limit (int): Maximum number of lines to retain.

    Output:
        list[str]: Raw log lines.
    """
    return [m["line"] for m in matches[:limit]]


def evaluate_rule(
    rule: dict[str, Any],
    lines: list[str],
    now: datetime | None = None,
    internal_networks: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate a single rule against a list of lines.

    Input:
        rule (dict): Compiled rule dict.
        lines (list[str]): List of log lines.
        now (datetime, optional): Reference time for parsing.
        internal_networks (list[str], optional): CIDR network list.

    Output:
        dict: {
            "rule_id": str,
            "log_type": str,
            "mode": "threshold" | "each",
            "total_matches": int,
            "hits": [hit dict, ...]
        }
    """
    rule_id = rule["id"]
    log_type = rule["log_type"]
    threshold = rule.get("threshold", 1)
    group_by = rule.get("group_by")
    count_distinct = rule.get("count_distinct")
    window_minutes = rule.get("window_minutes")

    mode = "threshold" if (group_by or threshold > 1 or count_distinct) else "each"
    matches = apply_rule(rule, lines, now=now)
    total_matches = len(matches)
    hits: list[dict[str, Any]] = []

    if mode == "threshold":
        windowed = group_and_window(
            matches,
            group_by=group_by,
            threshold=threshold,
            window_minutes=window_minutes,
            count_distinct=count_distinct,
        )
        for item in windowed:
            first_m = item["matches"][0] if item["matches"] else None
            groups = first_m["groups"] if first_m else {}

            ip_val = groups.get("ip") or (item["key"] if group_by == "ip" else None)
            is_internal = _is_ip_internal(ip_val, internal_networks)

            severity = rule.get("severity", "MEDIUM")
            if is_internal is True and rule.get("severity_internal"):
                severity = rule["severity_internal"]

            hits.append({
                "rule_id": rule_id,
                "key": item["key"],
                "count": item["count"],
                "first_seen": item["first_seen"].isoformat() if item["first_seen"] else None,
                "last_seen": item["last_seen"].isoformat() if item["last_seen"] else None,
                "window_start": item["window_start"].isoformat() if item["window_start"] else None,
                "window_end": item["window_end"].isoformat() if item["window_end"] else None,
                "severity": severity,
                "is_internal": is_internal,
                "groups": groups,
                "evidence": build_evidence(item["matches"], limit=10),
                "line_numbers": [m["line_no"] for m in item["matches"]],
                "no_timestamp": item.get("no_timestamp", False),
            })
    else:
        for m in matches:
            ip_val = m["groups"].get("ip")
            is_internal = _is_ip_internal(ip_val, internal_networks)

            severity = rule.get("severity", "MEDIUM")
            if is_internal is True and rule.get("severity_internal"):
                severity = rule["severity_internal"]

            ts_iso = m["timestamp"].isoformat() if m["timestamp"] else None
            hits.append({
                "rule_id": rule_id,
                "key": rule_id,
                "count": 1,
                "first_seen": ts_iso,
                "last_seen": ts_iso,
                "window_start": ts_iso,
                "window_end": ts_iso,
                "severity": severity,
                "is_internal": is_internal,
                "groups": m["groups"],
                "evidence": [m["line"]],
                "line_numbers": [m["line_no"]],
                "no_timestamp": m["timestamp"] is None,
            })

    return {
        "rule_id": rule_id,
        "log_type": log_type,
        "mode": mode,
        "total_matches": total_matches,
        "hits": hits,
    }


def evaluate_all(
    rules: list[dict[str, Any]],
    collected: dict[str, Any],
    now: datetime | None = None,
    internal_networks: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate all rules across collected log sources.

    Input:
        rules (list): List of loaded rule dicts.
        collected (dict): Collected logs either as {log_type: [lines]} or
                          collector.collect_all output {"logs": {log_type: {"lines": [...]}}}.
        now (datetime, optional): Reference time for timestamp parsing.
        internal_networks (list[str], optional): Internal CIDR list.

    Output:
        dict: {
            "results": {rule_id: evaluate_rule result},
            "skipped_rules": [{"rule_id": str, "reason": str}],
            "errors": [{"rule_id": str, "error": str}]
        }
    """
    results: dict[str, Any] = {}
    skipped_rules: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []

    # Normalize collected logs structure
    logs_map: dict[str, list[str]] = {}
    if "logs" in collected and isinstance(collected["logs"], dict):
        for lt, log_data in collected["logs"].items():
            if isinstance(log_data, dict):
                logs_map[lt] = log_data.get("lines", [])
            elif isinstance(log_data, list):
                logs_map[lt] = log_data
    else:
        for lt, lines in collected.items():
            if isinstance(lines, list):
                logs_map[lt] = lines

    for rule in rules:
        rule_id = rule.get("id", "UNKNOWN")
        log_type = rule.get("log_type")

        lines = logs_map.get(log_type)
        if not lines:
            skipped_rules.append({
                "rule_id": rule_id,
                "reason": f"No log lines available for log_type '{log_type}'",
            })
            continue

        try:
            res = evaluate_rule(rule, lines, now=now, internal_networks=internal_networks)
            results[rule_id] = res
        except Exception as exc:
            logger.error("Error evaluating rule %s: %s", rule_id, exc)
            errors.append({"rule_id": rule_id, "error": str(exc)})

    return {
        "results": results,
        "skipped_rules": skipped_rules,
        "errors": errors,
    }


def get_rules_for_check(rules: list[dict[str, Any]], check_no: int) -> list[dict[str, Any]]:
    """Filter rules by the capstone brief check number (1..8)."""
    return [r for r in rules if r.get("check") == check_no]


def get_rule(rules: list[dict[str, Any]], rule_id: str) -> dict[str, Any] | None:
    """Retrieve a rule by its unique ID."""
    return next((r for r in rules if r.get("id") == rule_id), None)


def run_rule_tests(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Run built-in sample match/no_match tests for all rules.

    Input:
        rules (list): List of loaded rule dicts.

    Output:
        dict: {
            "passed": int,
            "failed": [{"rule_id": str, "kind": "match"|"no_match", "line": str, "reason": str}]
        }
    """
    passed = 0
    failed: list[dict[str, Any]] = []

    for rule in rules:
        rule_id = rule.get("id", "")
        re_obj = rule.get("_re")
        if not re_obj:
            failed.append({
                "rule_id": rule_id,
                "kind": "compile",
                "line": "",
                "reason": "Rule has no compiled regex (_re)",
            })
            continue

        tests = rule.get("tests", {})
        matches = tests.get("match", [])
        no_matches = tests.get("no_match", [])

        if len(matches) < 2:
            failed.append({
                "rule_id": rule_id,
                "kind": "schema",
                "line": "",
                "reason": f"Rule has fewer than 2 match test samples (found {len(matches)})",
            })
        if len(no_matches) < 2:
            failed.append({
                "rule_id": rule_id,
                "kind": "schema",
                "line": "",
                "reason": f"Rule has fewer than 2 no_match test samples (found {len(no_matches)})",
            })

        for line in matches:
            trunc_line = line[:4096]
            if re_obj.search(trunc_line):
                passed += 1
            else:
                failed.append({
                    "rule_id": rule_id,
                    "kind": "match",
                    "line": line,
                    "reason": "Line failed to match expected regex pattern",
                })

        for line in no_matches:
            trunc_line = line[:4096]
            if not re_obj.search(trunc_line):
                passed += 1
            else:
                failed.append({
                    "rule_id": rule_id,
                    "kind": "no_match",
                    "line": line,
                    "reason": "Line matched regex when it should NOT have matched",
                })

    return {"passed": passed, "failed": failed}


def validate_mitre_ids(rules: list[dict[str, Any]], attack_json_path: str = "hunting/attack.json") -> dict[str, list[str]]:
    """Validate MITRE ATT&CK IDs against attack.json if available.

    Input:
        rules (list): List of loaded rule dicts.
        attack_json_path (str): File path to attack.json.

    Output:
        dict: {
            "missing_in_attack": list of technique IDs used in rules but missing from attack.json,
            "unused_in_rules": list of technique IDs in attack.json but not used in any rule
        }
    """
    rule_techniques: set[str] = set()
    for r in rules:
        for tid in r.get("mitre", []):
            rule_techniques.add(tid)

    attack_file = Path(attack_json_path)
    if not attack_file.is_file():
        # Tolerate absent attack.json
        return {"missing_in_attack": [], "unused_in_rules": []}

    try:
        with open(attack_file, "r", encoding="utf-8") as f:
            attack_data = json.load(f)
    except Exception as exc:
        logger.warning("Could not read %s: %s", attack_json_path, exc)
        return {"missing_in_attack": [], "unused_in_rules": []}

    known_techniques: set[str] = set()
    if isinstance(attack_data, dict):
        # Could be { "T1110": { ... } } or { "techniques": [ ... ] }
        if "techniques" in attack_data and isinstance(attack_data["techniques"], list):
            for item in attack_data["techniques"]:
                if isinstance(item, dict) and "id" in item:
                    known_techniques.add(item["id"])
        else:
            for k in attack_data.keys():
                if _MITRE_PATTERN.match(k):
                    known_techniques.add(k)
    elif isinstance(attack_data, list):
        for item in attack_data:
            if isinstance(item, dict) and "id" in item:
                known_techniques.add(item["id"])

    missing = sorted(list(rule_techniques - known_techniques))
    unused = sorted(list(known_techniques - rule_techniques))
    return {"missing_in_attack": missing, "unused_in_rules": unused}


def coverage_summary(rules: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Generate mapping of MITRE technique IDs to rule IDs covering them.

    Input:
        rules (list): List of loaded rule dicts.

    Output:
        dict: {technique_id: [rule_ids]}
    """
    coverage: dict[str, list[str]] = {}
    for r in rules:
        rule_id = r.get("id", "")
        for tid in r.get("mitre", []):
            coverage.setdefault(tid, []).append(rule_id)

    for tid in coverage:
        coverage[tid] = sorted(list(set(coverage[tid])))

    return coverage


def main() -> None:
    """CLI interface for running self-test and evaluating logs."""
    parser = argparse.ArgumentParser(description="VM Threat Hunting Detection Rule Engine")
    parser.add_argument("--rules", default="hunting/rules.json", help="Path to rules.json")
    parser.add_argument("--selftest", action="store_true", help="Run rule test cases and validate schema")
    parser.add_argument("--logs", help="Directory of collected logs to evaluate")

    args = parser.parse_args()

    load_res = load_rules(args.rules, include_disabled=True)
    rules = load_res["rules"]
    errors = load_res["errors"]

    if errors:
        print(f"Rule Loading Errors ({len(errors)}):")
        for err in errors:
            print(f"  [{err.get('id') or 'N/A'}] {err.get('error')}")

    print(f"Loaded {len(rules)} valid rules from {args.rules}")

    if args.selftest:
        print("\nRunning rule test cases...")
        test_res = run_rule_tests(rules)
        print(f"  Passed test checks: {test_res['passed']}")
        if test_res["failed"]:
            print(f"  Failed test checks ({len(test_res['failed'])}):")
            for f in test_res["failed"]:
                print(f"    [{f['rule_id']}] {f['kind']}: {f['reason']} (line: {f['line']})")
            sys.exit(1)
        else:
            print("  All rule tests passed successfully! 0 failures.")
            coverage = coverage_summary(rules)
            print(f"  MITRE ATT&CK coverage: {len(coverage)} unique technique(s) mapped.")

    if args.logs:
        log_dir = Path(args.logs)
        if not log_dir.is_dir():
            print(f"Error: Log directory not found: {args.logs}")
            sys.exit(1)

        # Simple file-based loader
        collected: dict[str, list[str]] = {}
        for file_path in log_dir.glob("*.log"):
            log_type = file_path.stem
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                collected[log_type] = f.readlines()

        print(f"\nEvaluating rules against logs in {args.logs}...")
        eval_res = evaluate_all(rules, collected)
        total_hits = 0
        for r_id, res in eval_res["results"].items():
            hits = res.get("hits", [])
            if hits:
                total_hits += len(hits)
                print(f"  [+] {r_id} ({res['log_type']}): {len(hits)} hit(s)")
                for hit in hits:
                    print(f"      Severity: {hit['severity']} | Key: {hit['key']} | Count: {hit['count']}")
        print(f"\nTotal findings: {total_hits}")


if __name__ == "__main__":
    main()
