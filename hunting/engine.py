"""Hunt orchestration: collect evidence, run rules, compare to baseline."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from hunting.checks import (
    SEVERITY_RANK,
    baseline_checks,
    collect_data,
    detect_linux_distribution,
    load_baseline,
    validate_baseline,
)
from hunting.rule_engine import (
    advanced_rule_findings,
    load_attack,
    load_rules,
    run_rules,
)
from mitre.attack import attack_version, sync_attack_data
from transport.ssh import SSHTransport


def select_baseline(baseline: dict[str, Any], os_type: str) -> dict[str, Any]:
    if not isinstance(baseline, dict) or not os_type:
        return baseline
    profiles = baseline.get("profiles")
    if not isinstance(profiles, dict):
        return baseline
    profile_name = "linux" if os_type.lower().startswith("linux") else "windows"
    profile = profiles.get(profile_name)
    if not isinstance(profile, dict):
        return baseline
    merged = {key: value for key, value in baseline.items() if key != "profiles"}
    merged.update(profile)
    merged["profiles"] = profiles
    return merged


def refresh_attack_data(
    force: bool = True,
    cache_path: str | Path | None = None,
    opener: Any | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    return sync_attack_data(
        force=force, cache_path=cache_path, opener=opener, timeout=timeout
    )


def mitre_status(attack: dict[str, Any]) -> dict[str, Any]:
    dataset = attack if isinstance(attack, dict) else {}
    return {
        "status": dataset.get("status", ""),
        "source": dataset.get("source", ""),
        "version": attack_version(dataset),
        "dataset_version": dataset.get("dataset_version", ""),
        "synchronization_timestamp": dataset.get("synchronization_timestamp", ""),
        "sync_error": dataset.get("sync_error", ""),
        "notifications": list(dataset.get("notifications", []) or []),
        "all_notifications": list(
            dataset.get("all_notifications", dataset.get("notifications", [])) or []
        ),
    }


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
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


def _close_quietly(transport: Any) -> None:
    try:
        transport.close()
    except Exception:
        pass


def hunt_vm(
    vm: dict[str, Any],
    baseline: dict[str, Any] | None = None,
    transport: Any | None = None,
    timeout: int = 60,
    attack: dict[str, Any] | None = None,
    sync_attack: bool = False,
) -> dict[str, Any]:
    name = vm.get("name", "unnamed")
    os_type = vm.get("os", "windows")
    active_baseline = select_baseline(
        load_baseline(os_type=os_type) if baseline is None else baseline, os_type
    )
    active_attack = attack or (
        refresh_attack_data() if sync_attack else load_attack()
    )
    owns_transport = transport is None
    ssh = transport if transport is not None else SSHTransport(vm)

    report: dict[str, Any] = {
        "vm": name,
        "host": vm.get("host", ""),
        "os": os_type,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "findings": [],
        "errors": [],
        "summary": {},
        "mitre": mitre_status(active_attack),
    }
    report["errors"].extend(validate_baseline(active_baseline))

    try:
        if owns_transport:
            ssh.connect()
        distribution = None
        if os_type.lower().startswith("linux"):
            distribution = detect_linux_distribution(ssh, timeout)
        data, errors = collect_data(
            ssh, os_type, timeout=timeout, distribution=distribution
        )
        report["errors"].extend(errors)
        report["summary"] = {
            key: len(value) for key, value in data.items() if isinstance(value, list)
        }
        if distribution:
            report["distribution"] = distribution

        rule_errors: list[str] = []
        findings = run_rules(
            data,
            load_rules(),
            active_attack,
            active_baseline,
            errors=rule_errors,
        )
        report["errors"].extend(rule_errors)
        existing_rule_ids = {str(item.get("rule", "")) for item in findings}
        advanced_findings, advanced_errors = advanced_rule_findings(
            data, active_attack, skip_rule_ids=existing_rule_ids
        )
        report["errors"].extend(advanced_errors)
        findings.extend(advanced_findings)
        findings.extend(baseline_checks(data, active_baseline))
        findings = _dedupe(findings)
        findings.sort(
            key=lambda item: (
                SEVERITY_RANK.get(item.get("severity", "info"), 9),
                str(item.get("rule", "")),
                str(item.get("event_timestamp", "")),
            )
        )
        report["findings"] = findings
    finally:
        if owns_transport:
            _close_quietly(ssh)

    return report
