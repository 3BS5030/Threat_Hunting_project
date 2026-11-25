"""Hunt orchestration: collect evidence, run rules, compare to baseline."""

from __future__ import annotations

import datetime as dt
from typing import Any

from hunting.checks import baseline_checks, collect_data
from hunting.rule_engine import load_attack, load_rules, run_rules
from transport.ssh import SSHTransport

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def hunt_vm(
    vm: dict[str, Any],
    baseline: dict[str, Any],
    transport: Any | None = None,
) -> dict[str, Any]:
    """Return a report dict for a single VM.

    A transport-like object may be injected (useful for tests and demos);
    otherwise a Fabric SSH connection is created from the VM definition.
    """
    name = vm.get("name", "unnamed")
    os_type = vm.get("os", "windows")
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
    }

    try:
        if owns_transport:
            ssh.connect()
        data, errors = collect_data(ssh, os_type)
        report["errors"].extend(errors)
        report["summary"] = {key: len(value) for key, value in data.items()}
        findings = run_rules(data, load_rules(), load_attack())
        findings.extend(baseline_checks(data, baseline))
        findings.sort(key=lambda item: SEVERITY_RANK.get(item.get("severity", "info"), 9))
        report["findings"] = findings
    finally:
        if owns_transport:
            ssh.close()

    return report
