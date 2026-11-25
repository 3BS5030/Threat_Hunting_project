"""Host evidence collection and deviation checks against a known-good baseline."""

from __future__ import annotations

import re
from typing import Any

WINDOWS_COMMANDS: dict[str, str] = {
    "processes": (
        "powershell -NoProfile -Command \"Get-CimInstance Win32_Process | "
        "ForEach-Object { $_.Name + ' | ' + $_.CommandLine }\""
    ),
    "services": (
        "powershell -NoProfile -Command \"Get-Service | "
        "ForEach-Object { $_.Name + ' | ' + $_.Status }\""
    ),
    "scheduled_tasks": (
        "powershell -NoProfile -Command \"Get-ScheduledTask | "
        "ForEach-Object { $_.TaskName + ' | ' + $_.Actions.Command }\""
    ),
    "startup_commands": (
        "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" & "
        "reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\""
    ),
    "users": "net user",
    "listening_ports": "netstat -ano -p TCP",
}

LINUX_COMMANDS: dict[str, str] = {
    "processes": "ps -eo comm,args",
    "services": "systemctl list-units --type=service --state=running --no-pager",
    "scheduled_tasks": "(crontab -l 2>/dev/null; ls /etc/cron.d 2>/dev/null)",
    "startup_commands": "ls -la /etc/rc*.d 2>/dev/null",
    "users": "getent passwd",
    "listening_ports": "ss -lnt",
}

DATA_KEYS = tuple(WINDOWS_COMMANDS)


def commands_for(os_type: str) -> dict[str, str]:
    return LINUX_COMMANDS if os_type.lower().startswith("linux") else WINDOWS_COMMANDS


def collect_data(
    transport: Any, os_type: str = "windows"
) -> tuple[dict[str, list[str]], list[str]]:
    """Run the collection commands, tolerating individual command failures."""
    data: dict[str, list[str]] = {key: [] for key in DATA_KEYS}
    errors: list[str] = []
    for key, command in commands_for(os_type).items():
        try:
            output = transport.run(command) or ""
            data[key] = [line.strip() for line in output.splitlines() if line.strip()]
        except Exception as exc:
            errors.append(f"{key}: {type(exc).__name__}: {exc}")
    return data, errors


def _normalize(key: str, line: str) -> str:
    text = line.strip().lower()
    if key in ("processes", "services", "startup_commands", "scheduled_tasks"):
        text = text.split("|", 1)[0].strip()
    if key == "listening_ports":
        match = re.search(r"(\d+)\s+(?:0\.0\.0\.0|\*|::)\b", line)
        if match:
            return match.group(1)
        match = re.search(r"\b(\d{2,5})\b", line)
        return match.group(1) if match else ""
    return text


def baseline_checks(
    data: dict[str, list[str]], baseline: dict[str, Any]
) -> list[dict[str, Any]]:
    """Flag observed items that are absent from the known-good baseline."""
    findings: list[dict[str, Any]] = []
    for key in DATA_KEYS:
        expected = baseline.get(key)
        if not expected:
            continue
        allowed = {_normalize(key, str(item)) for item in expected}
        for line in data.get(key, []):
            if "---" in line or line.lower().startswith("the following"):
                continue
            value = _normalize(key, line)
            if not value or value in allowed:
                continue
            findings.append(
                {
                    "rule": f"BASELINE_NEW_{key.upper()}",
                    "description": f"Unexpected {key.replace('_', ' ')} entry",
                    "severity": "medium",
                    "technique": "",
                    "technique_name": "",
                    "tactic": "Baseline deviation",
                    "target": key,
                    "evidence": line[:500],
                    "match": value,
                    "source": "baseline",
                }
            )
    return findings
