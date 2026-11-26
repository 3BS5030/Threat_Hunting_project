"""Host evidence collection and deviation checks against a known-good baseline."""

from __future__ import annotations

import inspect
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from hunting.collector import ALL_LOG_TYPES, collect_all, get_lines

BASELINE_PATH = Path(__file__).resolve().parent.parent / "baseline.json"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
COLLECTION_ERROR_MARKER = "__COLLECT_ERROR__"

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

COLLECTOR_LOG_KEYS = tuple(ALL_LOG_TYPES)
DATA_KEYS = tuple(WINDOWS_COMMANDS) + ("secure_log",) + tuple(
    key for key in COLLECTOR_LOG_KEYS if key != "auth"
)
POLICY_KEYS = tuple(WINDOWS_COMMANDS) + ("secure_log",) + COLLECTOR_LOG_KEYS + (
    "trusted_administrators",
    "trusted_service_accounts",
    "allowed_internal_ip_ranges",
    "approved_packages",
    "expected_cron_jobs",
    "known_system_accounts",
    "trusted_executable_paths",
)

RHEL_IDS = {"rhel", "centos", "rocky", "almalinux", "oraclelinux", "fedora", "amzn", "amazon"}
DEBIAN_IDS = {"debian", "ubuntu", "linuxmint", "pop"}

SYSLOG_TIMESTAMP = r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"


def load_baseline(
    path: str | Path | None = None, os_type: str | None = None
) -> dict[str, Any]:
    target = Path(path) if path else BASELINE_PATH
    with target.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not os_type:
        return data if isinstance(data, dict) else {}
    profiles = data.get("profiles")
    if not isinstance(profiles, dict):
        return data
    profile_name = "linux" if os_type.lower().startswith("linux") else "windows"
    profile = profiles.get(profile_name)
    if not isinstance(profile, dict):
        return data
    merged = {key: value for key, value in data.items() if key != "profiles"}
    merged.update(profile)
    merged["profiles"] = profiles
    return merged


def validate_baseline(baseline: Any) -> list[str]:
    if not isinstance(baseline, dict):
        return ["baseline: expected an object"]
    issues: list[str] = []
    for key, value in baseline.items():
        if key == "descriptions":
            if not isinstance(value, dict):
                issues.append("descriptions: expected an object")
            continue
        if key == "profiles":
            if not isinstance(value, dict):
                issues.append("profiles: expected an object")
                continue
            for profile_name, profile in value.items():
                if not isinstance(profile, dict):
                    issues.append(f"profiles.{profile_name}: expected an object")
                    continue
                for profile_key, profile_value in profile.items():
                    if profile_key not in POLICY_KEYS:
                        issues.append(f"profiles.{profile_name}.{profile_key}: unknown policy section")
                    elif not isinstance(profile_value, list):
                        issues.append(f"profiles.{profile_name}.{profile_key}: expected a list")
            continue
        if key not in POLICY_KEYS:
            issues.append(f"{key}: unknown baseline category")
        elif not isinstance(value, list):
            issues.append(f"{key}: expected a list")
    return issues


def commands_for(os_type: str) -> dict[str, str]:
    return LINUX_COMMANDS if os_type.lower().startswith("linux") else WINDOWS_COMMANDS


def _accepts_timeout(runner: Any) -> bool:
    try:
        parameters = inspect.signature(runner).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == "timeout"
        or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _run_command(transport: Any, command: str, timeout: int) -> str:
    runner = transport.run
    raw = runner(command, timeout=timeout) if _accepts_timeout(runner) else runner(command)
    return raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw or "")


def _coerce_run_result(raw: Any) -> dict[str, Any]:
    value = raw if isinstance(raw, dict) else {"stdout": str(raw or "")}
    stdout = value.get("stdout", "")
    stderr = value.get("stderr", "")
    if isinstance(stdout, bytes):
        stdout = stdout.decode(errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode(errors="replace")
    code = value.get("exit_code")
    ok = value.get("ok")
    if ok is None:
        ok = code in (None, 0)
    error = value.get("error")
    return {
        "ok": bool(ok),
        "stdout": str(stdout or ""),
        "stderr": str(stderr or ""),
        "exit_code": code,
        "error": str(error) if error else None,
    }


def _marker_message(raw: str) -> str | None:
    for line in raw.splitlines():
        text = line.strip()
        if text.startswith(COLLECTION_ERROR_MARKER):
            return text[len(COLLECTION_ERROR_MARKER):].strip()
    return None


def _structured_runner(transport: Any, timeout: int) -> Any:
    def run_cmd(command: str, timeout: int = 30) -> dict[str, Any]:
        effective_timeout = timeout if timeout is not None else 30
        raw_runner = getattr(transport, "run_result", None)
        if callable(raw_runner):
            try:
                raw = (
                    raw_runner(command, timeout=effective_timeout)
                    if _accepts_timeout(raw_runner)
                    else raw_runner(command)
                )
                return _coerce_run_result(raw)
            except Exception as exc:
                return {
                    "ok": False,
                    "stdout": "",
                    "stderr": f"{type(exc).__name__}: {exc}",
                    "exit_code": None,
                    "error": f"{type(exc).__name__}: {exc}",
                }
        try:
            raw_text = _run_command(transport, command, effective_timeout)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            return {
                "ok": False,
                "stdout": "",
                "stderr": message,
                "exit_code": None,
                "error": message,
            }
        message = _marker_message(raw_text)
        if message:
            return {
                "ok": False,
                "stdout": raw_text,
                "stderr": message,
                "exit_code": 1,
                "error": message,
            }
        return {
            "ok": True,
            "stdout": raw_text,
            "stderr": "",
            "exit_code": 0,
            "error": None,
        }

    return run_cmd


def _linux_family(distribution: str) -> str:
    tokens = distribution.lower().replace("-", " ").split()
    if any(token in RHEL_IDS for token in tokens):
        return "rhel"
    if any(token in DEBIAN_IDS for token in tokens):
        return "debian"
    return "unknown"


def _split_lines(raw: str) -> list[str]:
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _extract_collection_errors(lines: list[str], source: str, errors: list[str]) -> list[str]:
    kept: list[str] = []
    for line in lines:
        if line.startswith(COLLECTION_ERROR_MARKER):
            errors.append(f"{source}: {line[len(COLLECTION_ERROR_MARKER):].strip()}")
        else:
            kept.append(line)
    return kept


def detect_linux_distribution(transport: Any, timeout: int = 60) -> str:
    command = (
        "if [ -r /etc/os-release ]; then . /etc/os-release; "
        "printf 'ID=%s\\nID_LIKE=%s\\n' \"$ID\" \"$ID_LIKE\"; "
        f"else printf '{COLLECTION_ERROR_MARKER} /etc/os-release is not readable\\n'; fi"
    )
    lines = _split_lines(_run_command(transport, command, timeout))
    values: dict[str, str] = {}
    for line in lines:
        if COLLECTION_ERROR_MARKER in line:
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip().lower()] = value.strip().strip('"').lower()
    identifiers = values.get("id", "").split()
    identifiers.extend(values.get("id_like", "").split())
    for identifier in identifiers:
        if identifier in RHEL_IDS:
            return identifier
        if identifier in DEBIAN_IDS:
            return identifier
    return "unknown"


def authentication_log_path(distribution: str) -> str | None:
    value = distribution.lower()
    tokens = value.replace("-", " ").split()
    if any(token in RHEL_IDS for token in tokens):
        return "/var/log/secure"
    if any(token in DEBIAN_IDS for token in tokens):
        return "/var/log/auth.log"
    return None


def _auth_log_command(path: str) -> str:
    return (
        f"if [ -r {path} ]; then cat {path}; "
        f"elif command -v sudo >/dev/null 2>&1 && sudo -n test -r {path} 2>/dev/null; "
        f"then sudo -n cat {path}; "
        f"elif [ -f {path} ]; then printf '{COLLECTION_ERROR_MARKER} permission denied: {path}\\n'; "
        f"else printf '{COLLECTION_ERROR_MARKER} missing: {path}\\n'; fi"
    )


def _normalized_timestamp(raw: str) -> str:
    if not raw:
        return ""
    try:
        return raw
    except TypeError:
        return ""


def _event_timestamp(raw: str) -> str:
    if not raw:
        return ""
    try:
        from datetime import datetime

        return datetime.strptime(raw, "%b %d %H:%M:%S").isoformat(timespec="seconds")
    except ValueError:
        return raw


def normalize_auth_event(line: str, source_path: str | None = None) -> dict[str, Any]:
    event: dict[str, Any] = {
        "raw": line,
        "text": line,
        "timestamp": "",
        "normalized_timestamp": "",
        "event_type": "authentication_event",
        "action": "",
        "username": "",
        "auth_user": "",
        "command_user": "",
        "target_user": "",
        "source_ip": "",
        "groupname": "",
        "gpasswd_group": "",
        "gpasswd_user": "",
        "command": "",
        "source": source_path or "",
    }
    timestamp_match = re.search(SYSLOG_TIMESTAMP, line)
    if timestamp_match:
        event["timestamp"] = timestamp_match.group("timestamp")
        event["normalized_timestamp"] = _event_timestamp(event["timestamp"])

    patterns = (
        (
            "failed_password",
            r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<source_ip>\S+)",
        ),
        (
            "successful_login",
            r"Accepted (?P<action>password|publickey) for (?P<username>\S+) from (?P<source_ip>\S+)",
        ),
        (
            "sudo_auth_failure",
            r"pam_unix\(sudo:auth\): authentication failure;.*?(?<!\S)user=\s*(?P<auth_user>\S+)",
        ),
        (
            "sudo_command",
            r"sudo(?:\[\d+\])?:\s*(?P<command_user>[^:\s]+)\s*:.*?USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)",
        ),
        (
            "account_created",
            r"(?P<action>useradd|groupadd)(?:\[\d+\])?:\s*new (?:user|group): name=(?P<username>[^,\s]+)",
        ),
        (
            "group_membership_change",
            r"(?:usermod(?:\[\d+\])?:\s*add '(?P<username>[^']+)' to group '(?P<groupname>[^']+)'|gpasswd(?:\[\d+\])?:\s*user (?P<gpasswd_user>\S+) added to group (?P<gpasswd_group>\S+))",
        ),
    )
    lowered = line.lower()
    favorite = "sudo_auth_failure" if "authentication failure" in lowered and "sudo" in lowered else ""
    for event_type, pattern in patterns:
        match = re.search(pattern, line, flags=re.IGNORECASE)
        if not match:
            continue
        fields = match.groupdict()
        if favorite and event_type != favorite:
            continue
        event["event_type"] = event_type
        for key, value in fields.items():
            if value:
                event[key] = value
        break
    if event["event_type"] == "account_created":
        if "groupadd" in lowered:
            event["groupname"] = event["username"]
            event["action"] = "groupadd"
        else:
            event["action"] = "useradd"
    event["normalized_line"] = (
        f"{event['timestamp']} {event['event_type']} "
        f"user={event['username'] or event['auth_user'] or event['command_user']} "
        f"source_ip={event['source_ip']} action={event['action']}"
    ).strip()
    return event


def normalize_auth_events(lines: list[str], source_path: str | None = None) -> list[dict[str, Any]]:
    return [normalize_auth_event(line, source_path) for line in lines]


def collect_data(
    transport: Any,
    os_type: str = "windows",
    timeout: int = 60,
    distribution: str | None = None,
) -> tuple[dict[str, list[str]], list[str]]:
    data: dict[str, list[str]] = {key: [] for key in DATA_KEYS}
    errors: list[str] = []
    for key, command in commands_for(os_type).items():
        try:
            lines = _split_lines(_run_command(transport, command, timeout))
            data[key] = _extract_collection_errors(lines, key, errors)
        except Exception as exc:
            errors.append(f"{key}: {type(exc).__name__}: {exc}")

    if os_type.lower().startswith("linux"):
        distro = distribution or detect_linux_distribution(transport, timeout)
        data["distribution"] = [distro]
        if distro == "unknown":
            errors.append("secure_log: Linux distribution detection failed")
            return data, errors
        family = _linux_family(distro)
        if family == "unknown":
            errors.append(f"secure_log: unsupported Linux distribution {distro!r}")
            return data, errors
        vm_name = "unknown_vm"
        vm_meta = getattr(transport, "vm", None)
        if isinstance(vm_meta, dict) and vm_meta.get("name"):
            vm_name = str(vm_meta["name"])
        try:
            collected = collect_all(
                {"name": vm_name}, family, _structured_runner(transport, timeout)
            )
        except Exception as exc:
            errors.append(f"secure_log: {type(exc).__name__}: {exc}")
            return data, errors

        for key in COLLECTOR_LOG_KEYS:
            if key != "auth":
                data[key] = list(get_lines(collected, key))
        for skipped in collected.get("skipped", []):
            log_type = str(skipped.get("log_type", "unknown"))
            if log_type == "auth":
                continue
            reason = str(skipped.get("reason", ""))
            if reason:
                errors.append(f"log_collection ({log_type}): {reason}")

        auth_info = collected.get("logs", {}).get("auth", {})
        auth_lines = [
            str(line)
            for line in auth_info.get("lines", [])
            if not str(line).startswith(COLLECTION_ERROR_MARKER)
        ]
        status = str(auth_info.get("status", "missing"))
        auth_error = auth_info.get("error")
        path = str(auth_info.get("path") or authentication_log_path(distro) or "")
        if status in ("missing", "denied", "error") and auth_error:
            errors.append(f"secure_log ({path}): {auth_error}")
        if not auth_lines and not any("secure_log" in item for item in errors):
            errors.append(f"secure_log ({path}): authentication log is empty")
        data["auth"] = auth_lines
        data["secure_log"] = normalize_auth_events(auth_lines, path)
    return data, errors


def _normalize_baseline_path(value: str) -> str:
    cleaned = value.strip().strip('"').strip("'")
    if " -> " in cleaned:
        cleaned = cleaned.split(" -> ", 1)[1].strip()
    if cleaned.startswith("/") and "/" in cleaned[1:]:
        return cleaned.rsplit("/", 1)[-1].lower()
    return cleaned.lower()


def _normalize(key: str, line: str) -> str:
    text = line.strip()
    if key == "listening_ports":
        if text.isdigit():
            return text
        match = re.search(r"(?:\[[0-9A-Fa-f:.]+\]|[0-9.]+|\*|::):(\d{1,5})\b", line)
        return match.group(1) if match else ""
    if key in ("processes", "services", "startup_commands", "scheduled_tasks"):
        text = text.split("|", 1)[0].strip()
    if key == "processes":
        parts = text.split()
        return _normalize_baseline_path(parts[0]) if parts else ""
    if key == "services":
        parts = text.split()
        return _normalize_baseline_path(parts[0]) if parts else ""
    if key == "users":
        return text.split(":", 1)[0].strip() if ":" in text else text.split()[0]
    if key == "scheduled_tasks":
        lowered = text.lower()
        if lowered.startswith(("root ", "@reboot ", "@daily ", "@weekly ", "@monthly ")):
            parts = text.split()
            for part in parts[1:]:
                if part.startswith(("/", "$", "./")):
                    return _normalize_baseline_path(part)
            return ""
        return _normalize_baseline_path(text)
    if key == "startup_commands":
        if " -> " in text:
            return _normalize_baseline_path(text.split(" -> ", 1)[1])
        return _normalize_baseline_path(text)
    return text.lower()


def _allowed_values(key: str, items: list[Any]) -> set[str]:
    allowed: set[str] = set()
    for item in items:
        value = _normalize(key, str(item))
        if value:
            allowed.add(value)
        allowed.add(str(item).strip().lower())
        if "/" in str(item):
            allowed.add(_normalize_baseline_path(str(item)))
    return allowed


def _is_internal_ip(value: str, ranges: list[Any]) -> bool:
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


def baseline_checks(
    data: dict[str, list[str]], baseline: dict[str, Any], skip_keys: set[str] | None = None
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    skip = set(skip_keys or set())
    for key in DATA_KEYS:
        if key in skip or key == "secure_log":
            continue
        expected = baseline.get(key)
        if not expected:
            continue
        allowed = _allowed_values(key, list(expected))
        for line in data.get(key, []):
            if "---" in line or line.lower().startswith("the following"):
                continue
            normalized = _normalize(key, line)
            if not normalized or normalized in allowed:
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
                    "match": normalized,
                    "classification": "untrusted",
                    "source": "baseline",
                }
            )
    return findings
