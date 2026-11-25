"""Log Collection Engine for VM Threat Hunting Dashboard.

Responsible for retrieving target VM logs safely via read-only SSH execution (run_cmd),
normalizing log paths by Linux distribution family (RHEL / Debian), merging package logs,
handling permission privilege escalation safely via sudo -n, and serializing/deserializing
logs for offline analysis.
Standard library only; no custom classes.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import shlex
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Canonical candidate path tables
LOG_SOURCES: dict[str, dict[str, list[str]]] = {
    "rhel": {
        "auth": ["/var/log/secure"],
        "syslog": ["/var/log/messages"],
        "audit": ["/var/log/audit/audit.log"],
        "cron": ["/var/log/cron"],
        "package": ["/var/log/yum.log", "/var/log/dnf.rpm.log"],
        "web_access": ["/var/log/httpd/access_log"],
        "web_error": ["/var/log/httpd/error_log"],
    },
    "debian": {
        "auth": ["/var/log/auth.log"],
        "syslog": ["/var/log/syslog"],
        "audit": ["/var/log/audit/audit.log"],
        "cron": ["/var/log/cron.log", "/var/log/syslog"],
        "package": ["/var/log/dpkg.log"],
        "web_access": ["/var/log/apache2/access.log"],
        "web_error": ["/var/log/apache2/error.log"],
    },
}

ALL_LOG_TYPES = [
    "auth",
    "syslog",
    "audit",
    "cron",
    "package",
    "history",
    "web_access",
    "web_error",
]


def resolve_log_paths(family: str) -> dict[str, list[str]]:
    """Resolve candidate log file paths based on Linux distro family.

    Input:
        family (str): 'rhel', 'debian', or 'unknown'.

    Output:
        dict[str, list[str]]: Mapping from canonical log_type to list of candidate paths.
    """
    fam = family.lower().strip() if family else "unknown"
    if fam in LOG_SOURCES:
        mapping = {k: list(v) for k, v in LOG_SOURCES[fam].items()}
    else:
        # Unknown family: try candidate paths from both RHEL and Debian
        mapping = {}
        for lt in ["auth", "syslog", "audit", "cron", "package", "web_access", "web_error"]:
            combined: list[str] = []
            for src_family in ("rhel", "debian"):
                for p in LOG_SOURCES[src_family].get(lt, []):
                    if p not in combined:
                        combined.append(p)
            mapping[lt] = combined

    # History is uniform across all distros using remote user $HOME
    mapping["history"] = ["$HOME/.bash_history"]
    return mapping


def family_from_os_release(text: str) -> str:
    """Infer distro family ('rhel', 'debian', or 'unknown') from /etc/os-release text.

    Input:
        text (str): Contents of /etc/os-release.

    Output:
        str: 'rhel', 'debian', or 'unknown'.
    """
    if not text:
        return "unknown"

    id_match = re.search(r"^ID=(?:\"([^\"]+)\"|(\S+))", text, re.MULTILINE)
    id_val = (id_match.group(1) or id_match.group(2) or "").lower() if id_match else ""

    id_like_match = re.search(r"^ID_LIKE=(?:\"([^\"]+)\"|(\S+))", text, re.MULTILINE)
    id_like_val = (id_like_match.group(1) or id_like_match.group(2) or "").lower() if id_like_match else ""

    combined = f"{id_val} {id_like_val}"

    if any(token in combined for token in ("rhel", "centos", "fedora", "rocky", "alma", "ol")):
        return "rhel"
    if any(token in combined for token in ("debian", "ubuntu", "kali", "mint")):
        return "debian"

    return "unknown"


def _clean_lines(raw_text: str) -> list[str]:
    """Sanitize raw text into list of lines (strip CR/LF, remove NUL bytes, decode replacements)."""
    if not raw_text:
        return []
    clean_text = raw_text.replace("\x00", "")
    lines = clean_text.splitlines()
    return [ln.rstrip("\r\n") for ln in lines if ln]


def collect_log(
    log_type: str,
    family: str,
    run_cmd: Callable[..., dict[str, Any]],
    max_lines: int = 20000,
) -> dict[str, Any]:
    """Collect a single log type from the target machine using run_cmd.

    Per candidate path:
    1. tail -n 20000 <path>
    2. If 'Permission denied' -> sudo -n /usr/bin/tail -n 20000 <path>
    3. For 'package', merges lines across all readable candidates.
    For other log types, uses the first readable candidate.

    Input:
        log_type (str): Canonical log type.
        family (str): 'rhel', 'debian', or 'unknown'.
        run_cmd (Callable): Function (cmd, timeout) -> {"ok": bool, "stdout": str, "stderr": str, "exit_code": int|None, "error": str|None}.
        max_lines (int): Max tail line count (default 20000).

    Output:
        dict: {
            "log_type": str,
            "path": str | None,
            "paths_read": list[str],
            "status": "ok" | "missing" | "denied" | "empty" | "error",
            "lines": list[str],
            "truncated": bool,
            "error": str | None
        }
    """
    paths_map = resolve_log_paths(family)
    candidates = paths_map.get(log_type, [])

    if not candidates:
        return {
            "log_type": log_type,
            "path": None,
            "paths_read": [],
            "status": "missing",
            "lines": [],
            "truncated": False,
            "error": f"No candidate paths configured for {log_type}",
        }

    merged_lines: list[str] = []
    paths_read: list[str] = []
    last_error: str | None = None
    all_denied = True
    any_missing = False

    is_package_merge = (log_type == "package")

    for path in candidates:
        if path == "$HOME/.bash_history":
            cmd = f'tail -n {max_lines} "$HOME/.bash_history"'
            sudo_cmd = None
        else:
            quoted_path = shlex.quote(path)
            cmd = f"tail -n {max_lines} {quoted_path}"
            sudo_cmd = f"sudo -n /usr/bin/tail -n {max_lines} {quoted_path}"

        res = run_cmd(cmd, timeout=30)
        output = res.get("stdout", "")
        err_out = res.get("stderr", "")
        error_msg = res.get("error")

        # Check for permission denied
        if not res.get("ok", False) or "Permission denied" in err_out or "permission denied" in err_out.lower():
            if sudo_cmd:
                sudo_res = run_cmd(sudo_cmd, timeout=30)
                sudo_err = sudo_res.get("stderr", "")
                if sudo_res.get("ok", False) and sudo_res.get("exit_code") == 0:
                    output = sudo_res.get("stdout", "")
                    res = sudo_res
                    all_denied = False
                else:
                    if "password is required" in sudo_err or "not allowed" in sudo_err or "a password is required" in sudo_err:
                        last_error = f"Permission denied (sudo requires password): {path}"
                        continue
                    elif "No such file" in sudo_err:
                        any_missing = True
                        all_denied = False
                        continue
                    else:
                        last_error = sudo_err or sudo_res.get("error") or "Sudo execution failed"
                        continue
            else:
                last_error = f"Permission denied reading {path}"
                continue
        elif "No such file" in err_out or (res.get("exit_code") != 0 and "No such file" in (error_msg or "")):
            any_missing = True
            all_denied = False
            continue
        elif not res.get("ok", False):
            last_error = error_msg or err_out or f"Command failed with exit code {res.get('exit_code')}"
            all_denied = False
            continue
        else:
            all_denied = False

        # Read succeeded
        lines = _clean_lines(output)
        paths_read.append(path)
        merged_lines.extend(lines)

        if not is_package_merge:
            break

    if paths_read:
        status = "empty" if len(merged_lines) == 0 else "ok"
        primary_path = paths_read[0] if paths_read else None
        return {
            "log_type": log_type,
            "path": primary_path,
            "paths_read": paths_read,
            "status": status,
            "lines": merged_lines,
            "truncated": len(merged_lines) >= max_lines,
            "error": None,
        }

    if all_denied and candidates and not any_missing:
        return {
            "log_type": log_type,
            "path": candidates[0] if candidates else None,
            "paths_read": [],
            "status": "denied",
            "lines": [],
            "truncated": False,
            "error": last_error or "Permission denied across candidate paths",
        }

    return {
        "log_type": log_type,
        "path": candidates[0] if candidates else None,
        "paths_read": [],
        "status": "missing",
        "lines": [],
        "truncated": False,
        "error": last_error or "Candidate files not found or unreadable",
    }


def collect_all(
    vm: dict[str, Any],
    family: str,
    run_cmd: Callable[..., dict[str, Any]],
    log_types: list[str] | None = None,
    progress_cb: Callable[[str, int, int], None] | None = None,
) -> dict[str, Any]:
    """Collect all configured log types for a given VM.

    Input:
        vm (dict): VM metadata dict with "name" key.
        family (str): Distro family ('rhel', 'debian', or 'unknown').
        run_cmd (Callable): Injected command runner.
        log_types (list[str], optional): Subset of log_types to collect.
        progress_cb (Callable, optional): Callback (log_type, index, total).

    Output:
        dict: {
            "vm": str,
            "family": str,
            "collected_at": str (ISO 8601),
            "logs": {log_type: collect_log result dict},
            "skipped": [{"log_type": str, "tried": list[str], "status": str, "reason": str}]
        }
    """
    vm_name = vm.get("name", "unknown_vm")
    targets = log_types if log_types is not None else ALL_LOG_TYPES
    total = len(targets)

    logs: dict[str, dict[str, Any]] = {}
    skipped: list[dict[str, Any]] = []

    paths_map = resolve_log_paths(family)

    for idx, lt in enumerate(targets, start=1):
        if progress_cb:
            try:
                progress_cb(lt, idx, total)
            except Exception as cb_err:
                logger.warning("Error in progress callback: %s", cb_err)

        try:
            res = collect_log(lt, family, run_cmd)
            logs[lt] = res
            if res.get("status") in ("missing", "denied", "error"):
                skipped.append({
                    "log_type": lt,
                    "tried": paths_map.get(lt, []),
                    "status": res.get("status", "unknown"),
                    "reason": res.get("error") or f"Log collection ended with status '{res.get('status')}'",
                })
        except Exception as exc:
            logger.error("Unexpected error collecting %s for %s: %s", lt, vm_name, exc)
            logs[lt] = {
                "log_type": lt,
                "path": None,
                "paths_read": [],
                "status": "error",
                "lines": [],
                "truncated": False,
                "error": str(exc),
            }
            skipped.append({
                "log_type": lt,
                "tried": paths_map.get(lt, []),
                "status": "error",
                "reason": str(exc),
            })

    return {
        "vm": vm_name,
        "family": family,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "logs": logs,
        "skipped": skipped,
    }


def get_lines(collected: dict[str, Any], log_type: str) -> list[str]:
    """Retrieve raw lines for a specific log_type from collected logs dict.

    Input:
        collected (dict): Output from collect_all or load_logs_from_dir.
        log_type (str): Canonical log type.

    Output:
        list[str]: Lines of the log.
    """
    if "logs" in collected and isinstance(collected["logs"], dict):
        log_info = collected["logs"].get(log_type, {})
        if isinstance(log_info, dict):
            return log_info.get("lines", [])
    elif log_type in collected and isinstance(collected[log_type], list):
        return collected[log_type]
    return []


def save_logs_to_dir(collected: dict[str, Any], out_dir: str | Path) -> list[str]:
    """Serialize collected logs into a directory (<log_type>.log files).

    Input:
        collected (dict): Output of collect_all.
        out_dir (str | Path): Destination directory.

    Output:
        list[str]: List of written file paths.
    """
    target_dir = Path(out_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    logs = collected.get("logs", {})
    for lt, log_data in logs.items():
        lines = log_data.get("lines", [])
        file_path = target_dir / f"{lt}.log"
        with open(file_path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(f"{line}\n")
        written.append(str(file_path))

    # Also save metadata
    meta = {
        "vm": collected.get("vm"),
        "family": collected.get("family"),
        "collected_at": collected.get("collected_at"),
        "skipped": collected.get("skipped", []),
    }
    meta_path = target_dir / "metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    written.append(str(meta_path))

    return written


def load_logs_from_dir(dir_path: str | Path) -> dict[str, Any]:
    """Load log files from a directory into a collected-shaped dictionary.

    Input:
        dir_path (str | Path): Directory containing <log_type>.log files.

    Output:
        dict: Shape matching collect_all output.
    """
    src_dir = Path(dir_path)
    if not src_dir.is_dir():
        return {
            "vm": "unknown",
            "family": "unknown",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "logs": {},
            "skipped": [{"log_type": "all", "tried": [str(dir_path)], "status": "missing", "reason": "Directory not found"}],
        }

    meta_file = src_dir / "metadata.json"
    os_release_file = src_dir / "os-release.txt"
    family = "unknown"
    vm_name = src_dir.name

    if meta_file.is_file():
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
                family = meta.get("family", "unknown")
                vm_name = meta.get("vm", vm_name)
        except Exception:
            pass

    if family == "unknown" and os_release_file.is_file():
        try:
            family = family_from_os_release(os_release_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    logs: dict[str, dict[str, Any]] = {}
    for log_file in src_dir.glob("*.log"):
        lt = log_file.stem
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                lines = [line.rstrip("\r\n") for line in f if line.rstrip("\r\n")]
            logs[lt] = {
                "log_type": lt,
                "path": str(log_file),
                "paths_read": [str(log_file)],
                "status": "ok" if lines else "empty",
                "lines": lines,
                "truncated": False,
                "error": None,
            }
        except Exception as read_err:
            logs[lt] = {
                "log_type": lt,
                "path": str(log_file),
                "paths_read": [],
                "status": "error",
                "lines": [],
                "truncated": False,
                "error": str(read_err),
            }

    return {
        "vm": vm_name,
        "family": family,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "logs": logs,
        "skipped": [],
    }


def generate_sudoers_snippet(username: str, family: str) -> str:
    """Generate exact, non-wildcard sudoers NOPASSWD configuration lines.

    Input:
        username (str): Target user connecting via SSH (e.g. 'analyst').
        family (str): 'rhel' or 'debian'.

    Output:
        str: Sudoers configuration text.
    """
    paths_map = resolve_log_paths(family)
    paths: list[str] = []
    for lt, plist in paths_map.items():
        if lt == "history":
            continue
        for p in plist:
            if p not in paths:
                paths.append(p)

    lines = [
        "# VM Threat Hunting Dashboard - Read-Only Log Access Configuration",
        "# Install via: sudo visudo -f /etc/sudoers.d/99-threat-hunting",
        "# Verify tail binary path with: command -v tail",
        "# Rule: Strict fixed tail command, no wildcards allowed.",
    ]

    for p in paths:
        lines.append(f"{username} ALL=(ALL) NOPASSWD: /usr/bin/tail -n 20000 {p}")

    return "\n".join(lines)
