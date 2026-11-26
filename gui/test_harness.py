from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Any, Callable

from hunting.checks import collect_data
from hunting.collector import ALL_LOG_TYPES, load_logs_from_dir
from hunting.engine import hunt_vm
from hunting.rule_engine import load_attack

ROOT_DIR = Path(__file__).resolve().parent.parent
SAMPLE_DIR = ROOT_DIR / "tests" / "sample_logs"

COMMAND_OUTPUTS = {
    "/etc/os-release": "ID=centos\nID_LIKE=rhel fedora\n",
    "ps -eo": "systemd | /usr/lib/systemd/systemd\nsshd | /usr/sbin/sshd -D\ncrond | /usr/sbin/crond -n\n",
    "systemctl list-units": "sshd.service | active\ncrond.service | active\n",
    "crontab -l": "/etc/cron.daily/logrotate\n",
    "ls -la /etc/rc": "/etc/rc.d/rc.local\n",
    "getent passwd": "root:x:0:0:root:/root:/bin/bash\n",
    "ss -lnt": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n",
}

LOG_PATHS = {
    "/var/log/secure": "auth",
    "/var/log/auth.log": "auth",
    "/var/log/messages": "syslog",
    "/var/log/syslog": "syslog",
    "/var/log/audit/audit.log": "audit",
    "/var/log/cron": "cron",
    "/var/log/cron.log": "cron",
    "/var/log/yum.log": "package",
    "/var/log/dnf.rpm.log": "package",
    "/var/log/dpkg.log": "package",
    "$HOME/.bash_history": "history",
    "/var/log/httpd/access_log": "web_access",
    "/var/log/httpd/error_log": "web_error",
    "/var/log/apache2/access.log": "web_access",
    "/var/log/apache2/error.log": "web_error",
}


class SampleTransport:
    def __init__(self, collected: dict[str, Any]) -> None:
        self.collected = collected
        self.vm = {"name": str(collected.get("vm", "sample"))}

    def run_result(self, command: str, timeout: int = 60) -> dict[str, Any]:
        stdout = ""
        for fragment, value in COMMAND_OUTPUTS.items():
            if fragment in command:
                stdout = value
                break
        if not stdout:
            for path, log_type in LOG_PATHS.items():
                if path in command:
                    lines = self.collected.get("logs", {}).get(log_type, {}).get("lines", [])
                    stdout = "\n".join(str(line) for line in lines)
                    break
        return {
            "ok": True,
            "stdout": stdout,
            "stderr": "",
            "exit_code": 0,
            "error": None,
        }

    def run(self, command: str, timeout: int = 60) -> str:
        return str(self.run_result(command, timeout=timeout)["stdout"])

    def close(self) -> None:
        return None


def build_transport(sample_name: str) -> SampleTransport:
    return SampleTransport(load_logs_from_dir(SAMPLE_DIR / sample_name))


def format_collection(data: dict[str, Any], errors: list[str]) -> str:
    lines = [
        f"Distribution: {', '.join(data.get('distribution', [])) or 'unknown'}",
        f"Errors: {len(errors)}",
    ]
    lines.extend(f"  ERROR {error}" for error in errors)
    for key in sorted(data):
        value = data[key]
        if isinstance(value, list):
            lines.append(f"{key}: {len(value)}")
    for log_type in ALL_LOG_TYPES:
        samples = [str(item) for item in data.get(log_type, [])[:3]]
        if samples:
            lines.append(f"{log_type} sample:")
            lines.extend(f"  {item[:200]}" for item in samples)
    return "\n".join(lines)


def format_report(report: dict[str, Any]) -> str:
    mitre = report.get("mitre", {})
    findings = list(report.get("findings", []))
    counts: dict[str, int] = {}
    for finding in findings:
        source = str(finding.get("source", "unknown"))
        counts[source] = counts.get(source, 0) + 1
    lines = [
        f"VM: {report.get('vm', '')}",
        f"MITRE status: {mitre.get('status', '')}",
        f"MITRE version: {mitre.get('version', '')}",
        f"Dataset version: {mitre.get('dataset_version', '')}",
        f"Errors: {len(report.get('errors', []))}",
        f"Findings: {len(findings)}",
        "Findings by source: "
        + (", ".join(f"{key}={value}" for key, value in sorted(counts.items())) or "none"),
    ]
    lines.extend(f"  ERROR {error}" for error in report.get("errors", []))
    for finding in findings[:40]:
        evidence = str(finding.get("evidence", "")).splitlines()
        first = evidence[0][:160] if evidence else ""
        lines.append(
            f"- {finding.get('rule', '')} [{finding.get('severity', '')}] "
            f"{finding.get('techniques', [])} :: {first}"
        )
    return "\n".join(lines)


class HarnessWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Log Collection + MITRE Hunting Test")
        self.root.geometry("900x620")
        self.root.minsize(760, 500)
        self.events: queue.Queue[dict[str, str]] = queue.Queue()

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        controls = ttk.Frame(main)
        controls.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(controls, text="Sample logs:").pack(side=tk.LEFT)
        self.sample_var = tk.StringVar(value="centos-lab")
        self.sample_box = ttk.Combobox(
            controls,
            textvariable=self.sample_var,
            values=["centos-lab", "clean"],
            state="readonly",
            width=18,
        )
        self.sample_box.pack(side=tk.LEFT, padx=(6, 16))

        self.collection_button = ttk.Button(
            controls, text="Test Log Collection", command=self.start_collection
        )
        self.collection_button.pack(side=tk.LEFT, padx=(0, 6))

        self.hunt_button = ttk.Button(
            controls, text="Run MITRE Hunt", command=self.start_hunt
        )
        self.hunt_button.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(controls, text="Clear", command=self.clear_output).pack(side=tk.LEFT)

        self.status = ttk.Label(main, text="Ready", anchor=tk.W)
        self.status.pack(fill=tk.X)

        output_frame = ttk.Frame(main)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        self.output = tk.Text(output_frame, wrap=tk.NONE, height=20)
        scrollbar = ttk.Scrollbar(
            output_frame, orient=tk.VERTICAL, command=self.output.yview
        )
        self.output.configure(yscrollcommand=scrollbar.set)
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.poll_queue()

    def start_collection(self) -> None:
        sample = self.sample_var.get()
        self._dispatch(
            self.collection_button,
            lambda: self._run_collection(sample),
            "Testing log collection...",
        )

    def start_hunt(self) -> None:
        sample = self.sample_var.get()
        self._dispatch(
            self.hunt_button,
            lambda: self._run_hunt(sample),
            "Running MITRE hunt...",
        )

    def clear_output(self) -> None:
        self.output.delete("1.0", tk.END)

    def _dispatch(
        self, button: ttk.Button, worker: Callable[[], tuple[str, str]], status: str
    ) -> None:
        button.config(state=tk.DISABLED)
        self.status.config(text=status)

        def target() -> None:
            try:
                title, text = worker()
            except Exception as exc:
                self.events.put(
                    {"type": "error", "title": "Error", "text": f"{type(exc).__name__}: {exc}"}
                )
            else:
                self.events.put({"type": "result", "title": title, "text": text})

        threading.Thread(target=target, daemon=True).start()

    def _run_collection(self, sample: str) -> tuple[str, str]:
        transport = build_transport(sample)
        data, errors = collect_data(transport, "linux", timeout=10)
        return f"Log collection: {sample}", format_collection(data, errors)

    def _run_hunt(self, sample: str) -> tuple[str, str]:
        transport = build_transport(sample)
        vm = {"name": sample, "host": "sample-host", "os": "linux"}
        report = hunt_vm(vm, transport=transport, attack=load_attack(), timeout=10)
        return f"MITRE hunt: {sample}", format_report(report)

    def poll_queue(self) -> None:
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            self.collection_button.config(state=tk.NORMAL)
            self.hunt_button.config(state=tk.NORMAL)
            self.status.config(text="Ready" if event["type"] == "result" else "Failed")
            self.output.insert(
                tk.END, f"\n--- {event['title']} ---\n{event['text']}\n"
            )
            self.output.see(tk.END)
        self.root.after(120, self.poll_queue)


def main() -> None:
    root = tk.Tk()
    HarnessWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
