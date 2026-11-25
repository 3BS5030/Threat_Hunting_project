"""Rule-pack and hunting pipeline tests."""

from __future__ import annotations

import json
from pathlib import Path

from hunting.checks import baseline_checks
from hunting.engine import hunt_vm
from hunting.navigator import build_layer
from hunting.rule_engine import load_rules, run_rule_tests, run_rules

ROOT = Path(__file__).resolve().parent.parent


class FakeTransport:
    """Returns canned evidence without opening an SSH connection."""

    OUTPUTS = {
        "Get-CimInstance": "powershell.exe -enc ZQBjAGgAbw== | C:\\Temp\\mimikatz.exe",
        "Get-Service": "evil-service | Running",
        "Get-ScheduledTask": "Update | powershell.exe -File C:\\Temp\\u.ps1",
        "reg query": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | updater.exe",
        "net user": "hunter\nbackdoor_admin\n",
        "netstat": "TCP 0.0.0.0:4444 0.0.0.0:0 LISTENING",
    }

    def run(self, command: str, timeout: int = 60) -> str:
        for fragment, output in self.OUTPUTS.items():
            if fragment in command:
                return output
        return ""


def test_every_embedded_rule_case_passes() -> None:
    failures = [case for case in run_rule_tests() if not case["passed"]]
    assert failures == [], failures


def test_rules_have_required_fields() -> None:
    required = {"id", "target", "pattern", "technique", "severity", "tests"}
    for rule in load_rules():
        assert required.issubset(rule), rule.get("id")


def test_run_rules_enriches_attack_metadata() -> None:
    findings = run_rules({"processes": ["powershell.exe -enc ZQBjAGgAbw=="]})
    assert any(
        item["rule"] == "PS_ENCODED_COMMAND"
        and item["technique"] == "T1059.001"
        and item["tactic"] == "Execution"
        for item in findings
    )


def test_baseline_checks_flag_unknown_process() -> None:
    findings = baseline_checks(
        {"processes": ["evil.exe | C:\\evil.exe"]}, {"processes": ["explorer.exe"]}
    )
    assert len(findings) == 1
    assert findings[0]["rule"] == "BASELINE_NEW_PROCESSES"


def test_hunt_vm_with_fake_transport() -> None:
    baseline = json.loads((ROOT / "baseline.json").read_text(encoding="utf-8"))
    report = hunt_vm(
        {"name": "fake-vm", "host": "127.0.0.1", "os": "windows"},
        baseline,
        FakeTransport(),
    )
    assert report["vm"] == "fake-vm"
    assert report["errors"] == []
    assert report["findings"]
    assert report["findings"][0]["severity"] in {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
    layer = build_layer(report)
    assert layer["techniques"]
    assert all("techniqueID" in item for item in layer["techniques"])
