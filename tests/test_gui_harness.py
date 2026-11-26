from __future__ import annotations

from gui.test_harness import build_transport, format_collection, format_report
from hunting.checks import collect_data
from hunting.engine import hunt_vm
from hunting.rule_engine import load_attack


def test_sample_transport_collects_integrated_logs() -> None:
    transport = build_transport("centos-lab")

    data, errors = collect_data(transport, "linux", timeout=10)

    assert errors == []
    assert data["auth"]
    assert data["syslog"]
    assert data["audit"]
    assert data["cron"]
    assert data["package"]
    assert data["history"]
    assert "auth: " in format_collection(data, errors)


def test_sample_transport_runs_mitre_hunt() -> None:
    transport = build_transport("centos-lab")
    vm = {"name": "centos-lab", "host": "sample-host", "os": "linux"}

    report = hunt_vm(vm, transport=transport, attack=load_attack(), timeout=10)

    assert report["errors"] == []
    assert report["findings"]
    assert any(item.get("source") == "advanced_rule_engine" for item in report["findings"])
    text = format_report(report)
    assert "MITRE status" in text
    assert "Findings by source" in text


def test_format_collection_reports_errors() -> None:
    text = format_collection(
        {"distribution": ["centos"], "auth": ["Nov 25 10:00:00 sshd: failed"]},
        ["secure_log: missing: /var/log/secure"],
    )

    assert "Errors: 1" in text
    assert "secure_log: missing: /var/log/secure" in text
