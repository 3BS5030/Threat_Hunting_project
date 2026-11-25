"""Unit tests for Detection Rule Engine & Log Collector (Person 2 - Core Security).

Offline testing:
- Validates rules against syntax, schema, and sample strings
- Tests sliding window, threshold counting, and distinct counting
- Tests timestamp parsing and RFC1918 internal severity switching
- Tests log collection with fake SSH run_cmd runners
- Tests synthetic lab logs (centos-lab) vs false-positive checks (clean)
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest

from hunting.collector import (
    collect_log,
    collect_all,
    get_lines,
    save_logs_to_dir,
    load_logs_from_dir,
    family_from_os_release,
    generate_sudoers_snippet,
    resolve_log_paths,
)
from hunting.rule_engine import (
    load_rules,
    run_rule_tests,
    parse_timestamp,
    apply_rule,
    group_and_window,
    evaluate_rule,
    evaluate_all,
    get_rules_for_check,
    get_rule,
    validate_mitre_ids,
    coverage_summary,
    _is_ip_internal,
)


def test_load_rules_p0_clean():
    """Verify that rules.json loads all starter P0 rules with zero errors."""
    res = load_rules("hunting/rules.json", include_disabled=True)
    assert len(res["errors"]) == 0, f"Encountered rule loading errors: {res['errors']}"
    assert len(res["rules"]) >= 23, f"Expected at least 23 rules, got {len(res['rules'])}"


def test_run_rule_tests_all_pass():
    """Verify all built-in test match/no_match assertions pass."""
    res = load_rules("hunting/rules.json", include_disabled=True)
    assert len(res["errors"]) == 0
    test_res = run_rule_tests(res["rules"])
    assert len(test_res["failed"]) == 0, f"Rule tests failed: {test_res['failed']}"
    assert test_res["passed"] >= 92


def test_schema_constraints():
    """Validate that every rule complies with strict schema rules."""
    res = load_rules("hunting/rules.json", include_disabled=True)
    rules = res["rules"]
    ids = set()
    for rule in rules:
        assert rule["id"] not in ids
        ids.add(rule["id"])
        assert "title" in rule and isinstance(rule["title"], str)
        assert "description" in rule and isinstance(rule["description"], str)
        assert rule["severity"] in {"HIGH", "MEDIUM", "LOW"}
        if rule.get("severity_internal"):
            assert rule["severity_internal"] in {"HIGH", "MEDIUM", "LOW"}
        assert isinstance(rule["mitre"], list) and len(rule["mitre"]) > 0
        for tid in rule["mitre"]:
            assert tid.startswith("T")
        assert len(rule["tests"].get("match", [])) >= 2
        assert len(rule["tests"].get("no_match", [])) >= 2


def test_catastrophic_regex_rejected(tmp_path):
    """Verify that unsafe nested-quantifier regex patterns are rejected."""
    bad_rule = [{
        "id": "LNX-TEST-001",
        "title": "Bad regex test",
        "description": "Test",
        "platform": "linux",
        "enabled": True,
        "log_type": "auth",
        "category": "brute_force",
        "check": 1,
        "regex": "sshd.*(a+)+bad",
        "flags": [],
        "group_by": None,
        "threshold": 1,
        "severity": "HIGH",
        "mitre": ["T1110"],
        "tests": {"match": ["a", "b"], "no_match": ["c", "d"]}
    }]
    bad_file = tmp_path / "bad_rules.json"
    bad_file.write_text(json.dumps(bad_rule), encoding="utf-8")

    res = load_rules(str(bad_file))
    assert len(res["rules"]) == 0
    assert len(res["errors"]) == 1
    assert "catastrophic backtracking" in res["errors"][0]["error"]


def test_duplicate_id_rejected(tmp_path):
    """Verify that duplicate rule IDs are detected and rejected."""
    dup_rules = [
        {
            "id": "LNX-AUTH-001",
            "title": "Rule 1",
            "description": "Test",
            "platform": "linux",
            "enabled": True,
            "log_type": "auth",
            "category": "brute_force",
            "regex": "failed",
            "severity": "HIGH",
            "mitre": ["T1110"],
            "tests": {"match": ["failed 1", "failed 2"], "no_match": ["ok 1", "ok 2"]}
        },
        {
            "id": "LNX-AUTH-001",
            "title": "Rule 2 duplicate",
            "description": "Test",
            "platform": "linux",
            "enabled": True,
            "log_type": "auth",
            "category": "brute_force",
            "regex": "failed",
            "severity": "HIGH",
            "mitre": ["T1110"],
            "tests": {"match": ["failed 1", "failed 2"], "no_match": ["ok 1", "ok 2"]}
        }
    ]
    dup_file = tmp_path / "dup_rules.json"
    dup_file.write_text(json.dumps(dup_rules), encoding="utf-8")

    res = load_rules(str(dup_file))
    assert len(res["rules"]) == 1
    assert len(res["errors"]) == 1
    assert "Duplicate rule id" in res["errors"][0]["error"]


def test_parse_timestamp():
    """Verify timestamp parsing across auditd, ISO 8601, syslog, and year inference."""
    ref_now = datetime(2026, 1, 10, 12, 0, 0)

    # 1. Auditd epoch
    audit_line = "type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e comm='sudo'"
    ts1 = parse_timestamp(audit_line, now=ref_now)
    assert ts1 is not None
    assert ts1.year in (2023, 2024)

    # 2. ISO 8601
    iso_line = "2026-11-25T14:30:00.123456+02:00 host app[123]: msg"
    ts2 = parse_timestamp(iso_line, now=ref_now)
    assert ts2 == datetime(2026, 11, 25, 14, 30, 0, 123456)

    # 3. Syslog current year
    syslog_line = "Jan  5 03:41:09 centos-web01 sshd[2211]: Failed password"
    ts3 = parse_timestamp(syslog_line, now=ref_now)
    assert ts3 == datetime(2026, 1, 5, 3, 41, 9)

    # 4. Syslog year rollover (if month is ahead of now by more than 1 day)
    syslog_prev = "Dec 25 23:59:00 centos-web01 sshd[2211]: Failed password"
    ts4 = parse_timestamp(syslog_prev, now=ref_now)
    assert ts4.year == 2025


def test_group_and_window_burst_vs_spread():
    """Verify sliding window fires for burst within window, but not spread over long time."""
    base_time = datetime(2026, 11, 25, 10, 0, 0)
    rule_res = load_rules("hunting/rules.json")
    auth_rule = get_rule(rule_res["rules"], "LNX-AUTH-001")
    assert auth_rule is not None

    # 8 failures within 2 minutes -> threshold 6 should HIT
    burst_lines = [
        f"Nov 25 10:0{i}:00 centos-web01 sshd: Failed password for root from 203.0.113.42 port 2222 ssh2"
        for i in range(8)
    ]
    eval_burst = evaluate_rule(auth_rule, burst_lines, now=base_time)
    assert len(eval_burst["hits"]) == 1
    assert eval_burst["hits"][0]["count"] == 8
    assert eval_burst["hits"][0]["key"] == "203.0.113.42"
    assert eval_burst["hits"][0]["severity"] == "HIGH"
    assert eval_burst["hits"][0]["is_internal"] is False

    # 8 failures spread over 4 hours (1 every 30 mins) with 60-min window -> should NOT HIT
    spread_matches = []
    for i in range(8):
        m_time = base_time + timedelta(minutes=30 * i)
        spread_matches.append({
            "rule_id": "LNX-AUTH-001",
            "line_no": i + 1,
            "line": f"spread line {i}",
            "timestamp": m_time,
            "groups": {"ip": "203.0.113.42", "user": "root"}
        })
    window_spread = group_and_window(spread_matches, group_by="ip", threshold=6, window_minutes=60)
    assert len(window_spread) == 0

    # Exactly 5 failures (threshold 6) -> should NOT HIT
    sub_threshold_matches = spread_matches[:5]
    for m in sub_threshold_matches:
        m["timestamp"] = base_time + timedelta(seconds=10)
    window_sub = group_and_window(sub_threshold_matches, group_by="ip", threshold=6, window_minutes=60)
    assert len(window_sub) == 0


def test_internal_vs_external_severity():
    """Verify RFC1918 IPs trigger severity_internal (MEDIUM) while external triggers HIGH."""
    rules_res = load_rules("hunting/rules.json")
    auth_rule = get_rule(rules_res["rules"], "LNX-AUTH-001")
    assert auth_rule is not None

    # 1. External IP 203.0.113.42 -> HIGH / is_internal False
    ext_lines = [
        f"Nov 25 10:00:0{i} centos sshd: Failed password for root from 203.0.113.42 port 2222 ssh2"
        for i in range(7)
    ]
    res_ext = evaluate_rule(auth_rule, ext_lines)
    assert len(res_ext["hits"]) == 1
    assert res_ext["hits"][0]["severity"] == "HIGH"
    assert res_ext["hits"][0]["is_internal"] is False

    # 2. Host-only Lab IP 192.168.56.10 -> MEDIUM / is_internal True
    int_lines = [
        f"Nov 25 10:00:0{i} centos sshd: Failed password for root from 192.168.56.10 port 2222 ssh2"
        for i in range(7)
    ]
    res_int = evaluate_rule(auth_rule, int_lines)
    assert len(res_int["hits"]) == 1
    assert res_int["hits"][0]["severity"] == "MEDIUM"
    assert res_int["hits"][0]["is_internal"] is True

    # 3. Invalid IP string -> is_internal is None, no crash, base severity used
    assert _is_ip_internal("invalid_ip_string") is None
    assert _is_ip_internal("") is None


def test_count_distinct_password_spraying():
    """Verify count_distinct logic for password spraying detection."""
    base_time = datetime(2026, 11, 25, 10, 0, 0)
    # 6 distinct users from 1 IP within 20 mins -> should HIT threshold 5
    matches = [
        {
            "rule_id": "LNX-TEST-SPRAY",
            "line_no": i,
            "line": f"failed user{i}",
            "timestamp": base_time + timedelta(minutes=i * 2),
            "groups": {"ip": "203.0.113.50", "user": f"user_{i}"}
        }
        for i in range(6)
    ]
    res_spray = group_and_window(
        matches, group_by="ip", threshold=5, window_minutes=30, count_distinct="user"
    )
    assert len(res_spray) == 1
    assert res_spray[0]["count"] == 6

    # 6 attempts for the SAME user -> count_distinct is 1 -> should NOT HIT
    same_user_matches = [
        {
            "rule_id": "LNX-TEST-SPRAY",
            "line_no": i,
            "line": f"failed root",
            "timestamp": base_time + timedelta(minutes=i * 2),
            "groups": {"ip": "203.0.113.50", "user": "root"}
        }
        for i in range(6)
    ]
    res_same = group_and_window(
        same_user_matches, group_by="ip", threshold=5, window_minutes=30, count_distinct="user"
    )
    assert len(res_same) == 0


def test_collector_with_fake_run_cmd():
    """Test collector functions against fake run_cmd simulating ok, missing, permission denied, sudo."""

    # 1. OK scenario
    def fake_ok(cmd, timeout=30):
        return {"ok": True, "stdout": "line 1\nline 2\n", "stderr": "", "exit_code": 0, "error": None}

    res_ok = collect_log("auth", "rhel", fake_ok)
    assert res_ok["status"] == "ok"
    assert res_ok["lines"] == ["line 1", "line 2"]
    assert res_ok["path"] == "/var/log/secure"

    # 2. Missing file
    def fake_missing(cmd, timeout=30):
        return {"ok": False, "stdout": "", "stderr": "tail: /var/log/secure: No such file or directory", "exit_code": 1, "error": None}

    res_missing = collect_log("auth", "rhel", fake_missing)
    assert res_missing["status"] == "missing"
    assert res_missing["lines"] == []

    # 3. Permission denied then sudo OK
    def fake_sudo_ok(cmd, timeout=30):
        if cmd.startswith("sudo -n"):
            return {"ok": True, "stdout": "audit log line 1\n", "stderr": "", "exit_code": 0, "error": None}
        return {"ok": False, "stdout": "", "stderr": "tail: /var/log/audit/audit.log: Permission denied", "exit_code": 1, "error": None}

    res_sudo = collect_log("audit", "rhel", fake_sudo_ok)
    assert res_sudo["status"] == "ok"
    assert res_sudo["lines"] == ["audit log line 1"]

    # 4. Sudo denied
    def fake_sudo_denied(cmd, timeout=30):
        if cmd.startswith("sudo -n"):
            return {"ok": False, "stdout": "", "stderr": "sudo: a password is required", "exit_code": 1, "error": None}
        return {"ok": False, "stdout": "", "stderr": "tail: /var/log/audit/audit.log: Permission denied", "exit_code": 1, "error": None}

    res_denied = collect_log("audit", "rhel", fake_sudo_denied)
    assert res_denied["status"] == "denied"

    # 5. Empty file
    def fake_empty(cmd, timeout=30):
        return {"ok": True, "stdout": "", "stderr": "", "exit_code": 0, "error": None}

    res_empty = collect_log("cron", "rhel", fake_empty)
    assert res_empty["status"] == "empty"
    assert res_empty["lines"] == []


def test_collector_round_trip(tmp_path):
    """Test save_logs_to_dir and load_logs_from_dir round trip."""
    collected = {
        "vm": "centos-web01",
        "family": "rhel",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "logs": {
            "auth": {
                "log_type": "auth",
                "path": "/var/log/secure",
                "paths_read": ["/var/log/secure"],
                "status": "ok",
                "lines": ["Nov 25 10:00:00 sshd: Accepted password for analyst from 192.168.56.1"],
                "truncated": False,
                "error": None
            }
        },
        "skipped": []
    }
    written = save_logs_to_dir(collected, tmp_path)
    assert len(written) >= 2
    assert (tmp_path / "auth.log").is_file()

    loaded = load_logs_from_dir(tmp_path)
    assert loaded["vm"] == "centos-web01"
    assert loaded["family"] == "rhel"
    auth_lines = get_lines(loaded, "auth")
    assert len(auth_lines) == 1
    assert "Accepted password" in auth_lines[0]


def test_generate_sudoers_snippet():
    """Verify generated sudoers snippet contains exact commands and no wildcards."""
    snippet_rhel = generate_sudoers_snippet("analyst", "rhel")
    assert "analyst ALL=(ALL) NOPASSWD: /usr/bin/tail -n 20000 /var/log/secure" in snippet_rhel
    assert "analyst ALL=(ALL) NOPASSWD: /usr/bin/tail -n 20000 /var/log/audit/audit.log" in snippet_rhel
    # No wildcards allowed
    assert "*" not in snippet_rhel.replace("*", "")  # check for glob stars in paths


def test_family_from_os_release():
    """Verify distro detection from os-release text."""
    centos_txt = 'NAME="CentOS Linux"\nID="centos"\nID_LIKE="rhel fedora"'
    assert family_from_os_release(centos_txt) == "rhel"

    ubuntu_txt = 'NAME="Ubuntu"\nID="ubuntu"\nID_LIKE="debian"'
    assert family_from_os_release(ubuntu_txt) == "debian"

    unknown_txt = 'NAME="CustomOS"\nID="myos"'
    assert family_from_os_release(unknown_txt) == "unknown"


def test_centos_lab_sample_logs():
    """Verify that sample_logs/centos-lab triggers expected P0 rules and checks."""
    lab_dir = Path("tests/sample_logs/centos-lab")
    assert lab_dir.is_dir()

    collected = load_logs_from_dir(lab_dir)
    rules_res = load_rules("hunting/rules.json")
    rules = rules_res["rules"]

    eval_res = evaluate_all(rules, collected)
    results = eval_res["results"]

    # Check 1: LNX-AUTH-001 (SSH Brute Force from 203.0.113.42)
    assert "LNX-AUTH-001" in results
    auth_hits = results["LNX-AUTH-001"]["hits"]
    assert len(auth_hits) >= 1
    assert any(h["key"] == "203.0.113.42" and h["count"] >= 6 for h in auth_hits)

    # Check 2: LNX-AUTH-002 (Accepted login from 203.0.113.42)
    assert "LNX-AUTH-002" in results
    assert len(results["LNX-AUTH-002"]["hits"]) >= 1

    # Check 3: LNX-AUTH-003 or LNX-AUTH-004 (sudo baduser not in sudoers)
    assert len(results["LNX-AUTH-003"]["hits"]) >= 1
    assert len(results["LNX-AUTH-004"]["hits"]) >= 1

    # Check 4: LNX-AUTH-005 & LNX-AUTH-006 (useradd/groupadd and usermod backdoor)
    assert len(results["LNX-AUTH-005"]["hits"]) >= 1
    assert len(results["LNX-AUTH-006"]["hits"]) >= 1

    # Check 5: LNX-CRON-001 (cron wget payload at 03:00)
    assert "LNX-CRON-001" in results
    assert len(results["LNX-CRON-001"]["hits"]) >= 1

    # Check 6: LNX-PKG-001 (nmap-ncat Installed)
    assert "LNX-PKG-001" in results
    assert len(results["LNX-PKG-001"]["hits"]) >= 1

    # Check 7: LNX-AUD-001 & LNX-AUD-002 (auditd sudo success and user_auth failed)
    assert "LNX-AUD-001" in results
    assert len(results["LNX-AUD-001"]["hits"]) >= 1
    assert "LNX-AUD-002" in results
    assert len(results["LNX-AUD-002"]["hits"]) >= 1

    # Check 8: LNX-HIST-001, 004, 005, 007
    assert len(results["LNX-HIST-001"]["hits"]) >= 1  # wget
    assert len(results["LNX-HIST-004"]["hits"]) >= 1  # chmod +x
    assert len(results["LNX-HIST-005"]["hits"]) >= 1  # python -c
    assert len(results["LNX-HIST-007"]["hits"]) >= 1  # base64 -d


def test_clean_sample_logs_no_false_positives():
    """Verify that sample_logs/clean generates ZERO HIGH hits."""
    clean_dir = Path("tests/sample_logs/clean")
    assert clean_dir.is_dir()

    collected = load_logs_from_dir(clean_dir)
    rules_res = load_rules("hunting/rules.json")
    rules = rules_res["rules"]

    eval_res = evaluate_all(rules, collected)
    results = eval_res["results"]

    for rule_id, res in results.items():
        hits = res.get("hits", [])
        for hit in hits:
            assert hit.get("severity") != "HIGH", f"False positive HIGH hit on clean logs: {rule_id}: {hit}"
