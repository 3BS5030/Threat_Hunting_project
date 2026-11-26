from __future__ import annotations

from hunting.checks import (
    authentication_log_path,
    collect_data,
    detect_linux_distribution,
    normalize_auth_event,
)
from transport.ssh import SSHTransport


class FakeTransport:
    def __init__(self, os_release: str = "", auth_lines: list[str] | None = None) -> None:
        self.os_release = os_release
        self.auth_lines = list(auth_lines or [])
        self.commands: list[str] = []

    def run(self, command: str, timeout: int = 60) -> str:
        self.commands.append(command)
        if "/etc/os-release" in command:
            return self.os_release
        if "/var/log/secure" in command or "/var/log/auth.log" in command:
            return "\n".join(self.auth_lines)
        return ""


def test_authentication_log_paths_match_distribution() -> None:
    assert authentication_log_path("centos") == "/var/log/secure"
    assert authentication_log_path("rhel") == "/var/log/secure"
    assert authentication_log_path("ubuntu") == "/var/log/auth.log"
    assert authentication_log_path("debian") == "/var/log/auth.log"
    assert authentication_log_path("unknown") is None


def test_centos_collects_secure_log_events() -> None:
    line = (
        "Nov 25 10:12:34 centos7 sshd[1234]: Failed password for invalid user bob "
        "from 192.0.2.10 port 43210 ssh2"
    )
    transport = FakeTransport("ID=centos\nID_LIKE=rhel fedora\n", [line])
    data, errors = collect_data(transport, "linux")

    assert errors == []
    assert data["distribution"] == ["centos"]
    assert data["secure_log"]
    assert data["secure_log"][0]["source"] == "/var/log/secure"
    assert data["secure_log"][0]["event_type"] == "failed_password"
    assert data["secure_log"][0]["username"] == "bob"
    assert data["secure_log"][0]["source_ip"] == "192.0.2.10"
    assert any("/var/log/secure" in command for command in transport.commands)


def test_ubuntu_collects_auth_log_events() -> None:
    line = (
        "Nov 25 10:12:34 ubuntu sshd[1234]: Accepted password for alice "
        "from 192.0.2.10 port 43210 ssh2"
    )
    transport = FakeTransport("ID=ubuntu\nID_LIKE=debian\n", [line])
    data, errors = collect_data(transport, "linux")

    assert errors == []
    assert data["distribution"] == ["ubuntu"]
    assert data["secure_log"][0]["source"] == "/var/log/auth.log"
    assert data["secure_log"][0]["event_type"] == "successful_login"
    assert any("/var/log/auth.log" in command for command in transport.commands)


def test_detect_linux_distribution_reads_os_release() -> None:
    assert detect_linux_distribution(FakeTransport("ID=rocky\nID_LIKE=rhel centos fedora\n")) == "rocky"
    assert detect_linux_distribution(FakeTransport("ID=linuxmint\nID_LIKE=ubuntu debian\n")) == "linuxmint"


def test_secure_log_permission_error_is_reported() -> None:
    transport = FakeTransport(
        "ID=centos\n", ["__COLLECT_ERROR__ permission denied: /var/log/secure"]
    )
    data, errors = collect_data(transport, "linux")

    assert data["secure_log"] == []
    assert any("permission denied: /var/log/secure" in item for item in errors)


def test_secure_log_missing_error_is_reported() -> None:
    transport = FakeTransport("ID=ubuntu\n", ["__COLLECT_ERROR__ missing: /var/log/auth.log"])
    data, errors = collect_data(transport, "linux")

    assert data["secure_log"] == []
    assert any("missing: /var/log/auth.log" in item for item in errors)


def test_normalize_auth_event_extracts_sudo_fields() -> None:
    event = normalize_auth_event(
        "Nov 25 10:30:01 centos7 sudo: alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
        "/var/log/secure",
    )
    assert event["event_type"] == "sudo_command"
    assert event["command_user"] == "alice"
    assert event["target_user"] == "root"
    assert event["command"] == "/bin/bash"


class StructuredFakeTransport:
    def __init__(self, os_release: str, files: dict[str, list[str]]) -> None:
        self.os_release = os_release
        self.files = files

    def run(self, command: str, timeout: int = 60) -> str:
        return str(self.run_result(command, timeout=timeout)["stdout"])

    def run_result(self, command: str, timeout: int = 60) -> dict[str, object]:
        if "/etc/os-release" in command:
            stdout = self.os_release
        else:
            stdout = ""
            for fragment, lines in self.files.items():
                if fragment in command:
                    stdout = "\n".join(lines)
                    break
        return {
            "ok": True,
            "stdout": stdout,
            "stderr": "",
            "exit_code": 0,
            "error": None,
        }


def test_collect_data_uses_integrated_collector_for_linux_logs() -> None:
    auth_line = (
        "Nov 25 10:12:34 centos7 sshd[1234]: Failed password for invalid user bob "
        "from 192.0.2.10 port 43210 ssh2"
    )
    syslog_lines = ["Nov 25 10:00:00 centos7 systemd: Started OpenSSH server daemon."]
    transport = StructuredFakeTransport(
        "ID=centos\nID_LIKE=rhel fedora\n",
        {"/var/log/secure": [auth_line], "/var/log/messages": syslog_lines},
    )

    data, errors = collect_data(transport, "linux")

    assert errors == []
    assert data["auth"] == [auth_line]
    assert data["syslog"] == syslog_lines
    assert data["secure_log"][0]["event_type"] == "failed_password"
    assert data["secure_log"][0]["source"] == "/var/log/secure"


class FakeResult:
    stdout = "ok"
    stderr = "warn"
    return_code = 1
    failed = True


class FakeConnection:
    def run(self, *_args: object, **_kwargs: object) -> FakeResult:
        return FakeResult()

    def close(self) -> None:
        return None


def test_ssh_transport_run_result_exposes_stderr_and_exit_code() -> None:
    transport = SSHTransport({"name": "vm", "host": "host"})
    transport.connection = FakeConnection()

    result = transport.run_result("id", timeout=5)

    assert result["ok"] is False
    assert result["stdout"] == "ok"
    assert result["stderr"] == "warn"
    assert result["exit_code"] == 1
    assert transport.run("id") == "ok"
