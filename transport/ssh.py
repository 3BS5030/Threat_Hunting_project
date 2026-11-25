"""Fabric-backed SSH transport: connect, run, fetch."""

from __future__ import annotations

from typing import Any

try:
    from fabric import Connection
except ImportError as exc:  # pragma: no cover - depends on local environment
    Connection = None  # type: ignore[assignment]
    _IMPORT_ERROR: Exception | None = exc
else:
    _IMPORT_ERROR = None


class SSHTransport:
    """Thin wrapper around a Fabric Connection for one VM."""

    def __init__(self, vm: dict[str, Any]) -> None:
        self.vm = vm
        self.connection: Any | None = None

    def connect(self) -> "SSHTransport":
        if Connection is None:
            raise RuntimeError(f"fabric is required for SSH: {_IMPORT_ERROR}")
        kwargs: dict[str, Any] = {}
        if self.vm.get("password"):
            kwargs["connect_kwargs"] = {"password": self.vm["password"]}
        elif self.vm.get("key_filename"):
            kwargs["connect_kwargs"] = {"key_filename": self.vm["key_filename"]}
        self.connection = Connection(
            host=self.vm.get("host", "localhost"),
            user=self.vm.get("username"),
            port=int(self.vm.get("port", 22)),
            **kwargs,
        )
        self.connection.open()
        return self

    def run(self, command: str, timeout: int = 60) -> str:
        if self.connection is None:
            self.connect()
        result = self.connection.run(command, hide=True, warn=True, timeout=timeout)
        return result.stdout or ""

    def fetch(self, remote_path: str, local_path: str) -> Any:
        if self.connection is None:
            self.connect()
        return self.connection.get(remote_path, local_path)

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def __enter__(self) -> "SSHTransport":
        return self.connect()

    def __exit__(self, *_exc: Any) -> None:
        self.close()
