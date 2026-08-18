from __future__ import annotations

import os
import pty
import select
import signal
import subprocess
import time
from typing import Protocol

from wiki_spike.infrastructure import keystore as ks

_SECURITY = "/usr/bin/security"
_DUPLICATE_ITEM = 45
_ITEM_NOT_FOUND = 44
_COMMAND_TIMEOUT_SECONDS = 30


class ProductionCustodyError(ks.KeyStoreError):
    """Production custody failed closed."""


class KeychainBackend(Protocol):
    def add(self, *, service: str, account: str, secret: str) -> bool: ...

    def read(self, *, service: str, account: str) -> str | None: ...

    def delete(self, *, service: str, account: str) -> bool: ...


class SecurityCliKeychainBackend:
    @staticmethod
    def _run(
        arguments: list[str],
        *,
        stdin: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [_SECURITY, *arguments],
                input=stdin,
                capture_output=True,
                check=False,
                text=True,
                timeout=_COMMAND_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ProductionCustodyError(
                "macOS Keychain command could not complete"
            ) from None

    @staticmethod
    def _run_prompted(arguments: list[str], *, secret: str) -> int:
        pid, master_fd = pty.fork()
        if pid == 0:
            try:
                os.execv(_SECURITY, [_SECURITY, *arguments])
            except OSError:
                os._exit(127)
        deadline = time.monotonic() + _COMMAND_TIMEOUT_SECONDS
        output_tail = b""
        prompts_answered = 0
        prompts = (
            b"password data for new item:",
            b"retype password for new item:",
        )
        try:
            while True:
                waited_pid, status = os.waitpid(pid, os.WNOHANG)
                if waited_pid == pid:
                    return os.waitstatus_to_exitcode(status)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    os.kill(pid, signal.SIGKILL)
                    _ = os.waitpid(pid, 0)
                    raise ProductionCustodyError(
                        "macOS Keychain command could not complete"
                    )
                readable, _, _ = select.select([master_fd], [], [], remaining)
                if not readable:
                    continue
                try:
                    chunk = os.read(master_fd, 1024)
                except OSError:
                    chunk = b""
                output_tail = (output_tail + chunk)[-1024:]
                if prompts_answered < len(prompts) and prompts[
                    prompts_answered
                ] in output_tail:
                    _ = os.write(master_fd, secret.encode("ascii") + b"\n")
                    prompts_answered += 1
                    output_tail = b""
        finally:
            os.close(master_fd)

    def add(self, *, service: str, account: str, secret: str) -> bool:
        returncode = self._run_prompted(
            ["add-generic-password", "-a", account, "-s", service, "-w"],
            secret=secret,
        )
        if returncode == 0:
            return True
        if returncode == _DUPLICATE_ITEM:
            return False
        raise ProductionCustodyError("macOS Keychain create failed")

    def read(self, *, service: str, account: str) -> str | None:
        result = self._run(
            ["find-generic-password", "-a", account, "-s", service, "-w"]
        )
        if result.returncode == 0:
            return result.stdout.rstrip("\n")
        if result.returncode == _ITEM_NOT_FOUND:
            return None
        raise ProductionCustodyError("macOS Keychain read failed")

    def delete(self, *, service: str, account: str) -> bool:
        result = self._run(
            ["delete-generic-password", "-a", account, "-s", service]
        )
        if result.returncode == 0:
            return True
        if result.returncode == _ITEM_NOT_FOUND:
            return False
        raise ProductionCustodyError("macOS Keychain delete failed")


__all__ = [
    "KeychainBackend",
    "ProductionCustodyError",
    "SecurityCliKeychainBackend",
]
