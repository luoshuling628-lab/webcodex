#!/usr/bin/env python3
"""Real isolated Server + Runner negative closeout E2E across both restarts.

This intentionally cannot claim positive native removal while the production
Runner release gate is disabled. No production credentials, paths, or process
are touched; every Project and process is created under TemporaryDirectory.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from e2e_local_agent_execution import Acceptance
from e2e_session_continuity_ws import check
import os


def stop(process):
    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        # Runner can own child processes retaining its log file after a
        # Windows terminate(). Kill only this isolated fixture process tree,
        # never any production process or unrelated Runner.
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=15,
        )
    else:
        process.send_signal(__import__("signal").SIGINT)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


class CloseoutFenceSmoke(Acceptance):
    def close(self):
        stop(self.runner)
        stop(self.server)
        for log in self.logs:
            log.close()

    def launch(self, binary: str, args: list[str], env: dict) -> subprocess.Popen:
        # Windows binaries are named .exe. POSIX uses plain names.
        executable = self.bin_dir / (binary + (".exe" if __import__("os").name == "nt" else ""))
        log = (self.root / f"{binary}-{len(self.logs)}.log").open("wb")
        self.logs.append(log)
        return subprocess.Popen([str(executable), *args], env=env,
                                stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def probe(self) -> None:
        self.prepare()
        sentinel = self.project_dir / "unique-business-content.txt"
        sentinel.write_text("NEVER_DELETE_UNIQUE_CONTENT\n", encoding="utf-8")
        payload = {"project": self.project, "expected_revision": "sha256:" + "a" * 64}
        endpoint = "/api/admin/projects/native-closeout-admission"
        # A non-admin must not acquire a delete capability.
        rejected = self.post(endpoint, payload, self.owner)
        check(rejected.get("status") == 403 and "error" in rejected,
              "ordinary Project credential bypassed admin-only admission")
        observed = self.post(endpoint, payload, self.bootstrap)
        check(observed.get("delete_authorized") is not True,
              "read-only admission advertised destructive authority")
        check(sentinel.read_text(encoding="utf-8") == "NEVER_DELETE_UNIQUE_CONTENT\n",
              "native closeout altered unique Project data")
        print("PASS: isolated Server/Runner closeout admission did not remove unique data")

        # Exercise the real trusted Session close event over Server HTTP
        # against an independently running Runner, not just admission.
        def tool(name: str, params: dict) -> dict:
            result = self.post("/api/tools/call",
                               {"tool": name, "params": params}, self.bootstrap)
            check(result.get("success") is True,
                  f"{name} failed: {result}")
            return result["output"]

        started = tool("start_session", {
            "project": self.project,
            "title": "isolated-native-owner-wakeup",
        })
        session_id = started["session_id"]
        closed = tool("close_session", {"session_id": session_id})
        check(closed.get("lifecycle") == "closed"
              and closed.get("already_closed") is False,
              "first durable close did not complete")
        replay = tool("close_session", {"session_id": session_id})
        check(replay.get("already_closed") is True,
              "idempotent close replay did not hold")
        check(sentinel.read_text(encoding="utf-8") == "NEVER_DELETE_UNIQUE_CONTENT\n",
              "Session close wakeup deleted unique Project content")
        print("PASS: real Server Session close wakeup completed; idempotent; no delete")

        stop(self.server)
        self.server = None
        self.start_server()
        self.wait_ready(self.project, self.owner)
        check(sentinel.is_file(), "Server restart lost the unique file")
        persisted = tool("read_session_summary", {"session_id": session_id})
        check(persisted.get("lifecycle") == "closed",
              "Server restart lost the durable closed Session")
        observed = self.post(endpoint, payload, self.bootstrap)
        check(observed.get("delete_authorized") is not True,
              "Server restart elevated read-only admission")
        print("PASS: independent Server restart retained fail-closed closeout boundary")

        stop(self.runner)
        self.runner = self.launch("webcodex-runner", ["--config", str(self.root / "runner.toml")], self.env)
        self.wait_ready(self.project, self.owner)
        check(sentinel.read_text(encoding="utf-8") == "NEVER_DELETE_UNIQUE_CONTENT\n",
              "Runner restart altered unique data")
        observed = self.post(endpoint, payload, self.bootstrap)
        check(observed.get("delete_authorized") is not True,
              "Runner restart elevated read-only admission")
        print("PASS: independent Runner restart retained the unique file and delete gate")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="native-closeout-cross-process-") as root:
        smoke = CloseoutFenceSmoke(args.bin_dir.resolve(), Path(root))
        try:
            smoke.probe()
        finally:
            smoke.close()


if __name__ == "__main__":
    main()
