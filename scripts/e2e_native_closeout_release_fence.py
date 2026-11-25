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

    def prepare(self):
        # All Git objects, recovery refs, allowed roots and service credentials
        # belong to this disposable fixture, never to a production Project.
        super().prepare()
        stop(self.runner)
        self.runner = None
        config = self.root / "runner.toml"
        old = "allowed_roots = [" + json.dumps(str(self.project_dir)) + "]"
        content = config.read_text(encoding="utf-8")
        check(content.count(old) == 1, "fixture policy binding drifted")
        config.write_text(content.replace(old, "allowed_roots = [" +
                          json.dumps(str(self.root)) + "]"), encoding="utf-8")
        self.git(self.project_dir, "init", "-b", "main")
        self.git(self.project_dir, "config", "user.name", "Closeout fixture")
        self.git(self.project_dir, "config", "user.email", "fixture@example.invalid")
        (self.project_dir / "README.md").write_text("isolated closeout fixture\n")
        self.git(self.project_dir, "add", "README.md")
        self.git(self.project_dir, "commit", "-m", "fixture baseline")
        remote = self.root / "recovery.git"
        self.git(self.root, "init", "--bare", str(remote))
        self.git(self.project_dir, "remote", "add", "origin", str(remote))
        self.git(self.project_dir, "push", "origin", "main")
        self.runner = self.launch("webcodex-runner", ["--config", str(config)], self.env)
        self.wait_ready(self.project, self.owner)

    @staticmethod
    def git(cwd: Path, *args: str) -> str:
        return subprocess.run(["git", "-C", str(cwd), *args], check=True,
                              capture_output=True, text=True, timeout=30).stdout.strip()

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

        # Create a real managed child while the source is clean. The sentinel
        # is deliberately untracked in the source, so move its creation after
        # the worktree request and preserve it throughout subsequent restarts.
        sentinel.unlink()
        before = self.git(self.project_dir, "worktree", "list", "--porcelain")
        managed = tool("work_on_project", {
            "project": self.project, "mode": "worktree", "base_ref": "HEAD",
            "instruction": "isolated native closeout fixture",
        })
        child_session = managed["session_id"]
        check(managed.get("worktree", {}).get("managed") is True,
              "fixture did not create a managed worktree")
        after = self.git(self.project_dir, "worktree", "list", "--porcelain")
        check(before != after, "managed worktree was not physically created")
        sentinel.write_text("NEVER_DELETE_UNIQUE_CONTENT\n", encoding="utf-8")
        child_closed = tool("close_session", {"session_id": child_session})
        check(child_closed.get("lifecycle") == "closed",
              "managed child Session did not durably close")
        check(self.git(self.project_dir, "worktree", "list", "--porcelain") == after,
              "unadmitted Runner removed a managed worktree")
        print("PASS: real managed worktree close preserved release fence")

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
