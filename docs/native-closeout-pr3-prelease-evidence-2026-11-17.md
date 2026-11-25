# Native managed Worktree closeout: prelease evidence (2026-11-17)

## Identity and release boundary

- Identity: `ruoshui`; canonical governance repository: `luoshuling628-lab/ruoshui-ai-os`.
- Fresh-read Active Runtime: `RUNTIME-20261113-003`, exact SEALED bundle blob `a08a95e1c254dce87be5c487c257f3da9873a2bf`, verified.
- WebCodex candidate: PR #3 at baseline `7b402e97bdce93b864243248c125b1cbb47cdb3b` plus the test and this evidence note.
- Production native deletion is explicitly disabled in `crates/webcodex-runner/src/webcodex_runner/dispatch.rs` (`RELEASE_ADMITTED=false`).
- No production data deletion, live Runner restart, PR merge, or Runtime promotion was performed.

## Independently executed evidence

1. Built the candidate `webcodex-server` and `webcodex-runner` executable processes on Windows; both cargo builds exited 0.
2. Ran `python scripts/e2e_native_closeout_release_fence.py --bin-dir <isolated target/debug>` with actual isolated Server/Runner processes and temporary credentials, registry and Project:
   - PASS: ordinary Project credential cannot access admin-only closeout admission; sentinel containing unique content is preserved.
   - PASS: restart the Server process independently; no privilege escalation or sentinel deletion.
   - PASS: restart the Runner process independently; no privilege escalation or sentinel deletion.
   - The test is intentionally a **negative-path cross-process E2E**; it does **not** claim a native removal occurred.
3. Prior Runner real-Git fixture `native_closeout_full_runner_transaction_is_durable_and_idempotent` passed (1/1) with added fault injections at `git_removed` and `prepared` phases, unique-file blocking and exact receipt verification.
4. `bash scripts/release_check.sh --static-only` in Windows Git Bash: **FAIL at Stage 2**. A WindowsApps `python3` shim initially made tooling unavailable. Re-running with a bash-exported `python3` function bound to the installed Python 3.14.7 executed **888 Python tests: 16 failures, 158 errors, 64 skipped**. One observed error was `ModuleNotFoundError: No module named 'scripts'` from subprocess-based release tooling; this is a host-environment diagnostic, not grounds to waive the gate.
5. GitHub PR HEAD previously returned **zero associated Actions workflow runs** and **zero commit status checks**. PR #3 was Draft with **zero independent reviews**.

## Admission decision: NO-GO

The negative-path cross-process E2E and Runner crash-replay fixtures cannot substitute for the complete positive effect path. Before release:

- Establish independently verified trusted Owner issuance of the immutable deletion intent, including origin/ref reachability and exact Runner identity.
- Execute a complete **disposable-only** Server -> Runner native deletion -> Runner terminal journal -> Server receipt -> exact Registry CAS -> Session durable-lease release sequence with process restart, lost receipt, stale instance, and unique-content rejection.
- Prove no double execution and fail-closed behavior during mid-phase crashes using **actual independently launched Server and Runner processes**.
- Obtain complete independent CI Full Prelease and review evidence. Do not mark missing CI or reviews as PASS.
- Only after protected admission may code review, merge, controlled binary rollout, and fresh post-release Runtime validation proceed.

No change to `RELEASE_ADMITTED` or the production recovery opt-in setting is authorized by this evidence document.
