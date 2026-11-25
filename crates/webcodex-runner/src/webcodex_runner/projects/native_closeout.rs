//! Durable, fail-closed native managed-worktree closeout journal.
//!
//! Only the existing native closeout Owner may use this ledger while it owns
//! both the Server Session fence and Runner job-start fence. A journal alone
//! never authorizes filesystem removal.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CloseoutPhase {
    Prepared,
    GitRemoved,
    Unregistered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeCloseoutRecord {
    pub operation_id: String,
    pub project_id: String,
    pub expected_revision: String,
    pub expected_incarnation: String,
    pub expected_head: String,
    pub expected_root_fingerprint: String,
    pub expected_origin_url: String,
    pub expected_remote_ref: String,
    pub source_root: String,
    pub worktree_root: String,
    pub phase: CloseoutPhase,
}

fn validate_record(record: &NativeCloseoutRecord) -> Result<(), &'static str> {
    if uuid::Uuid::parse_str(&record.operation_id).is_err()
        || record.project_id.is_empty()
        || !record
            .project_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        || uuid::Uuid::parse_str(&record.expected_incarnation).is_err()
        || record.expected_revision.is_empty()
        || record.expected_root_fingerprint.is_empty()
        || record.expected_origin_url.is_empty()
        || record.source_root.is_empty()
        || record.worktree_root.is_empty()
        || !record.expected_remote_ref.starts_with("refs/heads/")
        || !matches!(record.expected_head.len(), 40 | 64)
        || !record.expected_head.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err("native_closeout_invalid_identity");
    }
    Ok(())
}

fn ledger_path(registry: &Path, record: &NativeCloseoutRecord) -> PathBuf {
    registry.join(format!(
        ".native-closeout-{}-{}.json",
        record.project_id, record.operation_id
    ))
}

fn fsync_dir(dir: &Path) -> Result<(), &'static str> {
    // Keep the same cross-platform directory durability semantics as the
    // existing project-registry writer; missing durability is indeterminate.
    super::registration::sync_dir(dir).map_err(|_| "native_closeout_journal_indeterminate")
}

fn persist(record: &NativeCloseoutRecord, registry: &Path) -> Result<(), &'static str> {
    validate_record(record)?;
    let path = ledger_path(registry, record);
    let temp = registry.join(format!(
        ".native-closeout-{}-{}.pending",
        record.project_id,
        uuid::Uuid::new_v4()
    ));
    let bytes = serde_json::to_vec(record).map_err(|_| "native_closeout_journal_indeterminate")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|_| "native_closeout_journal_indeterminate")?;
    if file.write_all(&bytes).is_err() || file.sync_all().is_err() {
        return Err("native_closeout_journal_indeterminate");
    }
    drop(file);
    fs::rename(&temp, &path).map_err(|_| "native_closeout_journal_indeterminate")?;
    fsync_dir(registry)?;
    Ok(())
}

/// Create or recover one exact durable intent; an operation id may never be
/// recycled for a different Project incarnation or input. Recovery is explicit.
pub(super) fn begin_or_read(
    registry: &Path,
    candidate: NativeCloseoutRecord,
) -> Result<NativeCloseoutRecord, &'static str> {
    validate_record(&candidate)?;
    if candidate.phase != CloseoutPhase::Prepared {
        return Err("native_closeout_invalid_phase");
    }
    let path = ledger_path(registry, &candidate);
    if path.exists() {
        let saved: NativeCloseoutRecord = serde_json::from_slice(
            &fs::read(&path).map_err(|_| "native_closeout_journal_indeterminate")?,
        )
        .map_err(|_| "native_closeout_journal_indeterminate")?;
        validate_record(&saved)?;
        let mut normalized = saved.clone();
        normalized.phase = CloseoutPhase::Prepared;
        if normalized != candidate {
            return Err("native_closeout_idempotency_conflict");
        }
        return Ok(saved);
    }
    persist(&candidate, registry)?;
    Ok(candidate)
}

/// Strict monotonic phases. Call only after independently verifying that the
/// associated effect has occurred. Never infer deletion from this receipt.
pub(super) fn advance(
    registry: &Path,
    previous: &NativeCloseoutRecord,
    next: CloseoutPhase,
) -> Result<NativeCloseoutRecord, &'static str> {
    let current: NativeCloseoutRecord = serde_json::from_slice(
        &fs::read(ledger_path(registry, previous))
            .map_err(|_| "native_closeout_journal_indeterminate")?,
    )
    .map_err(|_| "native_closeout_journal_indeterminate")?;
    if &current != previous {
        return Err("native_closeout_journal_revision_conflict");
    }
    let allowed = matches!(
        (current.phase, next),
        (CloseoutPhase::Prepared, CloseoutPhase::GitRemoved)
            | (CloseoutPhase::GitRemoved, CloseoutPhase::Unregistered)
    );
    if !allowed {
        return Err("native_closeout_invalid_phase");
    }
    let mut updated = current;
    updated.phase = next;
    persist(&updated, registry)?;
    Ok(updated)
}

/// Independent read-only reconciliation against the exact immutable Runner
/// intent, its durable terminal phase, current registration, and Git worktree
/// membership. Never trusts a missing directory or a journal phase alone.
/// The existing Runner registry lock excludes concurrent register/unregister.
#[allow(dead_code)]
pub(super) fn read_verified_terminal(
    registry: &Path,
    expected: &NativeCloseoutRecord,
) -> Result<NativeCloseoutRecord, &'static str> {
    validate_record(expected)?;
    if expected.phase != CloseoutPhase::Prepared {
        return Err("native_closeout_invalid_phase");
    }
    let _lock = super::project_registry_write_lock()
        .lock()
        .map_err(|_| "native_closeout_registry_lock_failed")?;
    let registry = super::super::shell::canonicalize_existing(registry)
        .map_err(|_| "native_closeout_registry_missing")?;
    // A missing journal is NOT evidence of completion; do not fabricate it.
    let bytes = fs::read(ledger_path(&registry, expected))
        .map_err(|_| "native_closeout_terminal_not_proven")?;
    let saved: NativeCloseoutRecord =
        serde_json::from_slice(&bytes).map_err(|_| "native_closeout_journal_indeterminate")?;
    validate_record(&saved)?;
    let mut normalized = saved.clone();
    normalized.phase = CloseoutPhase::Prepared;
    if &normalized != expected {
        return Err("native_closeout_idempotency_conflict");
    }
    if saved.phase != CloseoutPhase::Unregistered {
        return Err("native_closeout_terminal_not_proven");
    }
    if fs::symlink_metadata(&saved.worktree_root).is_ok()
        || registry.join(format!("{}.toml", saved.project_id)).exists()
    {
        return Err("native_closeout_terminal_state_conflict");
    }
    let source = super::super::shell::canonicalize_existing(Path::new(&saved.source_root))
        .map_err(|_| "native_closeout_source_missing")?;
    if source != Path::new(&saved.source_root)
        || super::managed_worktree::source_mentions_worktree_path(
            &source,
            Path::new(&saved.worktree_root),
        )
        .unwrap_or(true)
    {
        return Err("native_closeout_git_state_indeterminate");
    }
    Ok(saved)
}

/// Runner-side effect transaction. This is intentionally not a dispatchable
/// Runner operation: the Server must first bind a continuously held, exact
/// Session + Job fence and prove terminal processes/leases. The existing
/// unguarded admin admission endpoint MUST NOT call this function.
#[allow(dead_code)]
pub(super) fn execute_under_verified_owner(
    policy: &super::super::config::RunnerPolicy,
    registry: &Path,
    candidate: NativeCloseoutRecord,
) -> Result<NativeCloseoutRecord, &'static str> {
    use webcodex_runner_config::paths::paths_equal;

    // Hold the existing Runner registry CAS lock across all effects and
    // journal transitions. No independent unregister is allowed to interleave.
    let _lock = super::project_registry_write_lock()
        .lock()
        .map_err(|_| "native_closeout_registry_lock_failed")?;
    validate_record(&candidate)?;
    if candidate.phase != CloseoutPhase::Prepared {
        return Err("native_closeout_invalid_phase");
    }
    super::registration::validate_project_op_id(&candidate.project_id)
        .map_err(|_| "native_closeout_invalid_identity")?;
    let registry = super::super::shell::canonicalize_existing(registry)
        .map_err(|_| "native_closeout_registry_missing")?;
    let config = registry.join(format!("{}.toml", candidate.project_id));
    let source = super::super::shell::canonicalize_existing(Path::new(&candidate.source_root))
        .map_err(|_| "native_closeout_source_missing")?;
    if !paths_equal(&source, Path::new(&candidate.source_root))
        || super::registration::validate_project_path_policy(policy, &source).is_err()
    {
        return Err("native_closeout_source_identity_conflict");
    }
    let target = Path::new(&candidate.worktree_root);
    let intent_preexists = ledger_path(&registry, &candidate).exists();
    // A fresh intent must be anchored in the current Runner registration.
    // A crash retry can use the immutable journal only after the prior
    // prepared identity was durably recorded.
    if !intent_preexists && !config.exists() {
        return Err("native_closeout_registration_missing");
    }
    if !intent_preexists && !target.exists() {
        return Err("native_closeout_target_missing");
    }

    if config.exists() {
        let content =
            fs::read_to_string(&config).map_err(|_| "native_closeout_registration_unavailable")?;
        let child = super::catalog::parse_runner_project_toml(&content)
            .map_err(|_| "native_closeout_registration_unavailable")?;
        if child.id != candidate.project_id
            || super::catalog::project_revision(&child) != candidate.expected_revision
            || child.registration_incarnation.as_deref()
                != Some(candidate.expected_incarnation.as_str())
            || child.path != candidate.worktree_root
        {
            return Err("native_closeout_registration_cas_conflict");
        }
        // The identity gate must be rechecked while the real Worktree exists.
        if target.exists() {
            let projects = super::registration::load_project_files_for_path_resolution(&registry)
                .map_err(|_| "native_closeout_registration_unavailable")?;
            let source_project = projects
                .iter()
                .find(|p| p.id == child.managed_source_project_id.clone().unwrap_or_default())
                .ok_or("native_closeout_source_unregistered")?;
            super::managed_worktree::managed_worktree_reclaim_lineage_gate(&child, source_project)?;
            let canonical_target = super::super::shell::canonicalize_existing(target)
                .map_err(|_| "native_closeout_target_missing")?;
            if !paths_equal(&canonical_target, target)
                || super::registration::validate_project_path_policy(policy, &canonical_target)
                    .is_err()
                || super::catalog::project_root_fingerprint(&canonical_target)
                    != candidate.expected_root_fingerprint
                || child.managed_base_sha.as_deref() != Some(candidate.expected_head.as_str())
            {
                return Err("native_closeout_worktree_identity_conflict");
            }
        }
    }

    let mut current = begin_or_read(&registry, candidate.clone())?;
    if current.phase == CloseoutPhase::Prepared {
        if target.exists() {
            if !config.exists() {
                return Err("native_closeout_registration_missing");
            }
            super::managed_worktree::managed_worktree_normal_remove_after_gates(
                &source,
                target,
                &current.expected_head,
                &current.expected_origin_url,
                &current.expected_remote_ref,
            )?;
        } else if !intent_preexists {
            return Err("native_closeout_target_missing");
        }
        // In a post-delete crash, the persisted PREPARED journal plus a
        // missing folder and missing Git link are required for reconciliation.
        // Never invoke git worktree prune or force-remove as a recovery shortcut.
        if fs::symlink_metadata(target).is_ok()
            || super::managed_worktree::source_mentions_worktree_path(&source, target)
                .unwrap_or(true)
        {
            return Err("native_closeout_git_state_indeterminate");
        }
        current = advance(&registry, &current, CloseoutPhase::GitRemoved)?;
    }
    if current.phase == CloseoutPhase::GitRemoved {
        if fs::symlink_metadata(target).is_ok()
            || super::managed_worktree::source_mentions_worktree_path(&source, target)
                .unwrap_or(true)
        {
            return Err("native_closeout_git_state_indeterminate");
        }
        if config.exists() {
            // Exact CAS was checked above, under the same registry lock.
            super::lifecycle::unregister_project_config(&config)
                .map_err(|_| "native_closeout_unregister_indeterminate")?;
        }
        if config.exists() {
            return Err("native_closeout_unregister_indeterminate");
        }
        current = advance(&registry, &current, CloseoutPhase::Unregistered)?;
    }
    if config.exists() || fs::symlink_metadata(target).is_ok() {
        return Err("native_closeout_terminal_state_conflict");
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> NativeCloseoutRecord {
        NativeCloseoutRecord {
            operation_id: uuid::Uuid::new_v4().to_string(),
            project_id: "managed-1".into(),
            expected_revision: "revision-1".into(),
            expected_incarnation: uuid::Uuid::new_v4().to_string(),
            expected_head: "a".repeat(40),
            expected_root_fingerprint: "root".into(),
            expected_origin_url: "https://github.com/example/repo.git".into(),
            expected_remote_ref: "refs/heads/main".into(),
            source_root: "C:/fixture/source".into(),
            worktree_root: "C:/fixture/worktree".into(),
            phase: CloseoutPhase::Prepared,
        }
    }

    fn git(root: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("git");
        assert!(
            output.status.success(),
            "{:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn native_closeout_full_runner_transaction_is_durable_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let child = temp.path().join("child-worktree");
        let remote = temp.path().join("remote.git");
        let registry = temp.path().join("registry");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&registry).unwrap();
        git(temp.path(), &["init", "--bare", remote.to_str().unwrap()]);
        git(&source, &["init"]);
        git(&source, &["config", "user.name", "Fixture"]);
        git(
            &source,
            &["config", "user.email", "fixture@example.invalid"],
        );
        fs::write(source.join("data.txt"), "recoverable").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "fixture"]);
        git(&source, &["branch", "-M", "main"]);
        git(
            &source,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&source, &["push", "origin", "main"]);
        let sha = git(&source, &["rev-parse", "HEAD"]);
        git(
            &source,
            &[
                "worktree",
                "add",
                "--detach",
                &super::super::managed_worktree::managed_worktree_git_cli_path(&child),
                "HEAD",
            ],
        );
        let source = super::super::super::shell::canonicalize_existing(&source).unwrap();
        let child = super::super::super::shell::canonicalize_existing(&child).unwrap();
        let source_text = source.to_str().unwrap();
        let child_text = child.to_str().unwrap();
        let source_content = super::super::registration::build_project_toml(
            "fixture-source",
            "Source",
            source_text,
            &None,
            true,
        );
        fs::write(registry.join("fixture-source.toml"), source_content).unwrap();
        let managed = super::super::managed_worktree::managed_worktree_project_toml(
            "fixture-child",
            "Managed",
            child_text,
            source_text,
            "fixture-source",
            &super::super::catalog::project_root_fingerprint(&source),
            "main",
            &sha,
            &uuid::Uuid::new_v4().to_string(),
        );
        fs::write(registry.join("fixture-child.toml"), &managed).unwrap();
        let parsed = super::super::catalog::parse_runner_project_toml(&managed).unwrap();
        let inventory_child = super::super::catalog::runner_project_summary(&parsed, 1, true);
        assert_eq!(
            inventory_child.git_head.as_deref(),
            Some(sha.as_str()),
            "Runner inventory must use exact full SHA required by Server CAS"
        );
        let candidate = NativeCloseoutRecord {
            operation_id: uuid::Uuid::new_v4().to_string(),
            project_id: "fixture-child".into(),
            expected_revision: super::super::catalog::project_revision(&parsed),
            expected_incarnation: parsed.registration_incarnation.clone().unwrap(),
            expected_head: sha,
            expected_root_fingerprint: super::super::catalog::project_root_fingerprint(&child),
            expected_origin_url: remote.to_str().unwrap().into(),
            expected_remote_ref: "refs/heads/main".into(),
            source_root: source_text.into(),
            worktree_root: child_text.into(),
            phase: CloseoutPhase::Prepared,
        };
        let policy = super::super::super::config::RunnerPolicy {
            allowed_roots: vec![temp.path().to_path_buf()],
            ..Default::default()
        };

        let jobs = super::super::super::job_manager::JobManager::new(1);
        let shells = super::super::super::persistent_shell::PersistentShellManager::new(
            &super::super::super::config::ShellConfig::default(),
            super::super::super::ssh::SshConnectionPool::default(),
        );

        assert_eq!(
            read_verified_terminal(&registry, &candidate).unwrap_err(),
            "native_closeout_terminal_not_proven"
        );
        fs::write(child.join("unique.txt"), "do not delete").unwrap();
        assert_eq!(
            super::super::execute_native_closeout_under_runner_fences(
                &policy,
                &registry,
                &jobs,
                &shells,
                candidate.clone()
            )
            .unwrap_err(),
            "managed_reclaim_unique_content"
        );
        assert!(child.join("unique.txt").exists());
        fs::remove_file(child.join("unique.txt")).unwrap();

        // Read-only wire probe uses only the registered child and source:
        // no caller-supplied path or remote branch is accepted.
        let probe = webcodex_core::runner_operation::RunnerProjectOperation {
            kind: webcodex_core::runner_operation::RunnerProjectOperationKind::NativeManagedCloseoutRecoveryProbe,
            payload: serde_json::json!({
                "project_id": candidate.project_id,
                "expected_revision": candidate.expected_revision,
                "expected_incarnation": candidate.expected_incarnation,
                "expected_head": candidate.expected_head,
                "expected_root_fingerprint": candidate.expected_root_fingerprint,
            }).to_string(),
        };
        let before = fs::read(registry.join("fixture-child.toml")).unwrap();
        let observed = super::super::handle_native_closeout_recovery_probe_operation(
            &policy, &registry, &probe,
        );
        assert_eq!(observed.exit_code, Some(0), "{:?}", observed.stderr);
        let proof: serde_json::Value =
            serde_json::from_str(observed.stdout.as_deref().unwrap()).unwrap();
        assert_eq!(proof["operation"], "native_managed_closeout_recovery_probe");
        assert_eq!(proof["changed"], false);
        assert_eq!(proof["verified_remote_ref"], "refs/heads/main");
        assert_eq!(proof["verified_origin_url"], remote.to_str().unwrap());
        assert!(child.exists());
        assert_eq!(
            fs::read(registry.join("fixture-child.toml")).unwrap(),
            before
        );

        let mut altered: serde_json::Value = serde_json::from_str(&probe.payload).unwrap();
        altered["expected_head"] = serde_json::json!("b".repeat(40));
        let forged = webcodex_core::runner_operation::RunnerProjectOperation {
            kind: probe.kind,
            payload: altered.to_string(),
        };
        assert_ne!(
            super::super::handle_native_closeout_recovery_probe_operation(
                &policy, &registry, &forged
            )
            .exit_code,
            Some(0),
            "forged Git identity must not be accepted as recovery evidence"
        );
        assert!(child.exists());
        assert_eq!(
            fs::read(registry.join("fixture-child.toml")).unwrap(),
            before
        );

        // Remote refs can disappear between admission and execution.
        // Never physically remove the Worktree if remote recovery is lost.
        git(&source, &["push", "origin", ":refs/heads/main"]);
        let revoked = super::super::handle_native_closeout_recovery_probe_operation(
            &policy, &registry, &probe,
        );
        assert_ne!(
            revoked.exit_code,
            Some(0),
            "stale remote recovery probe must fail closed"
        );
        assert_eq!(
            super::super::execute_native_closeout_under_runner_fences(
                &policy,
                &registry,
                &jobs,
                &shells,
                candidate.clone()
            )
            .unwrap_err(),
            "managed_reclaim_remote_unreachable"
        );
        assert!(child.exists());
        assert!(registry.join("fixture-child.toml").exists());
        assert!(read_verified_terminal(&registry, &candidate).is_err());
        git(&source, &["push", "origin", "main"]);

        let done = super::super::execute_native_closeout_under_runner_fences(
            &policy,
            &registry,
            &jobs,
            &shells,
            candidate.clone(),
        )
        .unwrap();
        assert_eq!(done.phase, CloseoutPhase::Unregistered);
        assert_eq!(read_verified_terminal(&registry, &candidate).unwrap(), done);

        // Crash fault injection: Git already removed the Worktree but the
        // Runner died before unregistering the exact Project. Persist an
        // authentic intermediate journal plus its original registration,
        // then restart the executor from disk. A read-only receipt must NOT
        // release the durable Session lease at this intermediate phase.
        let receipt_path = ledger_path(&registry, &candidate);
        let terminal_bytes = fs::read(&receipt_path).unwrap();
        let mut crashed = done.clone();
        crashed.phase = CloseoutPhase::GitRemoved;
        fs::write(&receipt_path, serde_json::to_vec(&crashed).unwrap()).unwrap();
        fs::write(registry.join("fixture-child.toml"), &managed).unwrap();
        assert_eq!(
            read_verified_terminal(&registry, &candidate).unwrap_err(),
            "native_closeout_terminal_not_proven"
        );
        let resumed = super::super::execute_native_closeout_under_runner_fences(
            &policy,
            &registry,
            &jobs,
            &shells,
            candidate.clone(),
        )
        .unwrap();
        assert_eq!(resumed, done);
        assert!(!registry.join("fixture-child.toml").exists());
        assert!(!child.exists());
        assert_eq!(read_verified_terminal(&registry, &candidate).unwrap(), done);

        // Second crash point: deletion completed before the PREPARED journal
        // advanced; exact immutable identity may resume without running Git
        // removal a second time. No registration is fabricated.
        fs::write(&receipt_path, serde_json::to_vec(&candidate).unwrap()).unwrap();
        assert_eq!(
            read_verified_terminal(&registry, &candidate).unwrap_err(),
            "native_closeout_terminal_not_proven"
        );
        assert_eq!(
            super::super::execute_native_closeout_under_runner_fences(
                &policy,
                &registry,
                &jobs,
                &shells,
                candidate.clone()
            )
            .unwrap(),
            done
        );
        assert_eq!(fs::read(&receipt_path).unwrap(), terminal_bytes);

        // An interrupted transaction or a recreated Project registration
        // must never be accepted as a completed recovery receipt.
        let receipt_path = ledger_path(&registry, &candidate);
        let receipt = fs::read(&receipt_path).unwrap();
        let mut interrupted = done.clone();
        interrupted.phase = CloseoutPhase::GitRemoved;
        fs::write(&receipt_path, serde_json::to_vec(&interrupted).unwrap()).unwrap();
        assert_eq!(
            read_verified_terminal(&registry, &candidate).unwrap_err(),
            "native_closeout_terminal_not_proven"
        );
        fs::write(&receipt_path, &receipt).unwrap();
        fs::write(registry.join("fixture-child.toml"), &managed).unwrap();
        assert_eq!(
            read_verified_terminal(&registry, &candidate).unwrap_err(),
            "native_closeout_terminal_state_conflict"
        );
        fs::remove_file(registry.join("fixture-child.toml")).unwrap();
        assert_eq!(read_verified_terminal(&registry, &candidate).unwrap(), done);
        let query = webcodex_core::runner_operation::RunnerProjectOperation {
            kind: webcodex_core::runner_operation::RunnerProjectOperationKind::NativeManagedCloseoutReceipt,
            payload: serde_json::to_string(&candidate).unwrap(),
        };
        let observed = super::super::handle_native_closeout_receipt_operation(&registry, &query);
        assert_eq!(observed.exit_code, Some(0));
        let receipt_json: serde_json::Value =
            serde_json::from_str(observed.stdout.as_deref().unwrap()).unwrap();
        assert_eq!(receipt_json["operation"], "native_managed_closeout_receipt");
        assert_eq!(receipt_json["changed"], false);
        assert_eq!(receipt_json["phase"], "unregistered");
        assert!(!child.exists());
        assert!(!registry.join("fixture-child.toml").exists());
        assert_eq!(
            super::super::execute_native_closeout_under_runner_fences(
                &policy,
                &registry,
                &jobs,
                &shells,
                candidate.clone()
            )
            .unwrap(),
            done
        );
        let mut conflict = candidate.clone();
        conflict.expected_head = "b".repeat(40);
        assert_eq!(
            read_verified_terminal(&registry, &conflict).unwrap_err(),
            "native_closeout_idempotency_conflict"
        );
        assert_eq!(
            super::super::execute_native_closeout_under_runner_fences(
                &policy, &registry, &jobs, &shells, conflict
            )
            .unwrap_err(),
            "native_closeout_idempotency_conflict"
        );

        // Only this compiled test binary can opt into exporting an isolated
        // attestation. No production Runner command, capability or gate changes.
        if let Some(path) = std::env::var_os("WEBCODEX_NATIVE_CLOSEOUT_TEST_RECEIPT") {
            let proof = serde_json::json!({
                "phase": "unregistered",
                "git_worktree_removed": !child.exists(),
                "cas_unregistered": !registry.join("fixture-child.toml").exists(),
                "durable_terminal_verified": read_verified_terminal(&registry, &candidate).is_ok(),
                "remote_ref": "refs/heads/main",
                "operation_id": done.operation_id,
            });
            fs::write(path, serde_json::to_vec(&proof).unwrap()).unwrap();
        }
    }

    #[test]
    fn native_closeout_full_transaction_completes_in_separate_os_process() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = dir.path().join("subprocess-terminal.json");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("native_closeout_full_runner_transaction_is_durable_and_idempotent")
            .arg("--nocapture")
            .env("WEBCODEX_NATIVE_CLOSEOUT_TEST_RECEIPT", &receipt)
            .output()
            .expect("launch isolated native closeout test process");
        assert!(
            output.status.success(),
            "independent closeout process failed: {}\\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let evidence: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt).expect("subprocess receipt persisted"))
                .unwrap();
        assert_eq!(evidence["phase"], "unregistered");
        assert_eq!(evidence["git_worktree_removed"], true);
        assert_eq!(evidence["cas_unregistered"], true);
        assert_eq!(evidence["durable_terminal_verified"], true);
        assert_eq!(evidence["remote_ref"], "refs/heads/main");
        assert!(uuid::Uuid::parse_str(evidence["operation_id"].as_str().unwrap()).is_ok());
    }

    #[test]
    fn native_closeout_journal_recovers_rejects_conflicts_and_never_skips_phases() {
        let dir = tempfile::tempdir().unwrap();
        let initial = record();
        let saved = begin_or_read(dir.path(), initial.clone()).unwrap();
        assert_eq!(begin_or_read(dir.path(), initial.clone()).unwrap(), saved);
        let mut conflicting = initial.clone();
        conflicting.expected_head = "b".repeat(40);
        assert_eq!(
            begin_or_read(dir.path(), conflicting).unwrap_err(),
            "native_closeout_idempotency_conflict"
        );
        assert_eq!(
            advance(dir.path(), &saved, CloseoutPhase::Unregistered).unwrap_err(),
            "native_closeout_invalid_phase"
        );
        let removed = advance(dir.path(), &saved, CloseoutPhase::GitRemoved).unwrap();
        assert_eq!(
            advance(dir.path(), &saved, CloseoutPhase::Unregistered).unwrap_err(),
            "native_closeout_journal_revision_conflict"
        );
        assert_eq!(begin_or_read(dir.path(), initial).unwrap(), removed);
        let complete = advance(dir.path(), &removed, CloseoutPhase::Unregistered).unwrap();
        assert_eq!(complete.phase, CloseoutPhase::Unregistered);
    }
}
