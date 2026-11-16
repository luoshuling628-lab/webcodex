use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::config::default_true;
#[cfg(test)]
use super::config::RunnerPolicy;
use crate::webcodex_runner::output::CommandResult;
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use webcodex_core::runner_operation::RunnerOperation;
#[cfg(test)]
use webcodex_core::runner_operation::RunnerProjectOperation;
use webcodex_core::runner_protocol::RunnerProjectSummary;
#[cfg(test)]
use webcodex_core::runner_protocol::RunnerRequest;

mod catalog;
mod created_paths;
mod lifecycle;
mod managed_worktree;
mod native_closeout;
mod registration;

pub(crate) use catalog::load_runner_project_metadata;
pub(crate) use catalog::{
    find_project_shell_context, find_project_shell_context_by_id,
    load_runner_project_summaries_from_dir, project_root_fingerprint,
};
#[cfg(test)]
pub(crate) use catalog::{parse_runner_project_toml, runner_project_summary};

pub(crate) use lifecycle::{handle_project_lifecycle_operation, handle_project_operation};

pub(crate) use managed_worktree::handle_prepare_managed_worktree_operation;

/// Execute only after the Server owns its continuously held native Session
/// and Job-start closeout fences. This Runner-side exclusion closes both
/// local managed admission races; no public transport operation is exposed
/// until the Server↔Runner lease and crash-reconciliation protocol is bound.
#[allow(dead_code)]
/// Dedicated native Runner transport effect. An ordinary project lifecycle
/// tool never selects this operation; only the Server Native Closeout Owner
/// may enqueue it while retaining its own durable Session/Job fences.
#[allow(dead_code)]
pub(crate) fn handle_native_managed_closeout_operation(
    policy: &super::config::RunnerPolicy,
    registry: &std::path::Path,
    jobs: &super::job_manager::JobManager,
    shells: &super::persistent_shell::PersistentShellManager,
    operation: &webcodex_core::runner_operation::RunnerProjectOperation,
) -> CommandResult {
    let start = Instant::now();
    if operation.kind
        != webcodex_core::runner_operation::RunnerProjectOperationKind::NativeManagedCloseout
        || operation.payload.len() > 8192
    {
        return project_error_cmd(start, "native_closeout_invalid_request");
    }
    let candidate: native_closeout::NativeCloseoutRecord =
        match serde_json::from_str(&operation.payload) {
            Ok(candidate) => candidate,
            Err(_) => return project_error_cmd(start, "native_closeout_invalid_request"),
        };
    let project_id = candidate.project_id.clone();
    match execute_native_closeout_under_runner_fences(policy, registry, jobs, shells, candidate) {
        Ok(receipt) => crate::webcodex_runner::output::ok_cmd(
            start,
            serde_json::json!({
                "operation": "native_managed_closeout",
                "outcome": "native_closeout_completed",
                "changed": true,
                "agent_project_id": project_id,
                "operation_id": receipt.operation_id,
                "expected_revision": receipt.expected_revision,
                "registration_incarnation": receipt.expected_incarnation,
                "phase": receipt.phase,
            }),
        ),
        Err(reason) => structured_project_error_cmd(
            start,
            reason,
            true, // Treat any failure as potentially partially committed.
            serde_json::json!({"operation": "native_managed_closeout"}),
        ),
    }
}

/// Recovery observation never invokes a Git removal, unregister, or journal
/// phase transition. It only returns an exact already-committed terminal.
#[allow(dead_code)]
pub(crate) fn handle_native_closeout_receipt_operation(
    registry: &std::path::Path,
    operation: &webcodex_core::runner_operation::RunnerProjectOperation,
) -> CommandResult {
    let start = Instant::now();
    if operation.kind
        != webcodex_core::runner_operation::RunnerProjectOperationKind::NativeManagedCloseoutReceipt
        || operation.payload.len() > 8192
    {
        return project_error_cmd(start, "native_closeout_invalid_request");
    }
    let expected: native_closeout::NativeCloseoutRecord =
        match serde_json::from_str(&operation.payload) {
            Ok(value) => value,
            Err(_) => return project_error_cmd(start, "native_closeout_invalid_request"),
        };
    match native_closeout::read_verified_terminal(registry, &expected) {
        Ok(receipt) => crate::webcodex_runner::output::ok_cmd(
            start,
            serde_json::json!({
                "operation": "native_managed_closeout_receipt",
                "outcome": "native_closeout_completed",
                "changed": false,
                "agent_project_id": receipt.project_id,
                "operation_id": receipt.operation_id,
                "expected_revision": receipt.expected_revision,
                "registration_incarnation": receipt.expected_incarnation,
                "phase": receipt.phase,
            }),
        ),
        Err(reason) => project_error_cmd(start, reason),
    }
}

pub(crate) fn execute_native_closeout_under_runner_fences(
    policy: &super::config::RunnerPolicy,
    registry: &std::path::Path,
    jobs: &super::job_manager::JobManager,
    shells: &super::persistent_shell::PersistentShellManager,
    candidate: native_closeout::NativeCloseoutRecord,
) -> Result<native_closeout::NativeCloseoutRecord, &'static str> {
    jobs.with_quiescent_job_admission(|| {
        shells.with_quiescent_shell_admission(|| {
            native_closeout::execute_under_verified_owner(policy, registry, candidate)
        })
    })
}

#[cfg(test)]
use registration::build_project_toml;
pub(crate) use registration::handle_resolve_or_register_project_operation;
#[cfg(all(test, unix))]
use registration::sync_parent_dir;
#[cfg(test)]
pub(crate) use registration::{
    fail_next_project_parent_sync_after_rename, fail_next_project_publish_before_rename,
    validate_project_path_policy,
};

static PROJECT_REGISTRY_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(super) fn project_registry_write_lock() -> &'static Mutex<()> {
    PROJECT_REGISTRY_WRITE_LOCK.get_or_init(|| Mutex::new(()))
}

pub(super) fn project_error_cmd(start: Instant, error_code: &'static str) -> CommandResult {
    CommandResult {
        exit_code: Some(1),
        stdout: Some(
            serde_json::to_string(&serde_json::json!({"error_code": error_code}))
                .unwrap_or_else(|_| r#"{"error_code":"operation_failed"}"#.to_string()),
        ),
        stderr: Some(String::new()),
        duration_ms: Some(start.elapsed().as_millis() as u64),
        error: None,
    }
}

pub(super) fn structured_project_error_cmd(
    start: Instant,
    error_kind: &'static str,
    state_changed: bool,
    fields: serde_json::Value,
) -> CommandResult {
    let mut output = serde_json::json!({
        "error_code": error_kind,
        "error_kind": error_kind,
        "failure_kind": error_kind,
        "state_changed": state_changed,
    });
    if let (Some(output), Some(fields)) = (output.as_object_mut(), fields.as_object()) {
        output.extend(fields.clone());
    }
    CommandResult {
        exit_code: Some(1),
        stdout: Some(
            serde_json::to_string(&output)
                .unwrap_or_else(|_| r#"{"error_code":"operation_failed"}"#.to_string()),
        ),
        stderr: Some(String::new()),
        duration_ms: Some(start.elapsed().as_millis() as u64),
        error: None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RunnerProjectFile {
    pub(crate) id: String,
    pub(crate) path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) shell_profile: Option<String>,
    #[serde(default = "default_true")]
    pub(crate) allow_patch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) registration_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) registration_incarnation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) disabled: bool,
    #[serde(default)]
    pub(crate) hooks: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) managed_worktree: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) managed_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) managed_source_project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) managed_source_root_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) managed_base_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) managed_base_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) managed_operation_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RunnerProjectCache {
    projects: Vec<RunnerProjectSummary>,
    refreshed_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub(crate) struct RunnerProjectShellContext {
    pub(crate) id: String,
    pub(crate) path: String,
    /// Current registry write authority; avoids Git/status probes on tool admission.
    pub(crate) allow_patch: bool,
    pub(crate) shell_profile: Option<String>,
}

#[cfg(test)]
fn test_project_operation(
    request: &RunnerRequest,
) -> Result<RunnerProjectOperation, CommandResult> {
    match request.decode_operation() {
        Ok(RunnerOperation::Project(operation)) => Ok(operation),
        _ => Err(project_error_cmd(
            Instant::now(),
            "unsupported_runner_version",
        )),
    }
}

#[cfg(test)]
pub(crate) fn handle_project_op(
    policy: &RunnerPolicy,
    project_registry_dir: &Path,
    request: &RunnerRequest,
) -> CommandResult {
    let operation = match test_project_operation(request) {
        Ok(operation) => operation,
        Err(result) => return result,
    };
    handle_project_operation(policy, project_registry_dir, &request.client_id, &operation)
}

#[cfg(test)]
pub(crate) fn handle_resolve_or_register_project(
    policy: &RunnerPolicy,
    project_registry_dir: &Path,
    request: &RunnerRequest,
) -> CommandResult {
    let operation = match test_project_operation(request) {
        Ok(operation) => operation,
        Err(result) => return result,
    };
    handle_resolve_or_register_project_operation(
        policy,
        project_registry_dir,
        &request.client_id,
        &operation,
    )
}

#[cfg(test)]
pub(crate) fn handle_prepare_managed_worktree(
    policy: &RunnerPolicy,
    project_registry_dir: &Path,
    request: &RunnerRequest,
) -> CommandResult {
    let operation = match test_project_operation(request) {
        Ok(operation) => operation,
        Err(result) => return result,
    };
    handle_prepare_managed_worktree_operation(
        policy,
        project_registry_dir,
        &request.client_id,
        &operation,
    )
}

#[cfg(test)]
pub(crate) fn handle_project_lifecycle_op(
    policy: &RunnerPolicy,
    project_registry_dir: &Path,
    request: &RunnerRequest,
) -> CommandResult {
    let operation = match test_project_operation(request) {
        Ok(operation) => operation,
        Err(result) => return result,
    };
    handle_project_lifecycle_operation(policy, project_registry_dir, &operation)
}

#[cfg(test)]
mod durability_tests {
    #[cfg(windows)]
    use super::managed_worktree::managed_worktree_git_cli_path;
    use super::*;

    #[cfg(windows)]
    #[test]
    fn managed_worktree_git_cli_path_normalizes_only_verbatim_local_disk_paths() {
        assert_eq!(
            managed_worktree_git_cli_path(Path::new(r"\\?\C:\workspace\managed")),
            r"C:\workspace\managed"
        );
        assert_eq!(
            managed_worktree_git_cli_path(Path::new(r"C:\workspace\managed")),
            r"C:\workspace\managed"
        );
        assert_eq!(
            managed_worktree_git_cli_path(Path::new(r"\\server\share\managed")),
            r"\\server\share\managed"
        );
    }

    #[test]
    fn native_managed_worktree_git_reclaim_gate_preserves_unique_data() {
        use super::managed_worktree::managed_worktree_local_git_reclaim_gate;
        use std::process::Command;

        fn git(root: &Path, args: &[&str]) -> String {
            let output = Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .output()
                .expect("git available in native Runner test");
            assert!(
                output.status.success(),
                "git {:?}: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        }
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let child = temp.path().join("new-worktree");
        std::fs::create_dir(&source).unwrap();
        git(&source, &["init"]);
        git(&source, &["config", "user.name", "Managed Fixture"]);
        git(
            &source,
            &["config", "user.email", "fixture@example.invalid"],
        );
        std::fs::write(source.join(".gitignore"), "ignored.txt\n").unwrap();
        std::fs::write(source.join("tracked.txt"), "commit one\n").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "first"]);
        std::fs::write(source.join("tracked.txt"), "commit two\n").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "second"]);
        let sha = git(&source, &["rev-parse", "HEAD"]);
        let child_cli = super::managed_worktree::managed_worktree_git_cli_path(&child);
        git(
            &source,
            &["worktree", "add", "--detach", &child_cli, "HEAD"],
        );
        assert_eq!(
            managed_worktree_local_git_reclaim_gate(&source, &child, &sha),
            Ok(())
        );
        let source_project: RunnerProjectFile = serde_json::from_value(serde_json::json!({
            "id":"fixture-source", "path": source.to_string_lossy()
        }))
        .unwrap();
        let mut managed: RunnerProjectFile = serde_json::from_value(serde_json::json!({
            "id":"fixture-child","path":child.to_string_lossy(),
            "registration_source":"auto_registered", "managed_worktree":true,
            "registration_incarnation":"11111111-1111-4111-8111-111111111111",
            "managed_operation_id":"22222222-2222-4222-8222-222222222222",
            "managed_source":source.to_string_lossy(),
            "managed_source_project_id":"fixture-source",
            "managed_source_root_fingerprint":project_root_fingerprint(&source),
            "managed_base_sha":sha
        }))
        .unwrap();
        assert_eq!(
            super::managed_worktree::managed_worktree_reclaim_lineage_gate(
                &managed,
                &source_project
            ),
            Ok(())
        );
        managed.managed_source_project_id = Some("foreign-source".to_owned());
        assert_eq!(
            super::managed_worktree::managed_worktree_reclaim_lineage_gate(
                &managed,
                &source_project
            ),
            Err("managed_reclaim_source_project_mismatch")
        );
        managed.managed_source_project_id = Some("fixture-source".to_owned());
        managed.managed_source_root_fingerprint = Some("wrong-fingerprint".to_owned());
        assert_eq!(
            super::managed_worktree::managed_worktree_reclaim_lineage_gate(
                &managed,
                &source_project
            ),
            Err("managed_reclaim_source_fingerprint_mismatch")
        );
        managed.managed_source_root_fingerprint = Some(project_root_fingerprint(&source));
        managed.registration_incarnation = Some("not-a-uuid".to_owned());
        assert_eq!(
            super::managed_worktree::managed_worktree_reclaim_lineage_gate(
                &managed,
                &source_project
            ),
            Err("managed_reclaim_registration_identity_invalid")
        );

        assert_eq!(
            managed_worktree_local_git_reclaim_gate(&source, &child, "not-a-sha"),
            Err("managed_reclaim_invalid_expected_head")
        );
        std::fs::write(child.join("unique.txt"), "do not lose me").unwrap();
        assert_eq!(
            managed_worktree_local_git_reclaim_gate(&source, &child, &sha),
            Err("managed_reclaim_unique_content")
        );
        std::fs::remove_file(child.join("unique.txt")).unwrap();
        std::fs::write(child.join("ignored.txt"), "also unique").unwrap();
        assert_eq!(
            managed_worktree_local_git_reclaim_gate(&source, &child, &sha),
            Err("managed_reclaim_ignored_content")
        );
        std::fs::remove_file(child.join("ignored.txt")).unwrap();
        let git_dir = git(&child, &["rev-parse", "--absolute-git-dir"]);
        std::fs::write(Path::new(&git_dir).join("locked"), "do not remove").unwrap();
        assert_eq!(
            managed_worktree_local_git_reclaim_gate(&source, &child, &sha),
            Err("managed_reclaim_locked")
        );
        std::fs::remove_file(Path::new(&git_dir).join("locked")).unwrap();
        git(&child, &["reset", "--hard", "HEAD~1"]);
        assert_eq!(
            managed_worktree_local_git_reclaim_gate(&source, &child, &sha),
            Err("managed_reclaim_head_drift")
        );
    }

    /// Unix-only: verifies the POSIX directory-fsync contract (opening a
    /// directory as a file). On Windows directory sync is intentionally
    /// skipped because std cannot open directories with the required
    /// FILE_FLAG_BACKUP_SEMANTICS.
    #[cfg(unix)]
    #[test]
    fn registry_parent_sync_failures_are_not_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing").join("demo.toml");
        let error = sync_parent_dir(&missing).unwrap_err();
        assert!(error.contains("sync project registry directory"));
    }

    #[test]
    fn registry_loader_ignores_temp_and_unregister_tombstones() {
        let tmp = tempfile::tempdir().unwrap();
        let project_registry_dir = tmp.path().join("project-registry");
        let source = tmp.path().join("source");
        std::fs::create_dir_all(&project_registry_dir).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        let content = build_project_toml("demo", "Demo", source.to_str().unwrap(), &None, true);
        std::fs::write(project_registry_dir.join("demo.toml"), &content).unwrap();
        std::fs::write(project_registry_dir.join(".demo.random.toml.tmp"), &content).unwrap();
        std::fs::write(
            project_registry_dir.join(".demo.random.toml.unregistering"),
            &content,
        )
        .unwrap();
        let projects = load_runner_project_summaries_from_dir(&project_registry_dir);
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].id, "demo");
    }

    #[cfg(unix)]
    #[test]
    fn project_summary_reports_retargeted_symlinks_as_distinct_canonical_roots() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let first = tmp.path().join("first");
        let second = tmp.path().join("second");
        let link = tmp.path().join("current");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        symlink(&first, &link).unwrap();
        let project = RunnerProjectFile {
            id: "demo".to_string(),
            path: link.to_string_lossy().to_string(),
            shell_profile: None,
            allow_patch: true,
            name: None,
            kind: None,
            registration_source: None,
            registration_incarnation: None,
            description: None,
            disabled: false,
            hooks: HashMap::new(),
            managed_worktree: false,
            managed_source: None,
            managed_source_project_id: None,
            managed_source_root_fingerprint: None,
            managed_base_ref: None,
            managed_base_sha: None,
            managed_operation_id: None,
        };

        let first_summary = runner_project_summary(&project, 1, false);
        assert_eq!(
            Path::new(&first_summary.path),
            first.canonicalize().unwrap()
        );
        std::fs::remove_file(&link).unwrap();
        symlink(&second, &link).unwrap();
        let second_summary = runner_project_summary(&project, 2, false);
        assert_eq!(
            Path::new(&second_summary.path),
            second.canonicalize().unwrap()
        );
        assert_ne!(first_summary.path, second_summary.path);
    }
}
