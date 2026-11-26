use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use webcodex_core::runner_operation::RunnerProjectOperation;
use webcodex_runner_config::paths::paths_equal;

use super::super::config::RunnerPolicy;
use super::super::shell::canonicalize_existing;
use super::catalog::{
    effective_registration_source, parse_runner_project_toml, project_lineage, project_revision,
    project_root_fingerprint, project_wire_kind, run_git_bounded,
    AUTO_REGISTERED_REGISTRATION_SOURCE,
};
use super::registration::{
    bounded_project_name, build_project_toml_with_registration_source, choose_auto_project_id,
    load_project_files_for_path_resolution, projects_matching_canonical_path,
    resolve_managed_source_project, sanitized_project_basename, toml_basic_string,
    validate_model_network_project_ingress_authority, validate_project_op_id,
    validate_project_path_policy, validate_windows_project_root, write_project_toml_atomic,
    ProjectTomlWriteError,
};
use super::{project_registry_write_lock, structured_project_error_cmd, RunnerProjectFile};
use crate::webcodex_runner::output::{ok_cmd, CommandResult};

const MANAGED_WORKTREE_GIT_TIMEOUT: Duration = Duration::from_secs(20);
const MANAGED_WORKTREE_CHECKOUT_TIMEOUT: Duration = Duration::from_secs(300);
const MANAGED_WORKTREE_NAMESPACE: &str = ".webcodex-worktrees";

/// The slug is routing text, not recovery identity. Only an exact registry
/// record or an unconsumed creation receipt may establish ownership.
fn choose_managed_destination(
    root: &Path,
    source: &Path,
    operation_id: &str,
    projects: &[RunnerProjectFile],
    pending_destination: Option<&Path>,
) -> Result<PathBuf, &'static str> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"webcodex/managed-worktree-routing/v1\0");
    hash.update(operation_id.as_bytes());
    let digest = format!("{:x}", hash.finalize());
    for length in [8, 12, 16, 24, 32, 48, 64] {
        let candidate = root.join(format!(
            "{}-{}",
            sanitized_project_basename(source),
            &digest[..length]
        ));
        match std::fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(candidate),
            Err(_) => return Err("managed_worktree_recovery_conflict"),
            Ok(_) => {}
        }
        let existing =
            canonicalize_existing(&candidate).map_err(|_| "managed_worktree_recovery_conflict")?;
        let matches = projects_matching_canonical_path(projects, &existing);
        if matches.is_empty()
            && pending_destination.is_some_and(|pending| paths_equal(pending, &existing))
            && paths_equal(&existing, &candidate)
        {
            return Ok(candidate);
        }
        let [project] = matches.as_slice() else {
            return Err("managed_worktree_recovery_conflict");
        };
        let other = project
            .managed_operation_id
            .as_deref()
            .filter(|id| project.managed_worktree && uuid::Uuid::parse_str(id).is_ok())
            .ok_or("managed_worktree_recovery_conflict")?;
        if other == operation_id {
            return Ok(candidate);
        }
    }
    Err("managed_worktree_recovery_conflict")
}

// Stored outside the checkout, in the Runner's existing registry directory.
// Keep the receipt until a durable registry readback. An independently durable
// completion fence prevents an old receipt from authorizing resurrection.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct PendingMaterialization {
    operation_id: String,
    source: PathBuf,
    source_project_id: String,
    source_root_fingerprint: String,
    base_sha: String,
    destination: PathBuf,
}

fn completed_receipt_path(registry: &Path, operation_id: &str) -> PathBuf {
    registry.join(format!(".managed-materialization-{operation_id}.done"))
}

// Publication and completion both use the existing registry's durability
// primitive. A hard link publishes a complete immutable receipt without
// overwriting a competing operation.
fn publish_receipt_bytes(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    use std::io::Write;
    let parent = path.parent().ok_or("worktree_registration_failed")?;
    let temp = parent.join(format!(".materialization-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::hard_link(&temp, path)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&temp);
    result.map_err(|_| "worktree_registration_failed")?;
    super::registration::sync_dir(parent).map_err(|_| "operation_indeterminate")
}

fn mark_materialization_completed(path: &Path, receipt: &PendingMaterialization) -> Result<(), &'static str> {
    if let Some(existing) = read_pending_receipt(path)? {
        return if &existing == receipt {
            super::registration::sync_dir(path.parent().ok_or("operation_indeterminate")?).map_err(|_| "operation_indeterminate")
        } else { Err("managed_worktree_recovery_conflict") };
    }
    let bytes = serde_json::to_vec(receipt).map_err(|_| "worktree_registration_failed")?;
    publish_receipt_bytes(path, &bytes)
}

fn pending_receipt_path(registry: &Path, operation_id: &str) -> PathBuf {
    registry.join(format!(".managed-materialization-{operation_id}.json"))
}

fn read_pending_receipt(path: &Path) -> Result<Option<PendingMaterialization>, &'static str> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("managed_worktree_recovery_conflict"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16384 {
        return Err("managed_worktree_recovery_conflict");
    }
    let content = std::fs::read(path).map_err(|_| "managed_worktree_recovery_conflict")?;
    serde_json::from_slice(&content)
        .map(Some)
        .map_err(|_| "managed_worktree_recovery_conflict")
}

fn persist_pending_receipt(path: &Path, receipt: &PendingMaterialization) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec(receipt).map_err(|_| "worktree_registration_failed")?;
    publish_receipt_bytes(path, &bytes)
}

// Materialize an unregistered worktree using a fresh, private Git index.
// Interrupted private indexes (and their locks) never block a later attempt.
// An unknown ordinary index.lock is not ours to remove. Never overwrite an
// existing index or working file, even when an external writer races us.
fn resume_pending_materialization(path: &Path, base_sha: &str) -> Result<(), &'static str> {
    if managed_worktree_git_text(path, &["rev-parse", "HEAD"])? != base_sha {
        return Err("managed_worktree_recovery_conflict");
    }
    let git_dir_text = managed_worktree_git_text(path, &["rev-parse", "--absolute-git-dir"])?;
    let git_dir = canonicalize_existing(Path::new(&git_dir_text))
        .map_err(|_| "managed_worktree_recovery_conflict")?;
    let index = git_dir.join("index");
    let lock = git_dir.join("index.lock");
    let ensure_unlocked = || match std::fs::symlink_metadata(&lock) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("managed_worktree_recovery_conflict"),
    };
    ensure_unlocked()?;
    let expected = managed_worktree_git_text(path, &["rev-parse", "HEAD^{tree}"])?;
    // New no-checkout allocations normally have no index. A pre-existing
    // index must already represent the exact expected tree; never replace it.
    let has_index = match std::fs::symlink_metadata(&index) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
            verify_index_matches_base(path, base_sha)?;
            true
        }
        _ => return Err("managed_worktree_recovery_conflict"),
    };
    if has_index && verify_new_worktree_materialization(path, base_sha).is_ok() {
        return Ok(());
    }
    // Reserve an exclusive private directory, so no prior interrupted attempt
    // can leave a lock at the index path used by this attempt.
    let attempt = git_dir.join(format!("webcodex-materialization-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&attempt).map_err(|_| "worktree_materialization_failed")?;
    let private_index = attempt.join("index");
    // Git for Windows rejects verbatim-disk paths for GIT_INDEX_FILE.
    // Keep the canonical path for filesystem operations, render only argv/env.
    let private_git_index = PathBuf::from(managed_worktree_git_cli_path(&private_index));
    let run = |args: &[&str]| {
        super::catalog::run_git_bounded_with_index(
            "git", path, args, MANAGED_WORKTREE_CHECKOUT_TIMEOUT, None, Some(&private_git_index),
        ).map_err(|_| "worktree_materialization_failed")
    };
    let output = run(&["read-tree", base_sha]).map_err(|e| { eprintln!("materialize read-tree: {e}"); "worktree_materialization_failed" })?;
    if !output.status.success() || output.stdout_capped || output.stderr_capped {
        return Err("worktree_materialization_failed");
    }
    let output = run(&["write-tree"]).map_err(|e| { eprintln!("materialize write-tree: {e}"); "worktree_materialization_failed" })?;
    if !output.status.success() || output.stdout_capped || output.stderr_capped
        || String::from_utf8_lossy(&output.stdout).trim() != expected {
        return Err("worktree_materialization_failed");
    }
    // Without --force Git does not overwrite files left by earlier attempts.
    let output = run(&["-c", "core.longpaths=true", "checkout-index", "--all"]).map_err(|e| { eprintln!("materialize checkout-index: {e}"); "worktree_materialization_failed" })?;
    if output.stdout_capped || output.stderr_capped {
        return Err("worktree_materialization_failed");
    }
    let output = run(&["--no-optional-locks", "-c", "core.longpaths=true", "status",
        "--porcelain=v1", "--untracked-files=all"]).map_err(|e| { eprintln!("materialize status: {e}"); "worktree_materialization_failed" })?;
    if !output.status.success() || output.stdout_capped || output.stderr_capped
        || !output.stdout.is_empty() {
        eprintln!("materialize status failed: {:?} stdout={} stderr={}", output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        return Err("worktree_materialization_failed");
    }
    ensure_unlocked()?;
    if !has_index {
        // Atomic no-replace publication. No ordinary index.lock is created
        // by the materialization transaction, even if the Runner crashes.
        std::fs::File::open(&private_index).and_then(|file| file.sync_all())
            .map_err(|e| { eprintln!("materialize fsync private index: {e}"); "worktree_materialization_failed" })?;
        std::fs::hard_link(&private_index, &index)
            .map_err(|e| { eprintln!("materialize publish index: {e}"); "managed_worktree_recovery_conflict" })?;
        super::registration::sync_dir(&git_dir).map_err(|e| { eprintln!("materialize sync git dir: {e}"); "operation_indeterminate" })?;
    }
    ensure_unlocked()?;
    verify_new_worktree_materialization(path, base_sha)?;
    // Delete only this attempt's known file after successful verification.
    // Earlier private attempts are not deleted without lifecycle evidence.
    let _ = std::fs::remove_file(&private_index);
    let _ = std::fs::remove_dir(&attempt);
    Ok(())
}

fn managed_worktree_error(
    start: Instant,
    error_kind: &'static str,
    state_changed: bool,
    base_ref: Option<&str>,
    base_sha: Option<&str>,
    source_dirty: Option<bool>,
) -> CommandResult {
    structured_project_error_cmd(
        start,
        error_kind,
        state_changed,
        serde_json::json!({
            "base_ref": base_ref,
            "base_sha": base_sha,
            "source_dirty": source_dirty,
        }),
    )
}

fn managed_worktree_git_text(path: &Path, args: &[&str]) -> Result<String, &'static str> {
    let output = run_git_bounded(path, args, MANAGED_WORKTREE_GIT_TIMEOUT, None)
        .map_err(|_| "worktree_git_failed")?;
    if !output.status.success() || output.stdout_capped || output.stderr_capped {
        return Err("worktree_git_failed");
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| "worktree_git_failed")
}

// Fresh allocation and interrupted recovery use the same no-overwrite path.
fn materialize_new_worktree(path: &Path, base_sha: &str) -> Result<(), &'static str> {
    resume_pending_materialization(path, base_sha)
}

// diff --cached compares the index with the exact commit without creating
// an index or index.lock. write-tree is not a read-only verification command.
fn verify_index_matches_base(path: &Path, base_sha: &str) -> Result<(), &'static str> {
    let output = run_git_bounded(path,
        &["--no-optional-locks", "diff", "--cached", "--quiet", base_sha, "--"],
        MANAGED_WORKTREE_CHECKOUT_TIMEOUT, None,
    ).map_err(|_| "worktree_materialization_failed")?;
    if !output.status.success() || output.stdout_capped || output.stderr_capped {
        return Err("worktree_materialization_failed");
    }
    Ok(())
}

fn verify_new_worktree_materialization(path: &Path, base_sha: &str) -> Result<(), &'static str> {
    if managed_worktree_git_text(path, &["rev-parse", "HEAD"])? != base_sha {
        return Err("managed_worktree_recovery_conflict");
    }
    verify_index_matches_base(path, base_sha)?;
    let status = run_git_bounded(
        path,
        &["--no-optional-locks", "-c", "core.longpaths=true", "status", "--porcelain=v1", "--untracked-files=all"],
        MANAGED_WORKTREE_CHECKOUT_TIMEOUT,
        None,
    )
    .map_err(|_| "worktree_materialization_failed")?;
    if !status.status.success() || status.stdout_capped || status.stderr_capped || !status.stdout.is_empty() {
        return Err("worktree_materialization_failed");
    }
    Ok(())
}

fn exact_git_commit(source: &Path, base_ref: &str) -> Result<String, &'static str> {
    let commit_ref = format!("{base_ref}^{{commit}}");
    let output = run_git_bounded(
        source,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            commit_ref.as_str(),
        ],
        MANAGED_WORKTREE_GIT_TIMEOUT,
        None,
    )
    .map_err(|_| "base_ref_resolution_failed")?;
    if !output.status.success() || output.stdout_capped {
        return Err("base_ref_resolution_failed");
    }
    let sha = String::from_utf8(output.stdout)
        .map_err(|_| "base_ref_resolution_failed")?
        .trim()
        .to_string();
    if !matches!(sha.len(), 40 | 64) || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("base_ref_resolution_failed");
    }
    Ok(sha.to_ascii_lowercase())
}

fn managed_worktree_namespace_candidate(
    policy: &RunnerPolicy,
    source: &Path,
) -> Result<PathBuf, &'static str> {
    if policy.managed_worktree_root.is_some() {
        let root = validate_configured_managed_worktree_root(policy, Some(source))?;
        return Ok(root);
    }
    let mut roots =
        webcodex_runner_config::paths::canonicalize_usable_allowed_roots(&policy.allowed_roots);
    roots.sort_by_key(|root| std::cmp::Reverse(root.components().count()));
    for root in roots {
        if !webcodex_runner_config::paths::path_is_within(source, &root) {
            continue;
        }

        let candidate = root.join(MANAGED_WORKTREE_NAMESPACE);
        if webcodex_runner_config::paths::path_is_within(&candidate, source) {
            continue;
        }
        return Ok(candidate);
    }
    if policy.allow_cwd_anywhere {
        let parent = source.parent().ok_or("managed_worktree_root_unavailable")?;
        let parent =
            canonicalize_existing(parent).map_err(|_| "managed_worktree_root_unavailable")?;
        if !paths_equal(&parent, source) {
            return Ok(parent.join(MANAGED_WORKTREE_NAMESPACE));
        }
    }
    Err("managed_worktree_root_unavailable")
}

fn validate_configured_managed_worktree_root(
    policy: &RunnerPolicy,
    source: Option<&Path>,
) -> Result<PathBuf, &'static str> {
    let Some(configured) = policy.managed_worktree_root.as_ref() else {
        return Err("managed_worktree_root_unavailable");
    };
    let metadata =
        std::fs::symlink_metadata(configured).map_err(|_| "managed_worktree_root_unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("managed_worktree_root_unsafe");
    }
    let root =
        canonicalize_existing(configured).map_err(|_| "managed_worktree_root_unavailable")?;
    if !paths_equal(&root, configured)
        || source.is_some_and(|source| webcodex_runner_config::paths::path_is_within(&root, source))
        || validate_project_path_policy(policy, &root).is_err()
    {
        return Err("managed_worktree_root_unsafe");
    }
    Ok(root)
}

/// Materialize the Runner-owned managed-worktree namespace inside the current
/// Runner filesystem policy. The caller never selects this destination, but the
/// resulting Project must remain usable by the ordinary file/shell/process paths,
/// which continue to enforce `allowed_roots`.
fn ensure_managed_worktree_root(
    policy: &RunnerPolicy,
    source: &Path,
) -> Result<PathBuf, &'static str> {
    if policy.managed_worktree_root.is_some() {
        return managed_worktree_namespace_candidate(policy, source);
    }
    let candidate = managed_worktree_namespace_candidate(policy, source)?;
    match std::fs::symlink_metadata(&candidate) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("managed_worktree_root_unsafe");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(&candidate) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err("managed_worktree_root_unavailable"),
            }
        }
        Err(_) => return Err("managed_worktree_root_unavailable"),
    }

    let root =
        canonicalize_existing(&candidate).map_err(|_| "managed_worktree_root_unavailable")?;
    if !paths_equal(&root, &candidate)
        || validate_project_path_policy(policy, &root).is_err()
        || webcodex_runner_config::paths::path_is_within(&root, source)
    {
        return Err("managed_worktree_root_unsafe");
    }
    Ok(root)
}
fn valid_project_root_fingerprint(value: &str) -> bool {
    value
        .strip_prefix(webcodex_core::runner_protocol::PROJECT_ROOT_FINGERPRINT_PREFIX)
        .is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// Render an already-authorized managed-worktree destination for Git's CLI.
///
/// Rust canonicalization commonly returns `\\?\C:\...` on Windows. Win32
/// filesystem APIs accept that identity, but Git for Windows does not reliably
/// accept the verbatim-disk spelling as a `git worktree add` destination. Keep
/// canonical PathBuf values for policy, registry, recovery, and identity checks;
/// only the child-process argv gets the equivalent ordinary local-disk spelling.
pub(super) fn managed_worktree_git_cli_path(path: &Path) -> String {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};

        let mut components = path.components();
        if let Some(Component::Prefix(prefix)) = components.next() {
            if let Prefix::VerbatimDisk(drive) = prefix.kind() {
                let mut rendered = PathBuf::from(format!("{}:\\", char::from(drive)));
                for component in components {
                    match component {
                        Component::RootDir => {}
                        Component::Normal(part) => rendered.push(part),
                        _ => return path.to_string_lossy().into_owned(),
                    }
                }
                return rendered.to_string_lossy().into_owned();
            }
        }
    }
    path.to_string_lossy().into_owned()
}

fn source_mentions_worktree_path(source: &Path, worktree: &Path) -> Result<bool, &'static str> {
    let listing = managed_worktree_git_text(source, &["worktree", "list", "--porcelain"])?;
    Ok(listing
        .lines()
        .filter_map(|line| line.strip_prefix("worktree "))
        .any(|path| paths_equal(Path::new(path), worktree)))
}

fn managed_worktree_project_toml(
    id: &str,
    name: &str,
    worktree: &str,
    source: &str,
    source_project_id: &str,
    source_root_fingerprint: &str,
    base_ref: &str,
    base_sha: &str,
    operation_id: &str,
) -> String {
    let mut content = build_project_toml_with_registration_source(
        id,
        name,
        worktree,
        Some(AUTO_REGISTERED_REGISTRATION_SOURCE),
        &None,
        true,
    );
    content.push_str("managed_worktree = true\n");
    content.push_str(&format!(
        "registration_incarnation = \"{}\"\n",
        uuid::Uuid::new_v4()
    ));
    content.push_str(&format!("managed_source = {}\n", toml_basic_string(source)));
    content.push_str(&format!(
        "managed_source_project_id = {}\n",
        toml_basic_string(source_project_id)
    ));
    content.push_str(&format!(
        "managed_source_root_fingerprint = {}\n",
        toml_basic_string(source_root_fingerprint)
    ));
    content.push_str(&format!(
        "managed_base_ref = {}\n",
        toml_basic_string(base_ref)
    ));
    content.push_str(&format!(
        "managed_base_sha = {}\n",
        toml_basic_string(base_sha)
    ));
    content.push_str(&format!(
        "managed_operation_id = {}\n",
        toml_basic_string(operation_id)
    ));
    content
}

fn managed_worktree_success(
    start: Instant,
    client_id: &str,
    project: &RunnerProjectFile,
    worktree: &Path,
    base_ref: &str,
    base_sha: &str,
    source_dirty: bool,
    outcome: &'static str,
    registered: bool,
    changed: bool,
) -> CommandResult {
    ok_cmd(
        start,
        serde_json::json!({
            "id": format!("agent:{}:{}", client_id, project.id),
            "agent_project_id": project.id,
            "client_id": client_id,
            "name": project.name,
            "path": worktree.to_string_lossy(),
            "kind": project_wire_kind(project),
            "registration_source": effective_registration_source(project).as_str(),
            "description": project.description,
            "allow_patch": project.allow_patch,
            "disabled": project.disabled,
            "revision": project_revision(project),
            "root_fingerprint": project_root_fingerprint(worktree),
            "registration_incarnation": project.registration_incarnation,
            "lineage": project_lineage(project),
            "source": "managed_worktree",
            "outcome": outcome,
            "registered": registered,
            "created_config": registered,
            "changed": changed,
            "recovered": outcome == "managed_worktree_recovered",
            "managed": true,
            "base_ref": base_ref,
            "base_sha": base_sha,
            "source_dirty": source_dirty,
        }),
    )
}

fn resume_managed_worktree(
    start: Instant,
    policy: &RunnerPolicy,
    project_registry_dir: &Path,
    client_id: &str,
    source_root: &Path,
    source_dirty: bool,
    requested_base_ref: Option<&str>,
    resume_project_id: &str,
) -> CommandResult {
    if policy.managed_worktree_root.is_some()
        && validate_configured_managed_worktree_root(policy, Some(source_root)).is_err()
    {
        return managed_worktree_error(
            start,
            "managed_worktree_root_unsafe",
            false,
            requested_base_ref,
            None,
            Some(source_dirty),
        );
    }
    if validate_project_op_id(resume_project_id).is_err() {
        return managed_worktree_error(
            start,
            "invalid_request",
            false,
            requested_base_ref,
            None,
            Some(source_dirty),
        );
    }
    let projects = match load_project_files_for_path_resolution(project_registry_dir) {
        Ok(projects) => projects,
        Err(error) => {
            return managed_worktree_error(
                start,
                error,
                false,
                requested_base_ref,
                None,
                Some(source_dirty),
            )
        }
    };
    let Some(project) = projects
        .iter()
        .find(|project| project.id == resume_project_id)
        .cloned()
    else {
        return managed_worktree_error(
            start,
            "managed_worktree_resume_mismatch",
            false,
            requested_base_ref,
            None,
            Some(source_dirty),
        );
    };
    let stored_base_sha = project.managed_base_sha.as_deref().filter(|sha| {
        matches!(sha.len(), 40 | 64) && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    let stored_source = project
        .managed_source
        .as_deref()
        .and_then(|path| canonicalize_existing(Path::new(path)).ok());
    if project.disabled
        || !project.managed_worktree
        || stored_base_sha.is_none()
        || stored_source
            .as_ref()
            .is_none_or(|source| !paths_equal(source, source_root))
    {
        return managed_worktree_error(
            start,
            "managed_worktree_resume_mismatch",
            false,
            requested_base_ref,
            stored_base_sha,
            Some(source_dirty),
        );
    }
    if let (Some(stored_source_project_id), Some(stored_source_root_fingerprint)) = (
        project.managed_source_project_id.as_deref(),
        project.managed_source_root_fingerprint.as_deref(),
    ) {
        let current_lineage = resolve_managed_source_project(&projects, source_root);
        if current_lineage.as_ref().is_err()
            || current_lineage
                .as_ref()
                .is_ok_and(|(source_project_id, source_root_fingerprint)| {
                    source_project_id != stored_source_project_id
                        || source_root_fingerprint != stored_source_root_fingerprint
                })
        {
            return managed_worktree_error(
                start,
                "managed_worktree_resume_mismatch",
                false,
                requested_base_ref,
                stored_base_sha,
                Some(source_dirty),
            );
        }
    }
    let base_sha = stored_base_sha.expect("validated managed base SHA");
    if let Some(base_ref) = requested_base_ref {
        match exact_git_commit(source_root, base_ref) {
            Ok(resolved) if resolved == base_sha => {}
            Ok(_) => {
                return managed_worktree_error(
                    start,
                    "managed_worktree_resume_base_mismatch",
                    false,
                    Some(base_ref),
                    Some(base_sha),
                    Some(source_dirty),
                )
            }
            Err(error) => {
                return managed_worktree_error(
                    start,
                    error,
                    false,
                    Some(base_ref),
                    Some(base_sha),
                    Some(source_dirty),
                )
            }
        }
    }
    let worktree = match canonicalize_existing(Path::new(&project.path)) {
        Ok(worktree) => worktree,
        Err(_) => {
            return managed_worktree_error(
                start,
                "managed_worktree_recovery_conflict",
                false,
                project.managed_base_ref.as_deref(),
                Some(base_sha),
                Some(source_dirty),
            )
        }
    };
    // Persisted provenance proves identity, not current filesystem authority.
    // Re-apply the current Runner policy so narrowing allowed_roots takes effect
    // for exact resume just as it does for ordinary Projects.
    if validate_windows_project_root(&worktree).is_err()
        || validate_project_path_policy(policy, &worktree).is_err()
    {
        return managed_worktree_error(
            start,
            "managed_worktree_recovery_conflict",
            false,
            project.managed_base_ref.as_deref(),
            Some(base_sha),
            Some(source_dirty),
        );
    }
    let head = match managed_worktree_git_text(&worktree, &["rev-parse", "HEAD"]) {
        Ok(head) => head,
        Err(error) => {
            return managed_worktree_error(
                start,
                error,
                false,
                project.managed_base_ref.as_deref(),
                Some(base_sha),
                Some(source_dirty),
            )
        }
    };
    let listed = match source_mentions_worktree_path(source_root, &worktree) {
        Ok(listed) => listed,
        Err(error) => {
            return managed_worktree_error(
                start,
                error,
                false,
                project.managed_base_ref.as_deref(),
                Some(base_sha),
                Some(source_dirty),
            )
        }
    };
    if head != base_sha || !listed {
        return managed_worktree_error(
            start,
            "managed_worktree_recovery_conflict",
            false,
            project.managed_base_ref.as_deref(),
            Some(base_sha),
            Some(source_dirty),
        );
    }
    let projected_base_ref = project
        .managed_base_ref
        .as_deref()
        .unwrap_or(requested_base_ref.unwrap_or("HEAD"));
    managed_worktree_success(
        start,
        client_id,
        &project,
        &worktree,
        projected_base_ref,
        base_sha,
        source_dirty,
        "managed_worktree_recovered",
        false,
        false,
    )
}

/// Internal Server↔Runner operation that owns Git/ref/path semantics for managed
/// worktrees. It is intentionally not model-visible; successful output is fed
/// back through the ordinary registered runtime Project authority path.
pub(crate) fn handle_prepare_managed_worktree_operation(
    policy: &RunnerPolicy,
    project_registry_dir: &Path,
    client_id: &str,
    operation: &RunnerProjectOperation,
) -> CommandResult {
    let start = Instant::now();
    let _registry_guard = match project_registry_write_lock().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return managed_worktree_error(start, "operation_failed", false, None, None, None)
        }
    };
    let Some(payload) = serde_json::from_str::<serde_json::Value>(&operation.payload)
        .ok()
        .and_then(|payload| payload.as_object().cloned())
    else {
        return managed_worktree_error(start, "invalid_request", false, None, None, None);
    };
    // Optional project-share parent-root grant forwarded by the Server. It
    // authorizes the *source* the worktree derives from, judged on the
    // Runner's own canonical resolution before any side effect; the derived
    // sibling destination is a Runner-owned namespace and is not required to
    // live inside the grant. Ordinary credentials omit the field and keep the
    // exact previous payload. Malformed scopes fail closed.
    let granted_roots = match payload.get("project_root_scopes") {
        None => None,
        Some(serde_json::Value::Array(items)) => {
            if items.is_empty() {
                return managed_worktree_error(start, "invalid_request", false, None, None, None);
            }
            let mut roots = Vec::with_capacity(items.len());
            for item in items {
                let Some(root) = item.as_str().filter(|root| {
                    !root.is_empty() && !root.contains('\0') && Path::new(root).is_absolute()
                }) else {
                    return managed_worktree_error(
                        start,
                        "invalid_request",
                        false,
                        None,
                        None,
                        None,
                    );
                };
                roots.push(PathBuf::from(root));
            }
            Some(roots)
        }
        Some(_) => {
            return managed_worktree_error(start, "invalid_request", false, None, None, None)
        }
    };
    let expected_field_counts = if granted_roots.is_some() {
        [5usize, 7]
    } else {
        [4usize, 6]
    };
    if !expected_field_counts.contains(&payload.len()) {
        return managed_worktree_error(start, "invalid_request", false, None, None, None);
    }
    let Some(path) = payload
        .get("path")
        .and_then(serde_json::Value::as_str)
        .filter(|path| !path.is_empty() && !path.contains('\0') && Path::new(path).is_absolute())
    else {
        return managed_worktree_error(start, "invalid_project_path", false, None, None, None);
    };
    let requested_base_ref = match payload.get("base_ref") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value))
            if !value.trim().is_empty() && value.len() <= 1024 && !value.contains('\0') =>
        {
            Some(value.clone())
        }
        _ => return managed_worktree_error(start, "invalid_base_ref", false, None, None, None),
    };
    let base_ref = requested_base_ref
        .clone()
        .unwrap_or_else(|| "HEAD".to_string());
    let resume_project_id = match payload.get("resume_project_id") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => Some(value.as_str()),
        _ => {
            return managed_worktree_error(
                start,
                "invalid_request",
                false,
                Some(&base_ref),
                None,
                None,
            )
        }
    };
    let Some(operation_id) = payload
        .get("operation_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| uuid::Uuid::parse_str(value).is_ok())
    else {
        return managed_worktree_error(
            start,
            "invalid_request",
            false,
            Some(&base_ref),
            None,
            None,
        );
    };
    let expected_source_identity = match (
        payload.get("expected_source_project_id"),
        payload.get("expected_source_root_fingerprint"),
    ) {
        (None, None) => None,
        (
            Some(serde_json::Value::String(project_id)),
            Some(serde_json::Value::String(root_fingerprint)),
        ) if validate_project_op_id(project_id).is_ok()
            && valid_project_root_fingerprint(root_fingerprint) =>
        {
            Some((project_id.as_str(), root_fingerprint.as_str()))
        }
        _ => {
            return managed_worktree_error(
                start,
                "invalid_request",
                false,
                Some(&base_ref),
                None,
                None,
            )
        }
    };
    if validate_windows_project_root(Path::new(path)).is_err() {
        return managed_worktree_error(
            start,
            "invalid_project_path",
            false,
            Some(&base_ref),
            None,
            None,
        );
    }
    if let Err(error_kind) =
        validate_model_network_project_ingress_authority(policy, Path::new(path))
    {
        return managed_worktree_error(start, error_kind, false, Some(&base_ref), None, None);
    }
    let source = match canonicalize_existing(Path::new(path)) {
        Ok(source) if source.is_dir() && source.to_str().is_some() => source,
        _ => {
            return managed_worktree_error(
                start,
                "project_path_not_found",
                false,
                Some(&base_ref),
                None,
                None,
            )
        }
    };
    if validate_windows_project_root(&source).is_err()
        || validate_project_path_policy(policy, &source).is_err()
    {
        return managed_worktree_error(
            start,
            "path_outside_allowed_roots",
            false,
            Some(&base_ref),
            None,
            None,
        );
    }
    if let Some(granted_roots) = &granted_roots {
        // Share-grant admission is judged on the Runner's own canonical
        // resolution of the source before any git invocation or registry
        // write: a source that resolved inside the grant at Server-fence time
        // but elsewhere here fails closed. Roots are compared in canonical form
        // too, so unresolved text or a Windows verbatim prefix cannot decide it;
        // an unresolvable root stays denied. The derived worktree destination is
        // not part of this check; allowed_roots above still governs it.
        let admitted = granted_roots.iter().any(|root| {
            canonicalize_existing(root)
                .is_ok_and(|root| webcodex_runner_config::paths::path_is_within(&source, &root))
        });
        if !admitted {
            return managed_worktree_error(
                start,
                "project_path_outside_granted_roots",
                false,
                Some(&base_ref),
                None,
                None,
            );
        }
    }
    let source_root = match managed_worktree_git_text(&source, &["rev-parse", "--show-toplevel"])
        .ok()
        .and_then(|root| canonicalize_existing(Path::new(&root)).ok())
    {
        Some(root) if paths_equal(&root, &source) => root,
        _ => {
            return managed_worktree_error(
                start,
                "source_not_git_repository",
                false,
                Some(&base_ref),
                None,
                None,
            )
        }
    };
    let source_dirty = match managed_worktree_git_text(&source_root, &["status", "--porcelain"]) {
        Ok(status) => !status.is_empty(),
        Err(_) => {
            return managed_worktree_error(
                start,
                "source_git_status_failed",
                false,
                Some(&base_ref),
                None,
                None,
            )
        }
    };
    let source_projects = match load_project_files_for_path_resolution(project_registry_dir) {
        Ok(projects) => projects,
        Err(error) => {
            return managed_worktree_error(
                start,
                error,
                false,
                Some(&base_ref),
                None,
                Some(source_dirty),
            )
        }
    };
    let (source_project_id, source_root_fingerprint) =
        match resolve_managed_source_project(&source_projects, &source_root) {
            Ok(lineage) => lineage,
            Err(error) => {
                return managed_worktree_error(
                    start,
                    error,
                    false,
                    Some(&base_ref),
                    None,
                    Some(source_dirty),
                )
            }
        };
    // Validated before the resume short-circuit so a resume is anchored to the
    // registered source identity too, not only to the stored source path.
    if expected_source_identity.is_some_and(|(expected_project_id, expected_root_fingerprint)| {
        expected_project_id != source_project_id
            || expected_root_fingerprint != source_root_fingerprint
    }) {
        return structured_project_error_cmd(
            start,
            "managed_worktree_source_identity_changed",
            false,
            serde_json::json!({
                "base_ref": base_ref,
                "source_dirty": source_dirty,
                "source_project_id": source_project_id,
                "source_root_fingerprint": source_root_fingerprint,
            }),
        );
    }
    if let Some(resume_project_id) = resume_project_id {
        return resume_managed_worktree(
            start,
            policy,
            project_registry_dir,
            client_id,
            &source_root,
            source_dirty,
            requested_base_ref.as_deref(),
            resume_project_id,
        );
    }
    let base_sha = match exact_git_commit(&source_root, &base_ref) {
        Ok(sha) => sha,
        Err(error) => {
            return managed_worktree_error(
                start,
                error,
                false,
                Some(&base_ref),
                None,
                Some(source_dirty),
            )
        }
    };
    let managed_root = match ensure_managed_worktree_root(policy, &source_root) {
        Ok(root) => root,
        Err(error) => {
            return managed_worktree_error(
                start,
                error,
                false,
                Some(&base_ref),
                Some(&base_sha),
                Some(source_dirty),
            )
        }
    };
    let receipt_path = pending_receipt_path(project_registry_dir, operation_id);
    let completed_path = completed_receipt_path(project_registry_dir, operation_id);
    let completed = match read_pending_receipt(&completed_path) {
        Ok(receipt) => receipt,
        Err(error) => return managed_worktree_error(start, error, false, Some(&base_ref), Some(&base_sha), Some(source_dirty)),
    };
    let pending = match read_pending_receipt(&receipt_path) {
        Ok(pending) => pending,
        Err(error) => return managed_worktree_error(start, error, false, Some(&base_ref), Some(&base_sha), Some(source_dirty)),
    };
    if pending.as_ref().is_some_and(|receipt| {
        receipt.operation_id != operation_id || receipt.source != source_root
            || receipt.source_project_id != source_project_id
            || receipt.source_root_fingerprint != source_root_fingerprint
            || receipt.base_sha != base_sha
    }) {
        return managed_worktree_error(start, "managed_worktree_recovery_conflict", false, Some(&base_ref), Some(&base_sha), Some(source_dirty));
    }
    let destination =
        match load_project_files_for_path_resolution(project_registry_dir).and_then(|projects| {
            choose_managed_destination(&managed_root, &source_root, operation_id, &projects,
                if completed.is_none() { pending.as_ref().map(|receipt| receipt.destination.as_path()) } else { None })
        }) {
            Ok(path) => path,
            Err(error) => {
                return managed_worktree_error(
                    start,
                    error,
                    false,
                    Some(&base_ref),
                    Some(&base_sha),
                    Some(source_dirty),
                )
            }
        };
    if pending.as_ref().is_some_and(|receipt| receipt.destination != destination) {
        return managed_worktree_error(start, "managed_worktree_recovery_conflict", false, Some(&base_ref), Some(&base_sha), Some(source_dirty));
    }
    if completed.as_ref().is_some_and(|receipt| receipt.destination != destination || !destination.exists()) {
        return managed_worktree_error(start, "managed_worktree_recovery_conflict", false, Some(&base_ref), Some(&base_sha), Some(source_dirty));
    }
    let mut created_worktree = false;
    let canonical_worktree = if destination.exists() {
        let Ok(existing) = canonicalize_existing(&destination) else {
            return managed_worktree_error(
                start,
                "managed_worktree_recovery_conflict",
                true,
                Some(&base_ref),
                Some(&base_sha),
                Some(source_dirty),
            );
        };
        let head = match managed_worktree_git_text(&existing, &["rev-parse", "HEAD"]) {
            Ok(head) => head,
            Err(_) => {
                return managed_worktree_error(
                    start,
                    "operation_indeterminate",
                    true,
                    Some(&base_ref),
                    Some(&base_sha),
                    Some(source_dirty),
                )
            }
        };
        let listed = match source_mentions_worktree_path(&source_root, &existing) {
            Ok(listed) => listed,
            Err(_) => {
                return managed_worktree_error(
                    start,
                    "operation_indeterminate",
                    true,
                    Some(&base_ref),
                    Some(&base_sha),
                    Some(source_dirty),
                )
            }
        };
        if head != base_sha || !listed {
            return managed_worktree_error(
                start,
                "managed_worktree_recovery_conflict",
                true,
                Some(&base_ref),
                Some(&base_sha),
                Some(source_dirty),
            );
        }
        existing
    } else {
        match source_mentions_worktree_path(&source_root, &destination) {
            Ok(true) => {
                return managed_worktree_error(
                    start,
                    "managed_worktree_recovery_conflict",
                    true,
                    Some(&base_ref),
                    Some(&base_sha),
                    Some(source_dirty),
                )
            }
            Ok(false) => {}
            Err(_) => {
                return managed_worktree_error(
                    start,
                    "operation_indeterminate",
                    false,
                    Some(&base_ref),
                    Some(&base_sha),
                    Some(source_dirty),
                )
            }
        }
        if pending.is_none() {
            let receipt = PendingMaterialization {
                operation_id: operation_id.to_owned(),
                source: source_root.clone(),
                source_project_id: source_project_id.clone(),
                source_root_fingerprint: source_root_fingerprint.clone(),
                base_sha: base_sha.clone(),
                destination: destination.clone(),
            };
            if let Err(error) = persist_pending_receipt(&receipt_path, &receipt) {
                return managed_worktree_error(start, error, false, Some(&base_ref), Some(&base_sha), Some(source_dirty));
            }
        }
        let destination_string = managed_worktree_git_cli_path(&destination);
        let add_result = run_git_bounded(
            &source_root,
            &[
                "worktree",
                "add",
                "--detach",
                "--no-checkout",
                destination_string.as_str(),
                base_sha.as_str(),
            ],
            MANAGED_WORKTREE_GIT_TIMEOUT,
            None,
        );
        match &add_result {
            Ok(output) if output.status.success() => created_worktree = true,
            Ok(_) if !destination.exists() => {
                return match source_mentions_worktree_path(&source_root, &destination) {
                    Ok(false) => managed_worktree_error(
                        start,
                        "worktree_creation_failed",
                        false,
                        Some(&base_ref),
                        Some(&base_sha),
                        Some(source_dirty),
                    ),
                    Ok(true) => managed_worktree_error(
                        start,
                        "managed_worktree_recovery_conflict",
                        true,
                        Some(&base_ref),
                        Some(&base_sha),
                        Some(source_dirty),
                    ),
                    Err(_) => managed_worktree_error(
                        start,
                        "operation_indeterminate",
                        false,
                        Some(&base_ref),
                        Some(&base_sha),
                        Some(source_dirty),
                    ),
                };
            }
            Err(_) if !destination.exists() => {
                return match source_mentions_worktree_path(&source_root, &destination) {
                    Ok(true) => managed_worktree_error(
                        start,
                        "managed_worktree_recovery_conflict",
                        true,
                        Some(&base_ref),
                        Some(&base_sha),
                        Some(source_dirty),
                    ),
                    Ok(false) | Err(_) => managed_worktree_error(
                        start,
                        "operation_indeterminate",
                        false,
                        Some(&base_ref),
                        Some(&base_sha),
                        Some(source_dirty),
                    ),
                };
            }
            Ok(_) | Err(_) => {
                // An uncertain add is not a successful creation, even if
                // HEAD and the linked-worktree metadata already exist.
                return managed_worktree_error(
                    start, "operation_indeterminate", true,
                    Some(&base_ref), Some(&base_sha), Some(source_dirty),
                );
            }
        }
        let worktree = match canonicalize_existing(&destination) {
            Ok(worktree) => worktree,
            Err(_) => {
                return managed_worktree_error(
                    start,
                    "operation_indeterminate",
                    true,
                    Some(&base_ref),
                    Some(&base_sha),
                    Some(source_dirty),
                )
            }
        };
        let head = match managed_worktree_git_text(&worktree, &["rev-parse", "HEAD"]) {
            Ok(head) => head,
            Err(_) => {
                return managed_worktree_error(
                    start,
                    "operation_indeterminate",
                    true,
                    Some(&base_ref),
                    Some(&base_sha),
                    Some(source_dirty),
                )
            }
        };
        let listed = match source_mentions_worktree_path(&source_root, &worktree) {
            Ok(listed) => listed,
            Err(_) => {
                return managed_worktree_error(
                    start,
                    "operation_indeterminate",
                    true,
                    Some(&base_ref),
                    Some(&base_sha),
                    Some(source_dirty),
                )
            }
        };
        if head != base_sha || !listed {
            return managed_worktree_error(
                start,
                "managed_worktree_recovery_conflict",
                true,
                Some(&base_ref),
                Some(&base_sha),
                Some(source_dirty),
            );
        }
        if worktree.parent().is_none_or(|parent| !paths_equal(parent, &managed_root))
            || validate_project_path_policy(policy, &worktree).is_err()
        {
            return managed_worktree_error(
                start, "managed_worktree_root_unsafe", true,
                Some(&base_ref), Some(&base_sha), Some(source_dirty),
            );
        }
        if let Err(error) = materialize_new_worktree(&worktree, &base_sha) {
            return managed_worktree_error(
                start, error, true,
                Some(&base_ref), Some(&base_sha), Some(source_dirty),
            );
        }
        worktree
    };
    if canonical_worktree
        .parent()
        .is_none_or(|parent| !paths_equal(parent, &managed_root))
        || validate_project_path_policy(policy, &canonical_worktree).is_err()
    {
        return managed_worktree_error(
            start,
            "managed_worktree_root_unsafe",
            true,
            Some(&base_ref),
            Some(&base_sha),
            Some(source_dirty),
        );
    }
    let projects = match load_project_files_for_path_resolution(project_registry_dir) {
        Ok(projects) => projects,
        Err(error) => {
            return managed_worktree_error(
                start,
                error,
                true,
                Some(&base_ref),
                Some(&base_sha),
                Some(source_dirty),
            )
        }
    };
    let matches = projects_matching_canonical_path(&projects, &canonical_worktree);
    if matches.len() > 1 {
        return managed_worktree_error(
            start,
            "ambiguous_project_path",
            true,
            Some(&base_ref),
            Some(&base_sha),
            Some(source_dirty),
        );
    }
    if let Some(project) = matches.into_iter().next() {
        let same_operation = project.managed_worktree
            && project.managed_operation_id.as_deref() == Some(operation_id)
            && project.managed_base_sha.as_deref() == Some(base_sha.as_str())
            && project.managed_source.as_deref() == source_root.to_str()
            && project.managed_source_project_id.as_deref() == Some(source_project_id.as_str())
            && project.managed_source_root_fingerprint.as_deref()
                == Some(source_root_fingerprint.as_str());
        if project.disabled || !same_operation {
            return managed_worktree_error(
                start,
                "managed_worktree_recovery_conflict",
                true,
                Some(&base_ref),
                Some(&base_sha),
                Some(source_dirty),
            );
        }
        if let Some(receipt) = pending.as_ref() {
            if let Err(error) = mark_materialization_completed(&completed_path, receipt) {
                return managed_worktree_error(start, error, true, Some(&base_ref), Some(&base_sha), Some(source_dirty));
            }
            if std::fs::remove_file(&receipt_path).is_err() {
                return managed_worktree_error(start, "operation_indeterminate", true, Some(&base_ref), Some(&base_sha), Some(source_dirty));
            }
        }
        return managed_worktree_success(
            start,
            client_id,
            &project,
            &canonical_worktree,
            &base_ref,
            &base_sha,
            source_dirty,
            "managed_worktree_recovered",
            false,
            false,
        );
    }
    // No registered project matched. Recovery is permitted only by a
    // previously persisted, exact creation receipt and the current root policy.
    if !created_worktree {
        if pending.is_none() || completed.is_some() {
            return managed_worktree_error(start, "managed_worktree_recovery_conflict", true, Some(&base_ref), Some(&base_sha), Some(source_dirty));
        }
        if let Err(error) = resume_pending_materialization(&canonical_worktree, &base_sha) {
            return managed_worktree_error(start, error, true, Some(&base_ref), Some(&base_sha), Some(source_dirty));
        }
    }
    let project_id =
        match choose_auto_project_id(project_registry_dir, &projects, &canonical_worktree) {
            Ok(id) => id,
            Err(error) => {
                return managed_worktree_error(
                    start,
                    error,
                    true,
                    Some(&base_ref),
                    Some(&base_sha),
                    Some(source_dirty),
                )
            }
        };
    let Some(worktree_string) = canonical_worktree.to_str() else {
        return managed_worktree_error(
            start,
            "invalid_project_path",
            true,
            Some(&base_ref),
            Some(&base_sha),
            Some(source_dirty),
        );
    };
    let source_string = source_root.to_str().expect("validated UTF-8 source path");
    let content = managed_worktree_project_toml(
        &project_id,
        &bounded_project_name(&canonical_worktree),
        worktree_string,
        source_string,
        &source_project_id,
        &source_root_fingerprint,
        &base_ref,
        &base_sha,
        operation_id,
    );
    // Retain pending ownership across pre-publication failures. Never report
    // success until registry readback and the completion fence are durable.
    match write_project_toml_atomic(project_registry_dir, &project_id, &content, false) {
        Ok(_) => {}
        Err(ProjectTomlWriteError::BeforeRename) => {
            return managed_worktree_error(
                start,
                "worktree_registration_failed",
                true,
                Some(&base_ref),
                Some(&base_sha),
                Some(source_dirty),
            )
        }
        Err(ProjectTomlWriteError::AfterRename) => {
            return managed_worktree_error(
                start,
                "operation_indeterminate",
                true,
                Some(&base_ref),
                Some(&base_sha),
                Some(source_dirty),
            )
        }
    }
    let persisted = match std::fs::read_to_string(project_registry_dir.join(format!("{project_id}.toml"))) {
        Ok(value) if value == content => value,
        _ => return managed_worktree_error(start, "operation_indeterminate", true, Some(&base_ref), Some(&base_sha), Some(source_dirty)),
    };
    let receipt = match read_pending_receipt(&receipt_path) {
        Ok(Some(receipt)) => receipt,
        _ => return managed_worktree_error(start, "operation_indeterminate", true, Some(&base_ref), Some(&base_sha), Some(source_dirty)),
    };
    if let Err(error) = mark_materialization_completed(&completed_path, &receipt) {
        return managed_worktree_error(start, error, true, Some(&base_ref), Some(&base_sha), Some(source_dirty));
    }
    if std::fs::remove_file(&receipt_path).is_err() {
        return managed_worktree_error(start, "operation_indeterminate", true, Some(&base_ref), Some(&base_sha), Some(source_dirty));
    }
    let project = match parse_runner_project_toml(&persisted) {
        Ok(project) => project,
        Err(_) => {
            return managed_worktree_error(
                start,
                "operation_indeterminate",
                true,
                Some(&base_ref),
                Some(&base_sha),
                Some(source_dirty),
            )
        }
    };
    managed_worktree_success(
        start,
        client_id,
        &project,
        &canonical_worktree,
        &base_ref,
        &base_sha,
        source_dirty,
        if created_worktree {
            "managed_worktree_created"
        } else {
            "managed_worktree_recovered"
        },
        true,
        true,
    )
}

#[cfg(test)]
mod materialization_tests {
    use super::*;

    fn git(path: &Path, args: &[&str]) -> String {
        managed_worktree_git_text(path, args).expect("fixture git")
    }

    #[test]
    fn fresh_no_checkout_materializes_exact_tree_and_preserves_source() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("source");
        let target = root.path().join("target");
        std::fs::create_dir(&source).unwrap();
        git(&source, &["init"]);
        git(&source, &["config", "user.name", "Fixture"]);
        git(&source, &["config", "user.email", "fixture@example.invalid"]);
        std::fs::write(source.join("tracked.txt"), "committed").unwrap();
        git(&source, &["add", "tracked.txt"]);
        git(&source, &["commit", "-m", "fixture"]);
        let head = git(&source, &["rev-parse", "HEAD"]);
        std::fs::write(source.join("tracked.txt"), "user edit").unwrap();
        let target_arg = managed_worktree_git_cli_path(&target);
        git(&source, &["worktree", "add", "--detach", "--no-checkout", &target_arg, &head]);
        assert!(verify_new_worktree_materialization(&target, &head).is_err());
        // Simulate interruption after the no-checkout allocation. An existing
        // lock must be preserved. Only after release can exact recovery resume.
        let git_dir = git(&target, &["rev-parse", "--absolute-git-dir"]);
        let lock = Path::new(&git_dir).join("index.lock");
        assert!(!Path::new(&git_dir).join("index").exists(), "verification must not create an index");
        assert!(!lock.exists(), "verification must not create an index lock");
        std::fs::write(&lock, "").unwrap();
        assert!(resume_pending_materialization(&target, &head).is_err());
        assert!(lock.exists());
        std::fs::remove_file(&lock).unwrap();
        // A dead attempt's private lock cannot block a new attempt.
        let abandoned = Path::new(&git_dir).join("webcodex-materialization-abandoned");
        std::fs::create_dir(&abandoned).unwrap();
        std::fs::write(abandoned.join("index.lock"), "prior attempt").unwrap();
        resume_pending_materialization(&target, &head).unwrap();
        assert_eq!(std::fs::read_to_string(abandoned.join("index.lock")).unwrap(), "prior attempt");
        assert!(!lock.exists());
        assert_eq!(std::fs::read_to_string(target.join("tracked.txt")).unwrap(), "committed");
        assert_eq!(std::fs::read_to_string(source.join("tracked.txt")).unwrap(), "user edit");
        std::fs::remove_file(target.join("tracked.txt")).unwrap();
        assert!(verify_new_worktree_materialization(&target, &head).is_err());
        resume_pending_materialization(&target, &head).unwrap();
        std::fs::write(target.join("tracked.txt"), "unexpected edit").unwrap();
        assert!(resume_pending_materialization(&target, &head).is_err());
        assert_eq!(std::fs::read_to_string(target.join("tracked.txt")).unwrap(), "unexpected edit");
    }
}
