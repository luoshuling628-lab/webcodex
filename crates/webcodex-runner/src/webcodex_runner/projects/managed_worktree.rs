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
const MANAGED_WORKTREE_NAMESPACE: &str = ".webcodex-worktrees";

/// The slug is routing text, not recovery identity. Only a registered exact
/// operation establishes whether an occupied path is ours or a collision.
fn choose_managed_destination(
    root: &Path,
    source: &Path,
    operation_id: &str,
    projects: &[RunnerProjectFile],
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

/**
 * Runner-local, read-only Git admission for a freshly managed worktree.
 *
 * The Server inventory is not sufficient: it can lag behind files created
 * after the last Runner snapshot. This is intentionally NOT a deletion
 * permission, and does not prove GitHub recovery, live-process leases or
 * successful Project CAS unregister. Call only under the trusted native
 * closeout Owner after verifying exact managed registration identity.
 */
/// Validate the *registered* immutable lineage before considering physical
/// reclamation. A folder name, an observation JSON, or a process-wide empty
/// queue is never sufficient to establish ownership.
pub(super) fn managed_worktree_reclaim_lineage_gate(
    child: &RunnerProjectFile,
    source_project: &RunnerProjectFile,
) -> Result<(), &'static str> {
    if !child.managed_worktree
        || effective_registration_source(child).as_str() != AUTO_REGISTERED_REGISTRATION_SOURCE
        || child
            .registration_incarnation
            .as_deref()
            .is_none_or(|v| uuid::Uuid::parse_str(v).is_err())
        || child
            .managed_operation_id
            .as_deref()
            .is_none_or(|v| uuid::Uuid::parse_str(v).is_err())
    {
        return Err("managed_reclaim_registration_identity_invalid");
    }
    if child.managed_source_project_id.as_deref() != Some(source_project.id.as_str())
        || source_project.managed_worktree
        || child.id == source_project.id
    {
        return Err("managed_reclaim_source_project_mismatch");
    }
    let source = canonicalize_existing(Path::new(&source_project.path))
        .map_err(|_| "managed_reclaim_source_missing")?;
    let registered_source = child
        .managed_source
        .as_deref()
        .ok_or("managed_reclaim_lineage_incomplete")?;
    if !paths_equal(Path::new(registered_source), &source)
        || child.managed_source_root_fingerprint.as_deref()
            != Some(project_root_fingerprint(&source).as_str())
    {
        return Err("managed_reclaim_source_fingerprint_mismatch");
    }
    let child_path = canonicalize_existing(Path::new(&child.path))
        .map_err(|_| "managed_reclaim_worktree_missing")?;
    if paths_equal(&child_path, &source)
        || child_path.parent().is_none()
        || child.managed_base_sha.as_deref().is_none_or(|sha| {
            !matches!(sha.len(), 40 | 64) || !sha.bytes().all(|c| c.is_ascii_hexdigit())
        })
    {
        return Err("managed_reclaim_lineage_incomplete");
    }
    managed_worktree_local_git_reclaim_gate(
        &source,
        &child_path,
        child.managed_base_sha.as_deref().expect("checked above"),
    )
}

pub(super) fn managed_worktree_local_git_reclaim_gate(
    source: &Path,
    worktree: &Path,
    expected_head: &str,
) -> Result<(), &'static str> {
    if !matches!(expected_head.len(), 40 | 64)
        || !expected_head.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err("managed_reclaim_invalid_expected_head");
    }
    let metadata =
        std::fs::symlink_metadata(worktree).map_err(|_| "managed_reclaim_worktree_missing")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("managed_reclaim_worktree_unsafe_path");
    }
    if paths_equal(source, worktree) || !source_mentions_worktree_path(source, worktree)? {
        return Err("managed_reclaim_source_binding_mismatch");
    }
    let head = managed_worktree_git_text(worktree, &["rev-parse", "--verify", "HEAD"])?;
    if !head.eq_ignore_ascii_case(expected_head) {
        return Err("managed_reclaim_head_drift");
    }
    let dirty = managed_worktree_git_text(
        worktree,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !dirty.is_empty() {
        return Err("managed_reclaim_unique_content");
    }
    let ignored = managed_worktree_git_text(
        worktree,
        &["ls-files", "--others", "--ignored", "--exclude-standard"],
    )?;
    if !ignored.is_empty() {
        return Err("managed_reclaim_ignored_content");
    }
    // Detached HEAD is mandatory; do not dispose a unique local branch tip.
    let branch = run_git_bounded(
        worktree,
        &["symbolic-ref", "--quiet", "HEAD"],
        MANAGED_WORKTREE_GIT_TIMEOUT,
        None,
    )
    .map_err(|_| "managed_reclaim_git_state_unverified")?;
    if branch.stdout_capped || branch.stderr_capped || branch.status.code() != Some(1) {
        return Err("managed_reclaim_branch_or_git_state");
    }
    let git_dir = managed_worktree_git_text(worktree, &["rev-parse", "--absolute-git-dir"])?;
    let git_dir = Path::new(&git_dir);
    if !git_dir.is_dir() {
        return Err("managed_reclaim_gitdir_unverified");
    }
    if git_dir.join("locked").exists() {
        return Err("managed_reclaim_locked");
    }
    // A fresh query of an owner-bound local source is NOT a remote GitHub
    // durability proof. The separate authenticated executor must require it.
    Ok(())
}

/// Require a fresh, exact remote branch head before disposal. Local tracking
/// branches and cached Git state are not evidence that a commit survived on
/// the server. A symbolic HEAD or a tag is deliberately insufficient: the
/// caller must supply an immutable source-bound branch ref.
#[allow(dead_code)]
pub(super) fn managed_worktree_remote_exact_ref_gate(
    source: &Path,
    expected_sha: &str,
    remote: &str,
    expected_origin_url: &str,
    branch_ref: &str,
) -> Result<(), &'static str> {
    if !matches!(expected_sha.len(), 40 | 64)
        || !expected_sha.bytes().all(|c| c.is_ascii_hexdigit())
        || remote != "origin"
        || expected_origin_url.is_empty()
        || !branch_ref.starts_with("refs/heads/")
        || branch_ref.len() <= "refs/heads/".len()
        || branch_ref
            .bytes()
            .any(|c| !c.is_ascii_alphanumeric() && !matches!(c, b'/' | b'-' | b'_' | b'.'))
        || branch_ref.contains("..")
        || branch_ref.ends_with('/')
        || branch_ref.ends_with(".lock")
    {
        return Err("managed_reclaim_remote_ref_unverified");
    }
    let configured_origin =
        managed_worktree_git_text(source, &["config", "--get", "remote.origin.url"])?;
    if configured_origin != expected_origin_url {
        return Err("managed_reclaim_remote_origin_mismatch");
    }
    let output = run_git_bounded(
        source,
        &["ls-remote", "--exit-code", "--refs", "origin", branch_ref],
        MANAGED_WORKTREE_GIT_TIMEOUT,
        None,
    )
    .map_err(|_| "managed_reclaim_remote_unreachable")?;
    if !output.status.success() || output.stdout_capped || output.stderr_capped {
        return Err("managed_reclaim_remote_unreachable");
    }
    let stdout =
        String::from_utf8(output.stdout).map_err(|_| "managed_reclaim_remote_ref_unverified")?;
    let mut rows = stdout.lines();
    let Some(row) = rows.next() else {
        return Err("managed_reclaim_remote_ref_unverified");
    };
    if rows.next().is_some() {
        return Err("managed_reclaim_remote_ref_unverified");
    }
    let Some((sha, name)) = row.split_once('\t') else {
        return Err("managed_reclaim_remote_ref_unverified");
    };
    if name != branch_ref || !sha.eq_ignore_ascii_case(expected_sha) {
        return Err("managed_reclaim_remote_commit_not_recoverable");
    }
    Ok(())
}

/// The filesystem step of an admitted native closeout, not a public
/// operation. The Server must retain both Runner Job and Session fences and
/// the Runner caller must own the exact registration CAS and durable journal
/// for the whole transaction before invoking this step.
#[allow(dead_code)]
pub(super) fn managed_worktree_normal_remove_after_gates(
    source: &Path,
    worktree: &Path,
    expected_sha: &str,
    expected_origin_url: &str,
    remote_branch_ref: &str,
) -> Result<(), &'static str> {
    managed_worktree_local_git_reclaim_gate(source, worktree, expected_sha)?;
    managed_worktree_remote_exact_ref_gate(
        source,
        expected_sha,
        "origin",
        expected_origin_url,
        remote_branch_ref,
    )?;
    // Revalidate immediately before the irreversible Git operation. Never
    // use --force or prune: Git must reject a dirty or locked worktree itself.
    managed_worktree_local_git_reclaim_gate(source, worktree, expected_sha)?;
    let target = managed_worktree_git_cli_path(worktree);
    let output = run_git_bounded(
        source,
        &["worktree", "remove", target.as_str()],
        MANAGED_WORKTREE_GIT_TIMEOUT,
        None,
    )
    .map_err(|_| "managed_reclaim_remove_indeterminate")?;
    if !output.status.success() || output.stdout_capped || output.stderr_capped {
        return Err("managed_reclaim_remove_indeterminate");
    }
    // A successful exit alone is not the durable post-removal receipt.
    if std::fs::symlink_metadata(worktree).is_ok()
        || source_mentions_worktree_path(source, worktree).unwrap_or(true)
    {
        return Err("managed_reclaim_remove_indeterminate");
    }
    Ok(())
}

#[cfg(test)]
mod remote_recoverability_tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("git executable");
        assert!(
            output.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn native_reclaim_requires_exact_fresh_remote_branch_sha() {
        let temp = tempfile::tempdir().unwrap();
        let bare = temp.path().join("bare.git");
        let source = temp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        git(temp.path(), &["init", "--bare", bare.to_str().unwrap()]);
        git(&source, &["init"]);
        git(&source, &["config", "user.name", "Fixture"]);
        git(
            &source,
            &["config", "user.email", "fixture@example.invalid"],
        );
        std::fs::write(source.join("tracked.txt"), "v1").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "first"]);
        git(&source, &["branch", "-M", "main"]);
        git(
            &source,
            &["remote", "add", "origin", bare.to_str().unwrap()],
        );
        git(&source, &["push", "origin", "main"]);
        let sha = git(&source, &["rev-parse", "HEAD"]);
        assert_eq!(
            managed_worktree_remote_exact_ref_gate(
                &source,
                &sha,
                "origin",
                bare.to_str().unwrap(),
                "refs/heads/main"
            ),
            Ok(())
        );
        assert_eq!(
            managed_worktree_remote_exact_ref_gate(
                &source,
                &sha,
                "origin",
                bare.to_str().unwrap(),
                "HEAD"
            ),
            Err("managed_reclaim_remote_ref_unverified")
        );
        assert_eq!(
            managed_worktree_remote_exact_ref_gate(
                &source,
                &sha,
                "other",
                bare.to_str().unwrap(),
                "refs/heads/main"
            ),
            Err("managed_reclaim_remote_ref_unverified")
        );

        assert_eq!(
            managed_worktree_remote_exact_ref_gate(
                &source,
                &sha,
                "origin",
                "https://github.com/other/repo.git",
                "refs/heads/main"
            ),
            Err("managed_reclaim_remote_origin_mismatch")
        );

        std::fs::write(source.join("tracked.txt"), "v2").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "unpushed"]);
        let unpushed = git(&source, &["rev-parse", "HEAD"]);
        assert_eq!(
            managed_worktree_remote_exact_ref_gate(
                &source,
                &unpushed,
                "origin",
                bare.to_str().unwrap(),
                "refs/heads/main"
            ),
            Err("managed_reclaim_remote_commit_not_recoverable")
        );
        git(&source, &["push", "origin", "main"]);
        assert_eq!(
            managed_worktree_remote_exact_ref_gate(
                &source,
                &unpushed,
                "origin",
                bare.to_str().unwrap(),
                "refs/heads/main"
            ),
            Ok(())
        );
    }

    #[test]
    fn native_reclaim_normal_remove_protects_unique_data_and_removes_clean_worktree() {
        let temp = tempfile::tempdir().unwrap();
        let bare = temp.path().join("bare.git");
        let source = temp.path().join("source");
        let child = temp.path().join("worktree");
        std::fs::create_dir(&source).unwrap();
        git(temp.path(), &["init", "--bare", bare.to_str().unwrap()]);
        git(&source, &["init"]);
        git(&source, &["config", "user.name", "Fixture"]);
        git(
            &source,
            &["config", "user.email", "fixture@example.invalid"],
        );
        std::fs::write(source.join("tracked.txt"), "recoverable").unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "recoverable"]);
        git(&source, &["branch", "-M", "main"]);
        git(
            &source,
            &["remote", "add", "origin", bare.to_str().unwrap()],
        );
        git(&source, &["push", "origin", "main"]);
        let sha = git(&source, &["rev-parse", "HEAD"]);
        git(
            &source,
            &[
                "worktree",
                "add",
                "--detach",
                &managed_worktree_git_cli_path(&child),
                "HEAD",
            ],
        );
        std::fs::write(child.join("local-untracked.txt"), "keep forever").unwrap();
        assert_eq!(
            managed_worktree_normal_remove_after_gates(
                &source,
                &child,
                &sha,
                bare.to_str().unwrap(),
                "refs/heads/main"
            ),
            Err("managed_reclaim_unique_content")
        );
        assert!(child.join("local-untracked.txt").exists());
        std::fs::remove_file(child.join("local-untracked.txt")).unwrap();
        assert_eq!(
            managed_worktree_normal_remove_after_gates(
                &source,
                &child,
                &sha,
                bare.to_str().unwrap(),
                "refs/heads/main"
            ),
            Ok(())
        );
        assert!(!child.exists());
        assert!(!source_mentions_worktree_path(&source, &child).unwrap());
    }
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
    let destination =
        match load_project_files_for_path_resolution(project_registry_dir).and_then(|projects| {
            choose_managed_destination(&managed_root, &source_root, operation_id, &projects)
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
        let destination_string = managed_worktree_git_cli_path(&destination);
        let add_result = run_git_bounded(
            &source_root,
            &[
                "worktree",
                "add",
                "--detach",
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
            Ok(_) | Err(_) => {}
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
    let project = match parse_runner_project_toml(&content) {
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
