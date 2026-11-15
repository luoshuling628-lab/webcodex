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
pub(super) enum CloseoutPhase {
    Prepared,
    GitRemoved,
    Unregistered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeCloseoutRecord {
    pub operation_id: String,
    pub project_id: String,
    pub expected_revision: String,
    pub expected_incarnation: String,
    pub expected_head: String,
    pub expected_root_fingerprint: String,
    pub expected_origin_url: String,
    pub expected_remote_ref: String,
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
            phase: CloseoutPhase::Prepared,
        }
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
