use crate::auth::{AuthContext, AuthKind};
use crate::db::AdminProjectAudit;
use crate::json_digest::update_sha256_with_json;
use crate::runner_http::{RunnerFeature, RunnerRegistry};
use crate::runner_protocol::RunnerProjectSummary;
use crate::tool_runtime::{ToolResult, ToolRuntime};
use crate::Database;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Mutex;
use webcodex_core::runtime_contract::validate_project_op_path;

const WAIT_SECS: u64 = 30;
pub(crate) const IDEMPOTENCY_KEY_MAX: usize = 128;
type IdempotencyLocks = Mutex<HashMap<String, Arc<Mutex<()>>>>;
static IDEMPOTENCY_LOCKS: OnceLock<IdempotencyLocks> = OnceLock::new();

fn idempotency_locks() -> &'static IdempotencyLocks {
    IDEMPOTENCY_LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisterProjectRequest {
    pub client_id: String,
    pub project_id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub path: String,
    #[serde(default = "default_true")]
    pub allow_patch: bool,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateProjectRequest {
    pub client_id: String,
    pub project_id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub path: String,
    #[serde(default = "default_true")]
    pub allow_patch: bool,
    #[serde(default)]
    pub git_init: bool,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub adopt_existing_empty: bool,
    pub idempotency_key: String,
}

/// Read-only admission request. Its result can NEVER be used as a
/// filesystem removal permit: the protective guards are released on return.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeCloseoutAdmissionRequest {
    pub project: String,
    pub expected_revision: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectMutationRequest {
    pub project: String,
    pub expected_revision: String,
    pub idempotency_key: String,
    pub confirm: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateProjectAllowPatchRequest {
    pub project: String,
    pub expected_revision: String,
    pub allow_patch: bool,
    pub idempotency_key: String,
    pub confirm: bool,
}

// Shared with the HTTP admin guard. Disallowed machine credential kinds
// cannot gain access even if a malformed identity includes an admin scope.
pub(crate) fn admin_project_mutation_authorized(auth: &AuthContext) -> bool {
    auth.is_admin()
        && !matches!(
            auth.kind,
            AuthKind::AgentToken
                | AuthKind::ProjectCredential
                | AuthKind::SharedKey
                | AuthKind::OpenAnonymous
                | AuthKind::AccountCredential
        )
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceResponse {
    pub status: u16,
    pub body: Value,
}

/// Separates user-admin recovery from the Server's own narrowly scoped
/// post-crash receipt reconciliation. DurableOwner has no route/HTTP entry
/// and cannot request a new delete, only verify a previously sealed intent.
#[allow(dead_code)]
enum NativeRecoveryAuthority<'a> {
    Admin(&'a AuthContext),
    DurableOwner,
}

struct ProjectUnregisterFence {
    registry: Arc<RunnerRegistry>,
    project: String,
}

impl Drop for ProjectUnregisterFence {
    fn drop(&mut self) {
        let registry = self.registry.clone();
        let project = self.project.clone();
        tokio::spawn(async move {
            registry.end_project_unregister(&project).await;
        });
    }
}

/// Native closeout-only Owner fences. Both are held over the full future
/// closeout transaction and released even if execution fails or is cancelled.
/// This is not a removal permit: the Runner must independently check the
/// exact revision, source lineage, process leases, remote recoverability and
/// persisted post-removal receipt before doing any filesystem mutation.
#[allow(dead_code)]
pub(crate) struct NativeManagedCloseoutFences {
    _jobs: ProjectUnregisterFence,
    _sessions: webcodex_workflow_session::SessionProjectUnregisterGuard,
}

impl NativeManagedCloseoutFences {
    /// Upgrade the exact already-held Session fence to a durable reservation,
    /// while the Runner Job-start fence remains held. This only prepares
    /// execution ownership; it is never a delete authorization by itself.
    #[allow(dead_code)]
    pub(crate) fn persist_owner_intent(
        &self,
        operation_id: &str,
        payload_json: &str,
    ) -> Result<(), ServiceResponse> {
        self._sessions
            .persist_managed_closeout_with_binding(operation_id, payload_json)
            .map_err(|_| api_error(503, "native_closeout_durable_intent_unverified"))
    }
}

/// Validate the exact terminal Runner payload at the trusted transport
/// boundary. This parser alone does NOT authenticate its provenance: only a
/// matched RunnerRegistry request/response from the fenced live instance may
/// call it. Never accept user-supplied JSON as a terminal receipt.
#[allow(dead_code)]
fn native_closeout_terminal_receipt_matches(
    exit_code: Option<i32>,
    output: &Value,
    project_id: &str,
    operation_id: &str,
    revision: &str,
    incarnation: &str,
) -> bool {
    exit_code == Some(0)
        && output.get("error_code").is_none()
        && output.get("operation").and_then(Value::as_str) == Some("native_managed_closeout")
        && output.get("outcome").and_then(Value::as_str) == Some("native_closeout_completed")
        && output.get("changed").and_then(Value::as_bool) == Some(true)
        && output.get("phase").and_then(Value::as_str) == Some("unregistered")
        && output.get("agent_project_id").and_then(Value::as_str) == Some(project_id)
        && output.get("operation_id").and_then(Value::as_str) == Some(operation_id)
        && output.get("expected_revision").and_then(Value::as_str) == Some(revision)
        && output
            .get("registration_incarnation")
            .and_then(Value::as_str)
            == Some(incarnation)
}

/// Construct the exact Runner-side closeout candidate from two independently
/// reported current Project inventory entries and an explicitly supplied,
/// externally verified recovery ref. Neither a local HEAD nor an inferred
/// default branch may fill in an absent recovery binding.
#[allow(dead_code)]
fn native_closeout_bound_runner_payload(
    child: &RunnerProjectSummary,
    source: &RunnerProjectSummary,
    expected_revision: &str,
    operation_id: &str,
    verified_origin_url: &str,
    verified_remote_ref: &str,
) -> Result<Value, &'static str> {
    use crate::runner_protocol::RunnerProjectLineage;
    let RunnerProjectLineage::ManagedWorktreeSource {
        source_project_id,
        source_root_fingerprint,
        base_sha,
    } = child
        .lineage
        .as_ref()
        .ok_or("native_closeout_lineage_missing")?;
    let clean_sha =
        |s: &str| matches!(s.len(), 40 | 64) && s.bytes().all(|c| c.is_ascii_hexdigit());
    if !native_closeout_owner_identity_ready(child, expected_revision)
        || child.id == source.id
        || source.id != *source_project_id
        || source.root_fingerprint.as_deref() != Some(source_root_fingerprint)
        || child.git_head.as_deref() != Some(base_sha)
        || !clean_sha(base_sha)
        || uuid::Uuid::parse_str(operation_id).is_err()
        || child.path.is_empty()
        || source.path.is_empty()
        || child.path == source.path
        || !source.path.chars().all(|ch| !ch.is_control())
        || !child.path.chars().all(|ch| !ch.is_control())
        || verified_origin_url.trim() != verified_origin_url
        || verified_origin_url.is_empty()
        || verified_remote_ref.len() > 256
        || !verified_remote_ref.starts_with("refs/heads/")
        || verified_remote_ref.len() == "refs/heads/".len()
        || verified_remote_ref.contains("..")
        || verified_remote_ref
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ':' || c == '\\')
        || !verified_remote_ref["refs/heads/".len()..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        return Err("native_closeout_binding_unverified");
    }
    let root = child
        .root_fingerprint
        .as_deref()
        .ok_or("native_closeout_root_unverified")?;
    let incarnation = child
        .registration_incarnation
        .as_deref()
        .ok_or("native_closeout_incarnation_unverified")?;
    if uuid::Uuid::parse_str(incarnation).is_err() {
        return Err("native_closeout_incarnation_unverified");
    }
    Ok(json!({
        "operation_id": operation_id,
        "project_id": child.id,
        "expected_revision": expected_revision,
        "expected_incarnation": incarnation,
        "expected_head": base_sha,
        "expected_root_fingerprint": root,
        "expected_origin_url": verified_origin_url,
        "expected_remote_ref": verified_remote_ref,
        "source_root": source.path,
        "worktree_root": child.path,
        "phase": "prepared"
    }))
}

/// Read-only recovered terminal must not masquerade as a fresh mutation
/// receipt. Identity matching is necessary but the trusted exact-instance
/// Registry response is also required before releasing a durable lease.
#[allow(dead_code)]
fn native_closeout_readonly_terminal_receipt_matches(
    exit_code: Option<i32>,
    output: &Value,
    project_id: &str,
    operation_id: &str,
    revision: &str,
    incarnation: &str,
) -> bool {
    exit_code == Some(0)
        && output.get("error_code").is_none()
        && output.get("operation").and_then(Value::as_str)
            == Some("native_managed_closeout_receipt")
        && output.get("outcome").and_then(Value::as_str) == Some("native_closeout_completed")
        && output.get("changed").and_then(Value::as_bool) == Some(false)
        && output.get("phase").and_then(Value::as_str) == Some("unregistered")
        && output.get("agent_project_id").and_then(Value::as_str) == Some(project_id)
        && output.get("operation_id").and_then(Value::as_str) == Some(operation_id)
        && output.get("expected_revision").and_then(Value::as_str) == Some(revision)
        && output
            .get("registration_incarnation")
            .and_then(Value::as_str)
            == Some(incarnation)
}

fn native_closeout_owner_identity_ready(
    project: &RunnerProjectSummary,
    expected_revision: &str,
) -> bool {
    matches!(
        project.lineage,
        Some(crate::runner_protocol::RunnerProjectLineage::ManagedWorktreeSource { .. })
    ) && project.registration_source.as_deref() == Some("auto_registered")
        && project.registration_incarnation.is_some()
        && project.root_fingerprint.is_some()
        && project.revision.as_deref() == Some(expected_revision)
        && project.git_dirty == Some(false)
        && project.git_head.is_some()
}

/// Acquire the existing Runner job-start fence and the stronger native
/// Session closeout fence in that order. A successful return does NOT authorize
/// unregister or Git deletion. Unlike ordinary Project unregister, the
/// native path requires at least one durably closed exact Project Session.
#[allow(dead_code)]
pub(crate) async fn begin_native_managed_closeout_fences(
    runtime: &ToolRuntime,
    auth: &AuthContext,
    target: &str,
    expected_revision: &str,
    recovery_operation_id: Option<&str>,
) -> Result<NativeManagedCloseoutFences, ServiceResponse> {
    if !admin_project_mutation_authorized(auth) {
        return Err(api_error(403, "admin_authority_required"));
    }
    validate_revision(expected_revision)?;
    let (client_id, project_id) = parse_runtime_project(target)?;
    let access = crate::runner_http::runner_access_from_auth(Some(auth));
    runtime
        .runner_registry
        .assert_runner_access(access.as_ref(), &client_id)
        .await
        .map_err(|_| api_error(403, "runner_access_denied"))?;
    let client = runtime
        .runner_registry
        .get_runner_semantic_view_for_auth(&client_id, access.as_ref())
        .await
        .ok_or_else(|| api_error(503, "agent_unavailable"))?;
    if !client.view.connected || client.view.status != "online" {
        return Err(api_error(503, "agent_unavailable"));
    }
    if !client.supports(RunnerFeature::ProjectLifecycle) {
        return Err(api_error(409, "unsupported_runner_version"));
    }
    if !client
        .view
        .project_inventory
        .as_ref()
        .is_some_and(|inventory| inventory.sync_state == "complete")
    {
        return Err(api_error(409, "runner_inventory_incomplete"));
    }
    let project = client
        .view
        .projects
        .iter()
        .find(|entry| entry.id == project_id)
        .ok_or_else(|| api_error(404, "project_not_found"))?;
    if !native_closeout_owner_identity_ready(project, expected_revision) {
        return Err(api_error(409, "native_closeout_identity_unverified"));
    }

    let active_jobs = runtime
        .runner_registry
        .begin_project_unregister(access.as_ref(), target)
        .await
        .map_err(|_| api_error(409, "runner_retirement_conflict"))?;
    let jobs_guard = ProjectUnregisterFence {
        registry: runtime.runner_registry.clone(),
        project: target.to_string(),
    };
    if active_jobs != 0 {
        return Err(api_error(409, "active_jobs_conflict"));
    }
    // A previously committed operation may reacquire its exact Session
    // recovery guard after a Server restart; all unrelated operations remain
    // blocked. Never clear the durable reservation as a recovery shortcut.
    let sessions_guard = match (
        recovery_operation_id,
        runtime.sessions.durable_managed_worktree_closeout(target),
    ) {
        (Some(operation_id), Some(_)) => runtime
            .sessions
            .begin_managed_worktree_recovery_fence(target, operation_id),
        (None, Some(_)) => Err("durable_closeout_recovery_identity_required".to_string()),
        (_, None) => runtime
            .sessions
            .begin_managed_worktree_cleanup_fence(target),
    }
    .map_err(|_| api_error(409, "native_sessions_not_durably_closed"))?;
    // Ensure the SessionStore's durable closure evidence is committed before
    // any future caller can even consider Runner-side physical removal.
    runtime
        .sessions
        .flush()
        .await
        .map_err(|_| api_error(503, "native_closeout_session_persistence_uncertain"))?;
    Ok(NativeManagedCloseoutFences {
        _jobs: jobs_guard,
        _sessions: sessions_guard,
    })
}

/// Internal-only execution input produced by the trusted Native Owner
/// after independent source/remote recovery verification. Not an HTTP body:
/// user-provided origin URLs or branch names must never become delete authority.
#[allow(dead_code)]
struct VerifiedNativeCloseoutIntent {
    project: String,
    expected_revision: String,
    operation_id: String,
    verified_origin_url: String,
    verified_remote_ref: String,
}

#[derive(Clone)]
pub(crate) struct AdminProjectLifecycleService {
    runtime: Arc<ToolRuntime>,
    db: Arc<Database>,
}

impl AdminProjectLifecycleService {
    pub(crate) fn new(runtime: Arc<ToolRuntime>, db: Arc<Database>) -> Self {
        Self { runtime, db }
    }

    /// Protected Owner execution path. This is deliberately not routed from
    /// HTTP or a generic tool until independent release admission is complete.
    /// The old Runner advertises no NativeCloseout capability, so no deletion
    /// can be dispatched to production. Never release a durable Session lease
    /// on a timeout, transport error, or an untrusted/unmatched result.
    #[allow(dead_code)]
    async fn execute_native_closeout_bound(
        &self,
        auth: &AuthContext,
        intent: VerifiedNativeCloseoutIntent,
    ) -> Result<ServiceResponse, ServiceResponse> {
        if !admin_project_mutation_authorized(auth) {
            return Err(api_error(403, "admin_authority_required"));
        }
        validate_revision(&intent.expected_revision)?;
        let (client_id, project_id) = parse_runtime_project(&intent.project)?;
        let access = crate::runner_http::runner_access_from_auth(Some(auth));
        self.runtime
            .runner_registry
            .assert_runner_access(access.as_ref(), &client_id)
            .await
            .map_err(|_| api_error(403, "runner_access_denied"))?;
        let client = self
            .runtime
            .runner_registry
            .get_runner_semantic_view_for_auth(&client_id, access.as_ref())
            .await
            .ok_or_else(|| api_error(503, "agent_unavailable"))?;
        if !client.view.connected
            || client.view.status != "online"
            || !client.supports(RunnerFeature::NativeManagedCloseout)
            || !client
                .view
                .project_inventory
                .as_ref()
                .is_some_and(|inventory| inventory.sync_state == "complete")
        {
            return Err(api_error(409, "native_closeout_runner_not_admitted"));
        }
        let child = client
            .view
            .projects
            .iter()
            .find(|entry| entry.id == project_id)
            .ok_or_else(|| api_error(404, "project_not_found"))?;
        let source_id = match child.lineage.as_ref() {
            Some(crate::runner_protocol::RunnerProjectLineage::ManagedWorktreeSource {
                source_project_id,
                ..
            }) => source_project_id,
            None => return Err(api_error(409, "native_closeout_source_unverified")),
        };
        let source = client
            .view
            .projects
            .iter()
            .find(|entry| entry.id == *source_id)
            .ok_or_else(|| api_error(409, "native_closeout_source_unverified"))?;
        let payload = native_closeout_bound_runner_payload(
            child,
            source,
            &intent.expected_revision,
            &intent.operation_id,
            &intent.verified_origin_url,
            &intent.verified_remote_ref,
        )
        .map_err(|_| api_error(409, "native_closeout_binding_unverified"))?;
        let incarnation = child
            .registration_incarnation
            .as_deref()
            .ok_or_else(|| api_error(409, "native_closeout_identity_unverified"))?
            .to_string();
        let instance_id = client.view.runner_instance_id.clone();
        let guards = begin_native_managed_closeout_fences(
            self.runtime.as_ref(),
            auth,
            &intent.project,
            &intent.expected_revision,
            Some(&intent.operation_id),
        )
        .await?;
        let payload_json =
            serde_json::to_string(&payload).map_err(|_| api_error(500, "operation_failed"))?;
        guards.persist_owner_intent(&intent.operation_id, &payload_json)?;
        let (request_id, receiver) = self
            .runtime
            .runner_registry
            .enqueue_native_closeout_for_instance(
                client_id.clone(),
                payload_json,
                "server_native_closeout_owner".to_string(),
                &instance_id,
            )
            .await
            .map_err(|_| api_error(503, "native_closeout_dispatch_indeterminate"))?;
        let response = match tokio::time::timeout(Duration::from_secs(WAIT_SECS), receiver).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => {
                self.runtime
                    .runner_registry
                    .cancel_request(&request_id)
                    .await;
                return Err(api_error(503, "native_closeout_execution_indeterminate"));
            }
        };
        if response.request_id != request_id
            || response.client_id != client_id
            || response.error.is_some()
        {
            return Err(api_error(503, "native_closeout_execution_indeterminate"));
        }
        let output: Value = serde_json::from_str(response.stdout.as_deref().unwrap_or(""))
            .map_err(|_| api_error(503, "native_closeout_receipt_unverified"))?;
        if !native_closeout_terminal_receipt_matches(
            response.exit_code,
            &output,
            &project_id,
            &intent.operation_id,
            &intent.expected_revision,
            &incarnation,
        ) {
            return Err(api_error(503, "native_closeout_receipt_unverified"));
        }
        // The exact Runner incarnation must still own the Server projection.
        // Keep the durable Session block on any CAS or SQLite ambiguity.
        self.runtime
            .runner_registry
            .reconcile_native_closeout_project_for_instance(
                &client_id,
                &instance_id,
                &project_id,
                &incarnation,
            )
            .await
            .map_err(|_| api_error(503, "native_closeout_projection_indeterminate"))?;
        self.runtime
            .sessions
            .reconcile_durable_managed_closeout_terminal(&intent.project, &intent.operation_id)
            .map_err(|_| api_error(503, "native_closeout_release_indeterminate"))?;
        drop(guards);
        Ok(ServiceResponse {
            status: 200,
            body: json!({
                "outcome": "native_closeout_completed",
                "project": intent.project,
                "operation_id": intent.operation_id,
                "status": "completed",
            }),
        })
    }

    /// Server-crash recovery for an operation whose Runner has already
    /// committed unregistration. Rehydrate the immutable request from SQLite,
    /// not from a potentially missing live Project inventory. Only a trusted
    /// exact-Runner-instance read-only terminal receipt can release this lease.
    /// Kept internal until an independently admitted recovery trigger exists.
    #[allow(dead_code)]
    async fn reconcile_native_closeout_after_restart(
        &self,
        authority: NativeRecoveryAuthority<'_>,
        project: &str,
        operation_id: &str,
    ) -> Result<ServiceResponse, ServiceResponse> {
        // The internal principal can only reconcile an existing durable
        // operation after independently authenticated Runner terminal proof.
        // Never expose DurableOwner through a user-controlled endpoint.
        let access = match authority {
            NativeRecoveryAuthority::Admin(auth) => {
                if !admin_project_mutation_authorized(auth) {
                    return Err(api_error(403, "admin_authority_required"));
                }
                crate::runner_http::runner_access_from_auth(Some(auth))
            }
            NativeRecoveryAuthority::DurableOwner => Some(webcodex_runner_registry::RunnerAccess {
                global_visibility: true,
                owner_bypass: true,
                username: None,
                group: None,
            }),
        };
        let (client_id, project_id) = parse_runtime_project(project)?;
        if uuid::Uuid::parse_str(operation_id).is_err() {
            return Err(api_error(409, "native_closeout_recovery_identity_invalid"));
        }
        let binding_json = self
            .runtime
            .sessions
            .durable_managed_worktree_binding(project, operation_id)
            .map_err(|_| api_error(409, "native_closeout_binding_unavailable"))?
            .ok_or_else(|| api_error(409, "native_closeout_binding_missing"))?;
        let binding: Value = serde_json::from_str(&binding_json)
            .map_err(|_| api_error(409, "native_closeout_binding_unverified"))?;
        let field = |key| binding.get(key).and_then(Value::as_str);
        if field("operation_id") != Some(operation_id)
            || field("project_id") != Some(project_id.as_str())
            || field("phase") != Some("prepared")
            || field("expected_head").is_none()
            || field("expected_remote_ref").is_none()
            || field("source_root").is_none()
            || field("worktree_root").is_none()
            || field("expected_origin_url").is_none()
        {
            return Err(api_error(409, "native_closeout_binding_unverified"));
        }
        let revision = field("expected_revision")
            .ok_or_else(|| api_error(409, "native_closeout_binding_unverified"))?
            .to_string();
        validate_revision(&revision)?;
        let incarnation = field("expected_incarnation")
            .ok_or_else(|| api_error(409, "native_closeout_binding_unverified"))?
            .to_string();
        if uuid::Uuid::parse_str(&incarnation).is_err() {
            return Err(api_error(409, "native_closeout_binding_unverified"));
        }
        self.runtime
            .runner_registry
            .assert_runner_access(access.as_ref(), &client_id)
            .await
            .map_err(|_| api_error(403, "runner_access_denied"))?;
        let runner = self
            .runtime
            .runner_registry
            .get_runner_semantic_view_for_auth(&client_id, access.as_ref())
            .await
            .ok_or_else(|| api_error(503, "agent_unavailable"))?;
        if !runner.view.connected
            || runner.view.status != "online"
            || !runner.supports(RunnerFeature::NativeManagedCloseout)
            || !runner
                .view
                .project_inventory
                .as_ref()
                .is_some_and(|inventory| inventory.sync_state == "complete")
        {
            return Err(api_error(503, "native_closeout_runner_not_admitted"));
        }
        // A new Project with the same ID must never be removed by an old
        // receipt. A missing Project is allowed here ONLY because the Runner
        // read-only transaction proof will independently establish its removal.
        if runner
            .view
            .projects
            .iter()
            .find(|p| p.id == project_id)
            .is_some_and(|p| p.registration_incarnation.as_deref() != Some(incarnation.as_str()))
        {
            return Err(api_error(409, "native_closeout_projection_cas_conflict"));
        }
        let instance_id = runner.view.runner_instance_id.clone();
        let active = self
            .runtime
            .runner_registry
            .begin_project_unregister(access.as_ref(), project)
            .await
            .map_err(|_| api_error(409, "runner_retirement_conflict"))?;
        let jobs_guard = ProjectUnregisterFence {
            registry: self.runtime.runner_registry.clone(),
            project: project.to_string(),
        };
        if active != 0 {
            return Err(api_error(409, "active_jobs_conflict"));
        }
        let session_guard = self
            .runtime
            .sessions
            .begin_managed_worktree_recovery_fence(project, operation_id)
            .map_err(|_| api_error(409, "native_closeout_recovery_conflict"))?;
        let (request_id, receiver) = self
            .runtime
            .runner_registry
            .enqueue_native_closeout_receipt_for_instance(
                client_id.clone(),
                binding_json,
                "server_native_closeout_recovery".to_string(),
                &instance_id,
            )
            .await
            .map_err(|_| api_error(503, "native_closeout_receipt_dispatch_indeterminate"))?;
        let response = match tokio::time::timeout(Duration::from_secs(WAIT_SECS), receiver).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => {
                self.runtime
                    .runner_registry
                    .cancel_request(&request_id)
                    .await;
                return Err(api_error(503, "native_closeout_receipt_indeterminate"));
            }
        };
        if response.request_id != request_id
            || response.client_id != client_id
            || response.error.is_some()
        {
            return Err(api_error(503, "native_closeout_receipt_indeterminate"));
        }
        let result: Value = serde_json::from_str(response.stdout.as_deref().unwrap_or(""))
            .map_err(|_| api_error(503, "native_closeout_receipt_unverified"))?;
        if !native_closeout_readonly_terminal_receipt_matches(
            response.exit_code,
            &result,
            &project_id,
            operation_id,
            &revision,
            &incarnation,
        ) {
            return Err(api_error(503, "native_closeout_receipt_unverified"));
        }
        self.runtime
            .runner_registry
            .reconcile_native_closeout_project_for_instance(
                &client_id,
                &instance_id,
                &project_id,
                &incarnation,
            )
            .await
            .map_err(|_| api_error(503, "native_closeout_projection_indeterminate"))?;
        self.runtime
            .sessions
            .reconcile_durable_managed_closeout_terminal(project, operation_id)
            .map_err(|_| api_error(503, "native_closeout_release_indeterminate"))?;
        drop(session_guard);
        drop(jobs_guard);
        Ok(ServiceResponse {
            status: 200,
            body: json!({
                "outcome": "native_closeout_reconciled",
                "project": project,
                "operation_id": operation_id,
                "status": "completed",
                "source": "runner_verified_terminal_journal",
            }),
        })
    }

    /// Unattended Server maintenance only: this method cannot create a
    /// closeout intent or dispatch deletion. The only release authority is
    /// the exact durable SQLite binding PLUS the Runner's read-only terminal
    /// verification, checked again at receipt and Registry CAS.
    pub(crate) async fn reconcile_sealed_native_closeout(
        &self,
        project: &str,
        operation_id: &str,
    ) -> Result<ServiceResponse, ServiceResponse> {
        self.reconcile_native_closeout_after_restart(
            NativeRecoveryAuthority::DurableOwner,
            project,
            operation_id,
        )
        .await
    }

    /// Make the existing Native Owner fences reachable through the protected
    /// admin control plane without granting any delete capability. The actual
    /// executor needs its own continuous guard lifetime, live Runner evidence,
    /// GitHub recoverability proof, and persistent transaction receipts.
    pub(crate) async fn native_closeout_admission(
        &self,
        auth: &AuthContext,
        request: NativeCloseoutAdmissionRequest,
    ) -> ServiceResponse {
        match begin_native_managed_closeout_fences(
            self.runtime.as_ref(),
            auth,
            &request.project,
            &request.expected_revision,
            None,
        )
        .await
        {
            Ok(guard) => {
                drop(guard);
                ServiceResponse {
                    status: 200,
                    body: json!({
                        "outcome": "native_closeout_admission_observed",
                        "project": request.project,
                        "expected_revision": request.expected_revision,
                        "status": "blocked",
                        "delete_authorized": false,
                        "admission_fence_released": true,
                        "execution_lease_held": false,
                        "remaining": [
                            "runner_process_and_job_terminal_receipt",
                            "remote_git_recoverability",
                            "one_transaction_cas_unregister_and_normal_remove",
                            "durable_post_removal_receipt",
                            "independent_release_admission"
                        ]
                    }),
                }
            }
            Err(error) => error,
        }
    }

    pub(crate) async fn register(
        &self,
        auth: &AuthContext,
        request: RegisterProjectRequest,
    ) -> ServiceResponse {
        let target = format!("agent:{}:{}", request.client_id, request.project_id);
        self.idempotent(
            auth,
            "register",
            &target,
            &request,
            &request.idempotency_key,
            || async {
                validate_common(
                    &request.client_id,
                    &request.project_id,
                    &request.name,
                    request.description.as_deref(),
                    &request.path,
                )?;
                require_online_client(&self.runtime, auth, &request.client_id).await?;
                let result = self
                    .runtime
                    .register_project(
                        request.client_id.clone(),
                        request.project_id.clone(),
                        request.name.clone(),
                        request.path.clone(),
                        request.description.clone(),
                        request.allow_patch,
                        false,
                        Some(auth),
                    )
                    .await;
                map_create_result("register", "registered", &target, result)
            },
        )
        .await
    }

    pub(crate) async fn create(
        &self,
        auth: &AuthContext,
        request: CreateProjectRequest,
    ) -> ServiceResponse {
        let target = format!("agent:{}:{}", request.client_id, request.project_id);
        self.idempotent(
            auth,
            "create",
            &target,
            &request,
            &request.idempotency_key,
            || async {
                validate_common(
                    &request.client_id,
                    &request.project_id,
                    &request.name,
                    request.description.as_deref(),
                    &request.path,
                )?;
                require_online_client(&self.runtime, auth, &request.client_id).await?;
                if let Some(template) = request.template.as_deref() {
                    if template.len() > 32 {
                        return Err(api_error(400, "invalid_request"));
                    }
                }
                let result = self
                    .runtime
                    .create_project(
                        request.client_id.clone(),
                        request.project_id.clone(),
                        request.name.clone(),
                        request.path.clone(),
                        request.description.clone(),
                        request.allow_patch,
                        request.template.clone(),
                        request.git_init,
                        request.adopt_existing_empty,
                        false,
                        Some(auth),
                    )
                    .await;
                map_create_result("create", "created", &target, result)
            },
        )
        .await
    }

    /// Admin-only, revision-guarded single-field Project update.
    pub(crate) async fn update_allow_patch(
        &self,
        auth: &AuthContext,
        request: UpdateProjectAllowPatchRequest,
    ) -> ServiceResponse {
        if !admin_project_mutation_authorized(auth) {
            return api_error(403, "forbidden");
        }
        let target = request.project.clone();
        self.idempotent(
            auth,
            "update_allow_patch",
            &target,
            &request,
            &request.idempotency_key,
            || async {
                if !request.confirm {
                    return Err(api_error(400, "invalid_request"));
                }
                Self::mutate_authorized_core(
                    self.runtime.as_ref(),
                    Some(auth),
                    "update_allow_patch",
                    &request.project,
                    &request.expected_revision,
                    "admin_project_settings",
                    false,
                    Some(request.allow_patch),
                )
                .await
            },
        )
        .await
    }

    pub(crate) async fn mutate(
        &self,
        auth: &AuthContext,
        action: &'static str,
        request: ProjectMutationRequest,
    ) -> ServiceResponse {
        let target = request.project.clone();
        self.idempotent(
            auth,
            action,
            &target,
            &request,
            &request.idempotency_key,
            || async {
                if !request.confirm {
                    return Err(api_error(400, "invalid_request"));
                }
                Self::mutate_authorized_core(
                    self.runtime.as_ref(),
                    Some(auth),
                    action,
                    &request.project,
                    &request.expected_revision,
                    "admin_project_lifecycle",
                    false,
                    None,
                )
                .await
            },
        )
        .await
    }

    async fn mutate_authorized_core(
        runtime: &ToolRuntime,
        auth: Option<&AuthContext>,
        action: &'static str,
        target: &str,
        expected_revision: &str,
        requester: &'static str,
        require_owner_access: bool,
        allow_patch: Option<bool>,
    ) -> Result<ServiceResponse, ServiceResponse> {
        validate_revision(expected_revision)?;
        let (client_id, project_id) = parse_runtime_project(target)?;
        let access = crate::runner_http::runner_access_from_auth(auth);
        // Authenticated ordinary-runtime callers keep the explicit Runner owner/access
        // fence used by the HTTP unregister path. `auth=None` is the trusted in-process
        // / open-runtime path: visibility is intentionally unfiltered there, matching
        // other ToolRuntime operations, so requiring a user owner would incorrectly
        // reject otherwise reachable unowned Runners.
        if require_owner_access && auth.is_some() {
            runtime
                .runner_registry
                .assert_runner_access(access.as_ref(), &client_id)
                .await
                .map_err(|_| api_error(503, "agent_unavailable"))?;
        }
        let client = runtime
            .runner_registry
            .get_runner_semantic_view_for_auth(&client_id, access.as_ref())
            .await
            .ok_or_else(|| api_error(503, "agent_unavailable"))?;
        if !client.view.connected || client.view.status != "online" {
            return Err(api_error(503, "agent_unavailable"));
        }
        if !client.supports(RunnerFeature::ProjectLifecycle) {
            return Err(api_error(409, "unsupported_runner_version"));
        }
        if action == "update_allow_patch" && !client.supports(RunnerFeature::ProjectSettingsUpdate)
        {
            return Err(api_error(409, "unsupported_runner_version"));
        }
        let project = client.view.projects.iter().find(|p| p.id == project_id);
        if action != "unregister" && project.is_none() {
            return Err(api_error(404, "project_not_found"));
        }
        if action == "update_allow_patch" {
            let Some(project) = project else {
                return Err(api_error(404, "project_not_found"));
            };
            if project.revision.as_deref() != Some(expected_revision) {
                return Err(api_error(409, "revision_conflict"));
            }
            // Never change permissions on a Project whose current root
            // identity was not proven by the Runner inventory.
            if project.root_fingerprint.is_none() {
                return Err(api_error(409, "project_root_unverified"));
            }
        }
        let (active_jobs, _unregister_fence, _session_retirement_guard) = if action == "unregister"
        {
            let active = runtime
                .runner_registry
                .begin_project_unregister(access.as_ref(), target)
                .await
                .map_err(|_| api_error(500, "operation_failed"))?;
            // Own the Runner fence immediately, including early error exits.
            let project_unregister_fence = (active == 0).then(|| ProjectUnregisterFence {
                registry: runtime.runner_registry.clone(),
                project: target.to_string(),
            });
            if active > 0 {
                return Err(ServiceResponse {
                    status: 409,
                    body: json!({"error":{"code":"active_jobs_conflict"},"active_jobs":active}),
                });
            }
            let session_guard = runtime
                .sessions
                .begin_project_unregister_fence(target)
                .map_err(|_| api_error(409, "retained_sessions_or_retirement_conflict"))?;
            (active, project_unregister_fence, Some(session_guard))
        } else {
            (
                runtime
                    .runner_registry
                    .count_active_jobs_for_project(access.as_ref(), target)
                    .await,
                None,
                None,
            )
        };
        let mut payload_value = json!({
            "project_id": project_id,
            "expected_revision": expected_revision,
        });
        if action == "update_allow_patch" {
            payload_value["allow_patch"] =
                json!(allow_patch.ok_or_else(|| api_error(400, "invalid_request"))?);
            payload_value["expected_root_fingerprint"] = json!(project
                .and_then(|project| project.root_fingerprint.as_deref())
                .ok_or_else(|| api_error(409, "project_root_unverified"))?);
        }
        let payload = serde_json::to_string(&payload_value)
            .map_err(|_| api_error(500, "operation_failed"))?;
        let kind = if action == "update_allow_patch" {
            "project_update_allow_patch".to_string()
        } else {
            format!("project_lifecycle_{action}")
        };
        let (request_id, receiver) = runtime
            .runner_registry
            .enqueue_project_op(client_id.clone(), &kind, payload, requester.to_string())
            .await
            .map_err(|_| api_error(503, "agent_unavailable"))?;
        let response = match tokio::time::timeout(Duration::from_secs(WAIT_SECS), receiver).await {
            Ok(Ok(value)) => value,
            Ok(Err(_)) | Err(_) => {
                runtime.runner_registry.cancel_request(&request_id).await;
                return Err(api_error(503, "operation_indeterminate"));
            }
        };
        if let Some(error) = response.error.as_deref() {
            return Err(map_agent_error(error));
        }
        let output: Value = serde_json::from_str(response.stdout.as_deref().unwrap_or(""))
            .map_err(|_| api_error(502, "operation_failed"))?;
        if let Some(code) = output.get("error_code").and_then(Value::as_str) {
            return Err(map_agent_error(code));
        }
        if response.exit_code != Some(0) {
            return Err(api_error(500, "operation_failed"));
        }
        if action == "update_allow_patch"
            && output.get("allow_patch").and_then(Value::as_bool) != allow_patch
        {
            return Err(api_error(502, "operation_failed"));
        }
        let outcome = output
            .get("outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| api_error(502, "operation_failed"))?;
        let changed = output
            .get("changed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let revision = output.get("revision").cloned().unwrap_or(Value::Null);
        if action == "update_allow_patch" {
            let expected_outcome = if changed {
                "allow_patch_updated"
            } else {
                "already_updated"
            };
            let next_revision = revision
                .as_str()
                .ok_or_else(|| api_error(502, "operation_failed"))?;
            validate_revision(next_revision).map_err(|_| api_error(502, "operation_failed"))?;
            if outcome != expected_outcome
                || output.get("changed").and_then(Value::as_bool) != Some(changed)
                || (next_revision != expected_revision) != changed
                || output.get("previous_revision").and_then(Value::as_str)
                    != Some(expected_revision)
                || output.get("agent_project_id").and_then(Value::as_str)
                    != Some(project_id.as_str())
                || output
                    .get("registration_incarnation")
                    .and_then(Value::as_str)
                    != project.and_then(|p| p.registration_incarnation.as_deref())
            {
                return Err(api_error(502, "operation_failed"));
            }
        }
        if action == "unregister" && matches!(outcome, "unregistered" | "already_unregistered") {
            if runtime
                .runner_registry
                .remove_runner_project_for_instance(
                    &client_id,
                    &client.view.runner_instance_id,
                    &project_id,
                )
                .await
                .is_err()
            {
                return Err(project_projection_reconcile_response(
                    target,
                    outcome,
                    changed,
                    revision.clone(),
                    "server_project_projection_failed",
                ));
            }
        } else if action == "update_allow_patch" {
            let Some(new_revision) = revision.as_str() else {
                return Err(project_projection_reconcile_response(
                    target,
                    outcome,
                    changed,
                    revision.clone(),
                    "authoritative_revision_missing",
                ));
            };
            let Some(root_fingerprint) = output.get("root_fingerprint").and_then(Value::as_str)
            else {
                return Err(project_projection_reconcile_response(
                    target,
                    outcome,
                    changed,
                    revision.clone(),
                    "authoritative_root_missing",
                ));
            };
            if runtime
                .runner_registry
                .update_runner_project_allow_patch_for_instance(
                    &client_id,
                    &client.view.runner_instance_id,
                    &project_id,
                    expected_revision,
                    new_revision,
                    root_fingerprint,
                    allow_patch.ok_or_else(|| api_error(400, "invalid_request"))?,
                )
                .await
                .is_err()
            {
                return Err(project_projection_reconcile_response(
                    target,
                    outcome,
                    changed,
                    revision.clone(),
                    "server_project_projection_failed",
                ));
            }
        } else {
            let Some(summary) = lifecycle_summary(&output, &project_id) else {
                return Err(project_projection_reconcile_response(
                    target,
                    outcome,
                    changed,
                    revision.clone(),
                    "authoritative_project_summary_missing",
                ));
            };
            if runtime
                .runner_registry
                .upsert_runner_project_for_instance(
                    &client_id,
                    &client.view.runner_instance_id,
                    summary,
                )
                .await
                .is_err()
            {
                return Err(project_projection_reconcile_response(
                    target,
                    outcome,
                    changed,
                    revision.clone(),
                    "server_project_projection_failed",
                ));
            }
        }
        let warnings = if active_jobs > 0 {
            json!([{"code":"active_jobs_present","active_jobs":active_jobs}])
        } else {
            json!([])
        };
        let mut receipt = json!({
            "operation": action,
            "project": target,
            "outcome": outcome,
            "changed": changed,
            "revision": revision,
            "active_jobs": active_jobs,
            "warnings": warnings
        });
        if action == "update_allow_patch" {
            // Durable, non-sensitive before/after receipt, persisted under the
            // existing idempotency key. Do not change other lifecycle receipts.
            receipt["previous_revision"] = json!(expected_revision);
            receipt["allow_patch"] = json!(allow_patch);
        }
        Ok(ServiceResponse {
            status: 200,
            body: receipt,
        })
    }

    async fn idempotent<T, F, Fut>(
        &self,
        auth: &AuthContext,
        action: &str,
        target: &str,
        request: &T,
        key: &str,
        operation: F,
    ) -> ServiceResponse
    where
        T: Serialize,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<ServiceResponse, ServiceResponse>>,
    {
        if !valid_idempotency_key(key) {
            return api_error(400, "invalid_request");
        }
        let subject = subject_id(auth);
        let key_hash = digest(key.as_bytes());
        let request_hash = digest_json_or_empty(request);
        let lock_scope = format!("{subject}\u{1f}{action}\u{1f}{target}\u{1f}{key_hash}");
        let operation_lock = {
            let mut locks = idempotency_locks().lock().await;
            if locks.len() > 2_048 {
                locks.retain(|_, lock| Arc::strong_count(lock) > 1);
            }
            locks
                .entry(lock_scope.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _operation_guard = operation_lock.lock().await;
        match self
            .db
            .get_admin_project_idempotency(&subject, action, target, &key_hash)
        {
            Ok(Some(stored)) => {
                let stored_response = ServiceResponse {
                    status: stored.http_status as u16,
                    body: serde_json::from_str(&stored.response_json)
                        .unwrap_or_else(|_| json!({"error":{"code":"operation_failed"}})),
                };
                match stored_idempotency_action(
                    &stored.request_hash,
                    &request_hash,
                    &stored_response,
                ) {
                    StoredIdempotencyAction::Conflict => {
                        return api_error(409, "idempotency_conflict");
                    }
                    StoredIdempotencyAction::DeleteAndRetry => {
                        if self
                            .db
                            .delete_admin_project_idempotency(&subject, action, target, &key_hash)
                            .is_err()
                        {
                            return api_error(500, "operation_failed");
                        }
                    }
                    StoredIdempotencyAction::Replay => return stored_response,
                }
            }
            Err(_) => return api_error(500, "operation_failed"),
            Ok(None) => {}
        }
        let response = match operation().await {
            Ok(v) | Err(v) => v,
        };
        let correlation_id = uuid::Uuid::new_v4().to_string();
        let outcome = response
            .body
            .get("outcome")
            .and_then(Value::as_str)
            .unwrap_or("failed");
        let changed = response
            .body
            .get("changed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let reason_code = response.body.pointer("/error/code").and_then(Value::as_str);
        let client_id = parse_runtime_project(target).ok().map(|(client, _)| client);
        let subject_type = if auth.is_bootstrap() {
            "bootstrap"
        } else {
            "admin_pat"
        };
        let _ = self
            .db
            .insert_admin_project_lifecycle_audit(&AdminProjectAudit {
                correlation_id: &correlation_id,
                subject_type,
                subject_id: &subject,
                operation: action,
                project: target,
                client_id: client_id.as_deref(),
                outcome,
                changed,
                reason_code,
                idempotency_digest: &key_hash,
            });
        if !is_persistable_terminal(&response) {
            return response;
        }
        let response_json = serde_json::to_string(&response.body)
            .unwrap_or_else(|_| "{\"error\":{\"code\":\"operation_failed\"}}".to_string());
        match self.db.insert_admin_project_idempotency(
            &subject,
            action,
            target,
            &key_hash,
            &request_hash,
            response.status as i64,
            &response_json,
        ) {
            Ok(true) => response,
            Ok(false) => match self
                .db
                .get_admin_project_idempotency(&subject, action, target, &key_hash)
            {
                Ok(Some(stored)) if stored.request_hash == request_hash => ServiceResponse {
                    status: stored.http_status as u16,
                    body: serde_json::from_str(&stored.response_json).unwrap_or(response.body),
                },
                _ => api_error(409, "idempotency_conflict"),
            },
            Err(_) => api_error(503, "operation_indeterminate"),
        }
    }
}

/// Shared ordinary-runtime unregister path used by the canonical runtime tool.
/// The lifecycle core owns exact
/// revision validation, owner filtering, active-Job fencing, Runner capability
/// checks, uncertain delivery semantics, and Server inventory removal.
pub(crate) async fn unregister_project_runtime(
    runtime: &ToolRuntime,
    auth: Option<&AuthContext>,
    project: &str,
    expected_revision: &str,
) -> ServiceResponse {
    match AdminProjectLifecycleService::mutate_authorized_core(
        runtime,
        auth,
        "unregister",
        project,
        expected_revision,
        "project_unregister",
        true,
        None,
    )
    .await
    {
        Ok(response) | Err(response) => response,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum StoredIdempotencyAction {
    Conflict,
    DeleteAndRetry,
    Replay,
}

fn stored_idempotency_action(
    stored_hash: &str,
    request_hash: &str,
    response: &ServiceResponse,
) -> StoredIdempotencyAction {
    if stored_hash != request_hash {
        StoredIdempotencyAction::Conflict
    } else if is_persistable_terminal(response) {
        StoredIdempotencyAction::Replay
    } else {
        StoredIdempotencyAction::DeleteAndRetry
    }
}

fn is_persistable_terminal(response: &ServiceResponse) -> bool {
    if !(200..300).contains(&response.status) {
        return false;
    }
    matches!(
        response.body.get("outcome").and_then(Value::as_str),
        Some(
            "registered"
                | "created"
                | "enabled"
                | "disabled"
                | "unregistered"
                | "already_enabled"
                | "already_disabled"
                | "already_unregistered"
                | "allow_patch_updated"
                | "already_updated"
        )
    )
}

async fn require_online_client(
    runtime: &ToolRuntime,
    auth: &AuthContext,
    client_id: &str,
) -> Result<(), ServiceResponse> {
    let access = crate::runner_http::runner_access_from_auth(Some(auth));
    let client = runtime
        .runner_registry
        .get_runner_view_for_auth(client_id, access.as_ref())
        .await
        .ok_or_else(|| api_error(503, "agent_unavailable"))?;
    if !client.connected || client.status != "online" {
        return Err(api_error(503, "agent_unavailable"));
    }
    Ok(())
}

fn map_create_result(
    operation: &str,
    outcome: &str,
    project: &str,
    result: ToolResult,
) -> Result<ServiceResponse, ServiceResponse> {
    if !result.success {
        let code = result
            .output
            .get("error_code")
            .and_then(Value::as_str)
            .or(result.error.as_deref())
            .unwrap_or("operation_failed");
        return Err(map_agent_error(code));
    }
    let actual_outcome = result
        .output
        .get("outcome")
        .and_then(Value::as_str)
        .ok_or_else(|| api_error(502, "operation_failed"))?;
    if actual_outcome != outcome {
        return Err(api_error(502, "operation_failed"));
    }
    let changed = result
        .output
        .get("changed")
        .and_then(Value::as_bool)
        .ok_or_else(|| api_error(502, "operation_failed"))?;
    let recovered = result
        .output
        .get("recovered")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let revision = result
        .output
        .get("revision")
        .cloned()
        .filter(|v| v.as_str().is_some())
        .ok_or_else(|| api_error(502, "operation_failed"))?;
    Ok(ServiceResponse {
        status: 200,
        body: json!({
            "operation": operation, "project": project, "outcome": actual_outcome,
            "changed": changed, "recovered": recovered, "revision": revision, "warnings": []
        }),
    })
}

fn lifecycle_summary(output: &Value, id: &str) -> Option<RunnerProjectSummary> {
    let incarnation = output.get("registration_incarnation")?.as_str()?;
    uuid::Uuid::parse_str(incarnation).ok()?;
    Some(RunnerProjectSummary {
        registration_incarnation: Some(incarnation.to_string()),
        id: id.to_string(),
        name: output
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| Some(id.to_string())),
        path: output.get("path")?.as_str()?.to_string(),
        allow_patch: output
            .get("allow_patch")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        kind: output
            .get("kind")
            .and_then(Value::as_str)
            .map(str::to_string),
        registration_source: output
            .get("registration_source")
            .and_then(Value::as_str)
            .map(str::to_string),
        description: output
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        hooks: Vec::new(),
        disabled: output
            .get("disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        revision: output
            .get("revision")
            .and_then(Value::as_str)
            .map(str::to_string),
        root_fingerprint: output
            .get("root_fingerprint")
            .and_then(Value::as_str)
            .map(str::to_string),
        lineage: match output.get("lineage") {
            None | Some(Value::Null) => None,
            Some(value) => Some(serde_json::from_value(value.clone()).ok()?),
        },
        git_branch: None,
        git_head: None,
        git_dirty: None,
        updated_at: chrono::Utc::now().timestamp(),
        shell_profile: None,
    })
}

fn validate_common(
    client: &str,
    project: &str,
    name: &str,
    description: Option<&str>,
    path: &str,
) -> Result<(), ServiceResponse> {
    if client.is_empty()
        || client.len() > 128
        || !client
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(api_error(400, "invalid_request"));
    }
    if project.is_empty()
        || project.len() > 64
        || !project
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err(api_error(400, "invalid_request"));
    }
    if name.trim().is_empty()
        || name.len() > 120
        || path.len() > 4096
        || validate_project_op_path(path).is_err()
        || description.is_some_and(|v| v.len() > 500)
    {
        return Err(api_error(400, "invalid_request"));
    }
    Ok(())
}

pub(crate) fn validate_revision(value: &str) -> Result<(), ServiceResponse> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(api_error(400, "invalid_request"));
    }
    Ok(())
}

pub(crate) fn parse_runtime_project(value: &str) -> Result<(String, String), ServiceResponse> {
    let rest = value
        .strip_prefix("agent:")
        .ok_or_else(|| api_error(400, "invalid_request"))?;
    let (client, project) = rest
        .split_once(':')
        .ok_or_else(|| api_error(400, "invalid_request"))?;
    if client.is_empty() || project.is_empty() || project.contains(':') {
        return Err(api_error(400, "invalid_request"));
    }
    Ok((client.to_string(), project.to_string()))
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= IDEMPOTENCY_KEY_MAX
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}
fn subject_id(auth: &AuthContext) -> String {
    if auth.is_bootstrap() {
        "bootstrap".to_string()
    } else {
        auth.api_key_id
            .clone()
            .or_else(|| auth.user_id.clone())
            .unwrap_or_else(|| "admin".to_string())
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn digest_json_or_empty<T: Serialize + ?Sized>(value: &T) -> String {
    let mut hasher = Sha256::new();
    if update_sha256_with_json(&mut hasher, value).is_err() {
        // Match the historical `to_vec(...).unwrap_or_default()` fallback.
        hasher = Sha256::new();
    }
    format!("sha256:{:x}", hasher.finalize())
}
fn project_projection_reconcile_response(
    project: &str,
    outcome: &str,
    state_changed: bool,
    revision: Value,
    reason_code: &str,
) -> ServiceResponse {
    ServiceResponse {
        status: 503,
        body: json!({
            "error": {"code": "project_projection_reconcile_required"},
            "failure_kind": "reconcile_required",
            "reason_code": reason_code,
            "state_changed": state_changed,
            "project": project,
            "authoritative_outcome": outcome,
            "revision": revision,
            "reconcile": {
                "action": "observe_exact_project_revision_before_retry",
                "project": project,
            }
        }),
    }
}

fn api_error(status: u16, code: &str) -> ServiceResponse {
    ServiceResponse {
        status,
        body: json!({"error":{"code":code}}),
    }
}
fn map_agent_error(error: &str) -> ServiceResponse {
    match error {
        "revision_conflict" => api_error(409, "revision_conflict"),
        "root_identity_conflict" => api_error(409, "root_identity_conflict"),
        "project_not_found" => api_error(404, "project_not_found"),
        "path_outside_allowed_roots" => api_error(400, "path_outside_allowed_roots"),
        "path_not_empty" => api_error(409, "path_not_empty"),
        "path_exists" => api_error(409, "path_exists"),
        "project_already_exists" => api_error(409, "project_already_exists"),
        "unsupported_runner_version" => api_error(409, "unsupported_runner_version"),
        "agent_unavailable" => api_error(503, "agent_unavailable"),
        "operation_indeterminate" => api_error(503, "operation_indeterminate"),
        "project_projection_reconcile_required" => {
            api_error(503, "project_projection_reconcile_required")
        }
        _ => api_error(500, "operation_failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthKind;
    use webcodex_runner_registry::{JobStartContext, JobStartRequest};

    use crate::runner_protocol::{RunnerCapabilities, RunnerRegisterRequest};

    #[test]
    fn native_managed_closeout_requires_exact_registered_clean_identity() {
        let mut project: RunnerProjectSummary = serde_json::from_value(json!({
            "id":"new-child", "path":"/disposable-child", "updated_at":1,
            "registration_source":"auto_registered",
            "registration_incarnation":"11111111-1111-4111-8111-111111111111",
            "root_fingerprint":"wc_projroot_test",
            "revision": format!("sha256:{}", "a".repeat(64)),
            "git_dirty":false,
            "git_head":"0123456789012345678901234567890123456789",
            "lineage":{
                "kind":"managed_worktree_source",
                "source_project_id":"original",
                "source_root_fingerprint":"wc_projroot_source",
                "base_sha":"0123456789012345678901234567890123456789"
            }
        }))
        .unwrap();
        let expected = format!("sha256:{}", "a".repeat(64));
        assert!(native_closeout_owner_identity_ready(&project, &expected));
        assert!(!native_closeout_owner_identity_ready(
            &project,
            &format!("sha256:{}", "b".repeat(64))
        ));
        project.git_dirty = None;
        assert!(!native_closeout_owner_identity_ready(&project, &expected));
        project.git_dirty = Some(false);
        project.lineage = None;
        assert!(!native_closeout_owner_identity_ready(&project, &expected));
        project.registration_source = Some("explicit".into());
        assert!(!native_closeout_owner_identity_ready(&project, &expected));
    }

    #[test]
    fn project_settings_permission_rejects_ordinary_and_machine_credentials() {
        let mut principal = user_auth("ordinary");
        assert!(!admin_project_mutation_authorized(&principal));
        principal.scopes = vec![crate::auth::scopes::SCOPE_ADMIN.to_string()];
        assert!(admin_project_mutation_authorized(&principal));
        for kind in [
            AuthKind::AgentToken,
            AuthKind::ProjectCredential,
            AuthKind::SharedKey,
            AuthKind::OpenAnonymous,
            AuthKind::AccountCredential,
        ] {
            principal.kind = kind;
            assert!(!admin_project_mutation_authorized(&principal));
        }
        principal.kind = AuthKind::Bootstrap;
        principal.is_bootstrap = true;
        assert!(admin_project_mutation_authorized(&principal));
    }

    #[test]
    fn older_lifecycle_runner_cannot_advertise_project_settings_updates() {
        let caps = RunnerCapabilities {
            project_lifecycle: true,
            ..RunnerCapabilities::default()
        };
        assert!(!caps.project_settings_update);
    }

    #[test]
    fn update_allow_patch_contract_rejects_extra_fields_and_invalid_types() {
        let request = json!({
            "project": "agent:runner:demo",
            "expected_revision": format!("sha256:{}", "a".repeat(64)),
            "allow_patch": false,
            "idempotency_key": "one-operation",
            "confirm": true
        });
        let parsed: UpdateProjectAllowPatchRequest =
            serde_json::from_value(request.clone()).unwrap();
        assert!(!parsed.allow_patch);
        assert!(parsed.confirm);
        validate_revision(&parsed.expected_revision).unwrap();
        assert_eq!(
            parse_runtime_project(&parsed.project).unwrap(),
            ("runner".into(), "demo".into())
        );
        let mut malformed = request.clone();
        malformed["allow_patch"] = json!("false");
        assert!(serde_json::from_value::<UpdateProjectAllowPatchRequest>(malformed).is_err());
        let mut unexpected = request.clone();
        unexpected["name"] = json!("must not be overwritten");
        assert!(serde_json::from_value::<UpdateProjectAllowPatchRequest>(unexpected).is_err());
        let mut missing_revision = request.clone();
        missing_revision
            .as_object_mut()
            .unwrap()
            .remove("expected_revision");
        assert!(
            serde_json::from_value::<UpdateProjectAllowPatchRequest>(missing_revision).is_err()
        );
        for outcome in ["allow_patch_updated", "already_updated"] {
            assert!(is_persistable_terminal(&ServiceResponse {
                status: 200,
                body: json!({"outcome":outcome})
            }));
        }
    }

    #[test]
    fn idempotency_json_digest_matches_buffered_hash() {
        let value = json!({
            "project": "agent:test:demo",
            "escaped": "line\n\"quoted\"\\slash",
            "unicode": "你好 🦀",
            "nested": [1, true, null, {"key": "value"}]
        });
        assert_eq!(
            digest_json_or_empty(&value),
            digest(&serde_json::to_vec(&value).unwrap())
        );
    }

    fn user_auth(username: &str) -> AuthContext {
        AuthContext {
            kind: AuthKind::ApiToken,
            user_id: Some(format!("user-{username}")),
            username: Some(username.to_string()),
            api_key_id: Some(format!("key-{username}")),
            role: Some("user".to_string()),
            scopes: vec![crate::auth::scopes::SCOPE_PROJECT_WRITE.to_string()],
            is_bootstrap: false,
            token_kind: Some("user".to_string()),
            allowed_client_id: None,
            shared_key_hash: None,
            project_grant_id: None,

            project_root_scopes: Vec::new(),
        }
    }

    fn active_job_request(client_id: &str, command: &str) -> JobStartRequest {
        JobStartRequest {
            timeout_secs: 60,
            ..JobStartRequest::shell(client_id, command)
        }
    }

    #[tokio::test]
    async fn project_unregister_rejects_cross_owner_before_active_job_fence() {
        let registry = Arc::new(RunnerRegistry::default());
        let revision = format!("sha256:{}", "a".repeat(64));
        let target = "agent:owned-runner:demo";
        registry
            .register(crate::test_support::current_runner_registration(
                RunnerRegisterRequest {
                    computer_session_availability: None,
                    computer_control_epoch: None,
                    client_id: "owned-runner".to_string(),
                    runner_instance_id: "instance-owned".to_string(),
                    runner_protocol_generation:
                        crate::runner_protocol::RUNNER_PROTOCOL_GENERATION_V2,
                    display_name: None,
                    owner: Some("alice".to_string()),
                    hostname: None,
                    host_context: None,
                    capabilities: RunnerCapabilities {
                        jobs: true,
                        async_jobs: true,
                        async_shell_jobs: true,
                        project_lifecycle: true,
                        ..Default::default()
                    },
                    policy: None,
                    process_started_at: None,
                    build: None,
                    job_concurrency_limit: None,
                    job_inventory: None,
                    coding_agent_providers: None,
                    coding_agent_inventory: None,
                },
            ))
            .await
            .unwrap();

        let alice = user_auth("alice");
        let bob = user_auth("bob");
        let alice_access = crate::test_support::runner_access(&alice);
        let bob_access = crate::test_support::runner_access(&bob);
        registry
            .start_job(
                JobStartRequest {
                    context: JobStartContext {
                        project_id: Some(target.to_string()),
                        ..Default::default()
                    },
                    ..active_job_request("owned-runner", "sleep 60")
                },
                "alice".to_string(),
                Some(&alice_access),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            registry
                .count_active_jobs_for_project(Some(&alice_access), target)
                .await,
            1
        );
        assert_eq!(
            registry.count_active_jobs_for_project(Some(&bob_access), target).await,
            0,
            "the regression requires the cross-owner principal to be unable to see the owner's active Job"
        );

        let runtime = Arc::new(ToolRuntime::new_for_tests_with_runner_registry(
            registry.clone(),
        ));
        let response = tokio::time::timeout(
            Duration::from_millis(250),
            unregister_project_runtime(runtime.as_ref(), Some(&bob), target, &revision),
        )
        .await
        .expect(
            "cross-owner unregister must fail before enqueueing or installing an unregister fence",
        );
        assert_eq!(response.status, 503);
        assert_eq!(response.body["error"]["code"], "agent_unavailable");

        registry
            .start_job(
                JobStartRequest {
                    context: JobStartContext {
                        project_id: Some(target.to_string()),
                        ..Default::default()
                    },
                    ..active_job_request("owned-runner", "echo still-allowed")
                },
                "alice".to_string(),
                Some(&alice_access),
                None,
            )
            .await
            .expect("rejected cross-owner unregister must not leave an unregister fence behind");
        assert_eq!(
            registry
                .begin_project_unregister(Some(&alice_access), target)
                .await
                .unwrap(),
            2,
            "the owner's active Jobs must remain authoritative for the unregister fence"
        );
    }

    #[test]
    fn lifecycle_projection_requires_authoritative_registration_identity() {
        let complete = json!({
            "path": "/original-root",
            "name": "demo",
            "disabled": false,
            "registration_incarnation": "0a03dd75-3c93-4e91-a4ba-130592d5bc7e"
        });
        assert_eq!(
            lifecycle_summary(&complete, "demo")
                .unwrap()
                .registration_incarnation
                .as_deref(),
            Some("0a03dd75-3c93-4e91-a4ba-130592d5bc7e")
        );

        let mut missing = complete.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("registration_incarnation");
        assert!(
            lifecycle_summary(&missing, "demo").is_none(),
            "an incomplete lifecycle receipt must not erase a known Registry incarnation"
        );
        let mut malformed = complete;
        malformed["registration_incarnation"] = json!("not-an-incarnation");
        assert!(
            lifecycle_summary(&malformed, "demo").is_none(),
            "invalid registration identity must fail closed before a Registry update"
        );
    }

    #[test]
    fn native_closeout_runner_payload_requires_exact_inventory_and_remote_binding() {
        let incarnation = "11111111-1111-4111-8111-111111111111";
        let operation_id = "22222222-2222-4222-8222-222222222222";
        let sha = "a".repeat(40);
        let child: RunnerProjectSummary = serde_json::from_value(json!({
            "id": "child-one", "path": "/tmp/managed-child", "updated_at": 1,
            "registration_source": "auto_registered",
            "registration_incarnation": incarnation,
            "root_fingerprint": "wc_projroot_child",
            "revision": "sha256:revision",
            "git_head": sha,
            "git_dirty": false,
            "lineage": {
                "kind": "managed_worktree_source",
                "source_project_id": "source-one",
                "source_root_fingerprint": "wc_projroot_source",
                "base_sha": sha
            }
        }))
        .unwrap();
        let source: RunnerProjectSummary = serde_json::from_value(json!({
            "id": "source-one", "path": "/tmp/source", "updated_at": 1,
            "root_fingerprint": "wc_projroot_source",
            "git_head": sha, "git_dirty": false
        }))
        .unwrap();
        let make =
            |c: &RunnerProjectSummary, s: &RunnerProjectSummary, remote: &str, branch: &str| {
                native_closeout_bound_runner_payload(
                    c,
                    s,
                    "sha256:revision",
                    operation_id,
                    remote,
                    branch,
                )
            };
        let valid = make(
            &child,
            &source,
            "https://github.com/example/repo.git",
            "refs/heads/main",
        )
        .unwrap();
        assert_eq!(valid["phase"], "prepared");
        assert_eq!(valid["expected_incarnation"], incarnation);
        assert_eq!(valid["source_root"], "/tmp/source");
        assert_eq!(valid["expected_head"], sha);
        assert!(make(&child, &source, "", "refs/heads/main").is_err());
        assert!(make(&child, &source, "https://example.invalid", "HEAD").is_err());
        assert!(make(&child, &source, "https://example.invalid", "refs/heads/").is_err());
        assert!(make(
            &child,
            &source,
            "https://example.invalid",
            "refs/heads/../main"
        )
        .is_err());
        let mut changed = child.clone();
        changed.git_head = Some("b".repeat(40));
        assert!(make(
            &changed,
            &source,
            "https://example.invalid",
            "refs/heads/main"
        )
        .is_err());
        let mut changed_source = source.clone();
        changed_source.root_fingerprint = Some("different".into());
        assert!(make(
            &child,
            &changed_source,
            "https://example.invalid",
            "refs/heads/main"
        )
        .is_err());
        let mut unregistered = child;
        unregistered.registration_source = None;
        assert!(make(
            &unregistered,
            &source,
            "https://example.invalid",
            "refs/heads/main"
        )
        .is_err());
    }

    #[test]
    fn native_closeout_readonly_receipt_rejects_mutation_and_stale_identity() {
        let receipt = json!({
            "operation": "native_managed_closeout_receipt",
            "outcome": "native_closeout_completed",
            "changed": false,
            "phase": "unregistered",
            "agent_project_id": "managed-child",
            "operation_id": "operation-1",
            "expected_revision": "sha256:revision",
            "registration_incarnation": "incarnation-1",
        });
        let valid = |value: &Value| {
            native_closeout_readonly_terminal_receipt_matches(
                Some(0),
                value,
                "managed-child",
                "operation-1",
                "sha256:revision",
                "incarnation-1",
            )
        };
        assert!(valid(&receipt));
        for (field, replacement) in [
            ("operation", json!("native_managed_closeout")),
            ("outcome", json!("native_closeout_admission_observed")),
            ("changed", json!(true)),
            ("phase", json!("git_removed")),
            ("agent_project_id", json!("another-child")),
            ("operation_id", json!("another-operation")),
            ("expected_revision", json!("sha256:another")),
            ("registration_incarnation", json!("incarnation-2")),
        ] {
            let mut wrong = receipt.clone();
            wrong[field] = replacement;
            assert!(!valid(&wrong), "must reject {field}");
        }
        assert!(!native_closeout_readonly_terminal_receipt_matches(
            Some(1),
            &receipt,
            "managed-child",
            "operation-1",
            "sha256:revision",
            "incarnation-1",
        ));
    }

    #[test]
    fn native_closeout_terminal_receipt_requires_all_exact_identity_fields() {
        let source = json!({
            "operation": "native_managed_closeout",
            "outcome": "native_closeout_completed",
            "changed": true,
            "phase": "unregistered",
            "agent_project_id": "child-1",
            "operation_id": "op-1",
            "expected_revision": "sha256:expected",
            "registration_incarnation": "incarnation-1"
        });
        let check = |exit_code, body: &Value| {
            native_closeout_terminal_receipt_matches(
                exit_code,
                body,
                "child-1",
                "op-1",
                "sha256:expected",
                "incarnation-1",
            )
        };
        assert!(check(Some(0), &source));
        assert!(!check(Some(1), &source));
        assert!(!check(None, &source));
        for (field, replacement) in [
            ("operation", json!("project_lifecycle_unregister")),
            ("outcome", json!("native_closeout_admission_observed")),
            ("changed", json!(false)),
            ("phase", json!("git_removed")),
            ("agent_project_id", json!("child-2")),
            ("operation_id", json!("op-old")),
            ("expected_revision", json!("sha256:other")),
            ("registration_incarnation", json!("incarnation-old")),
        ] {
            let mut changed = source.clone();
            changed[field] = replacement;
            assert!(!check(Some(0), &changed), "must reject {field}");
            let mut missing = source.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(!check(Some(0), &missing), "must require {field}");
        }
        let mut contradictory = source;
        contradictory["error_code"] = json!("operation_indeterminate");
        assert!(!check(Some(0), &contradictory));
    }

    #[test]
    fn project_lifecycle_error_mapping_is_stable_and_safe() {
        assert_eq!(map_agent_error("agent_unavailable").status, 503);
        assert_eq!(map_agent_error("revision_conflict").status, 409);
        assert_eq!(map_agent_error("path_exists").status, 409);
        assert_eq!(map_agent_error("secret internal backtrace").status, 500);
        assert_eq!(
            map_agent_error("secret internal backtrace").body["error"]["code"],
            "operation_failed"
        );
    }

    #[test]
    fn transient_and_conflict_results_are_not_persisted() {
        for code in [
            "agent_unavailable",
            "operation_indeterminate",
            "active_jobs_conflict",
        ] {
            assert!(!is_persistable_terminal(&api_error(503, code)));
        }
        assert!(!is_persistable_terminal(&ServiceResponse {
            status: 409,
            body: json!({"error":{"code":"active_jobs_conflict"}}),
        }));
        assert!(is_persistable_terminal(&ServiceResponse {
            status: 200,
            body: json!({"outcome":"already_disabled"}),
        }));
    }

    #[test]
    fn old_transient_with_different_payload_is_conflict_before_delete() {
        let transient = api_error(503, "agent_unavailable");
        assert_eq!(
            stored_idempotency_action("sha256:old", "sha256:new", &transient),
            StoredIdempotencyAction::Conflict
        );
        assert_eq!(
            stored_idempotency_action("sha256:same", "sha256:same", &transient),
            StoredIdempotencyAction::DeleteAndRetry
        );
    }

    #[test]
    fn create_result_preserves_recovery_metadata() {
        let result = ToolResult::ok(json!({
            "outcome":"created", "changed":false, "recovered":true,
            "revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }));
        let response = map_create_result("create", "created", "agent:oe:demo", result).unwrap();
        assert_eq!(response.body["changed"], false);
        assert_eq!(response.body["recovered"], true);
        let invalid = ToolResult::ok(json!({
            "outcome":"registered", "changed":true, "revision":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }));
        assert_eq!(
            map_create_result("create", "created", "agent:oe:demo", invalid)
                .unwrap_err()
                .status,
            502
        );
    }
    #[test]
    fn project_lifecycle_idempotency_keys_are_bounded() {
        assert!(valid_idempotency_key("req-1:retry_2"));
        assert!(!valid_idempotency_key(""));
        assert!(!valid_idempotency_key("contains space"));
        assert!(!valid_idempotency_key(&"a".repeat(IDEMPOTENCY_KEY_MAX + 1)));
    }
}
