//! Mount-authorized control plane for a standing MPC node.
//!
//! A controller publishes commands atomically (temporary file + rename) into a
//! shared `commands` directory. Every party reads the same immutable command
//! and writes its own durable acknowledgement/event file. The directory mount
//! is the authorization boundary; this module never accepts commands over an
//! unauthenticated network listener.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use stoffel_vm::net::session::ExecutionId;
use stoffel_vm::net::{
    program_id_from_bytes, ExecutionSpecV1, MpcBackendKind, MpcCurveConfig, NodeEvent,
    NodeEventKind, NodeExecutionContext, NodeSupervisor, PreparedNodeExecution,
};
use stoffel_vm_types::compiled_binary::{
    ClientIoManifest, CompiledBinary, PreprocessingDemand,
    PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION,
};
use stoffelnet::network_utils::{CertificateIdentity, NodePublicKey};
use tokio_util::sync::CancellationToken;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

/// Upper bound for a committed command or durable event file.
///
/// Control files contain only execution metadata, so one MiB leaves ample
/// room for legitimate admissions while preventing a corrupted control mount
/// from forcing an unbounded allocation before JSON validation.
const MAX_STANDING_CONTROL_FILE_BYTES: usize = 1024 * 1024;
const MAX_STANDING_EVENT_TEXT_BYTES: usize = 16 * 1024;
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(25);
#[derive(Debug)]
enum BoundedControlFile {
    Bytes(Vec<u8>),
    Oversized(u64),
}

/// One authenticated client principal and the VM manifest slot it owns.
///
/// Vector order is the execution-local client ordinal used by the MPC backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingClientAdmissionV1 {
    pub certificate: String,
    pub manifest_slot: usize,
}

/// Complete immutable execution descriptor committed by `config_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingExecutionAdmissionV1 {
    /// Exactly 64 hexadecimal characters.
    pub execution_id: String,
    /// Content address of `programs/<program_id>.stflb`.
    pub program_id: String,
    pub entry: String,
    pub clients: Vec<StandingClientAdmissionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum StandingControlCommandV1 {
    Prepare {
        admission: StandingExecutionAdmissionV1,
    },
    Cancel {
        execution_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StandingControlOutcomeV1 {
    Event { event: NodeEvent },
    Rejected { error: String },
}

#[derive(Debug, Clone)]
pub struct ResolvedStandingExecutionAdmissionV1 {
    pub execution_id: ExecutionId,
    pub program_id: [u8; 32],
    pub entry: String,
    pub clients: Vec<StandingClientAdmissionV1>,
    /// Ordered, certificate-exact client principals frozen during Prepare.
    /// Vector position is the execution-local client ordinal.
    pub expected_client_identities: Vec<CertificateIdentity>,
    pub config_digest: [u8; 32],
}

#[async_trait::async_trait]
pub trait StandingExecutionHandler: Send + Sync + 'static {
    async fn prepare(
        self: Arc<Self>,
        admission: ResolvedStandingExecutionAdmissionV1,
        context: NodeExecutionContext,
    ) -> Result<Box<dyn PreparedNodeExecution>, String>;
}

#[derive(Debug, thiserror::Error)]
pub enum StandingControlError {
    #[error("standing control IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid standing control command: {0}")]
    InvalidCommand(String),
}

fn io_error(path: &Path, source: std::io::Error) -> StandingControlError {
    StandingControlError::Io {
        path: path.to_owned(),
        source,
    }
}

fn load_cursor(events: &Path) -> Result<u64, StandingControlError> {
    let mut sequences = fs::read_dir(events)
        .map_err(|source| io_error(events, source))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.path().file_stem()?.to_str()?.parse::<u64>().ok())
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    let mut next = 1u64;
    for sequence in sequences {
        if sequence != next {
            return Err(StandingControlError::InvalidCommand(format!(
                "non-contiguous command event journal: expected {next}, found {sequence}"
            )));
        }
        let path = events.join(format!("{sequence:020}.json"));
        let _: StandingControlOutcomeV1 = read_json(&path, "command event")?;
        next = next
            .checked_add(1)
            .ok_or_else(|| StandingControlError::InvalidCommand("sequence exhausted".to_owned()))?;
    }
    Ok(next)
}

fn retire_execution(
    directory: &Path,
    execution_id: ExecutionId,
) -> Result<(), StandingControlError> {
    atomic_write_bytes(
        &directory.join(execution_id.to_string()),
        execution_id.to_string().as_bytes(),
    )
}

/// A deliberately boring control pump. Commands are globally sequenced and
/// Prepare returns immediately, so serial command admission cannot prevent
/// independent executions from running concurrently.
pub struct StandingNodeControl {
    commands_dir: PathBuf,
    events_dir: PathBuf,
    programs_dir: PathBuf,
    client_cert_dir: PathBuf,
    supervisor: Arc<NodeSupervisor>,
    handler: Arc<dyn StandingExecutionHandler>,
    retired_executions: PathBuf,
}

impl StandingNodeControl {
    pub fn new<H>(
        party_id: usize,
        control_root: impl Into<PathBuf>,
        programs_dir: impl Into<PathBuf>,
        client_cert_dir: impl Into<PathBuf>,
        supervisor: Arc<NodeSupervisor>,
        handler: Arc<H>,
    ) -> Result<Self, StandingControlError>
    where
        H: StandingExecutionHandler,
    {
        let control_root = control_root.into();
        let commands_dir = control_root.join("commands");
        let events_dir = control_root.join("events").join(format!("party{party_id}"));
        let programs_dir = programs_dir.into();
        let client_cert_dir = client_cert_dir.into();
        for path in [&commands_dir, &events_dir, &programs_dir] {
            fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
        }
        let retired_executions =
            events_dir.join(".standing-control-state-v1/retired_execution_ids");
        fs::create_dir_all(&retired_executions)
            .map_err(|source| io_error(&retired_executions, source))?;
        Ok(Self {
            commands_dir,
            events_dir,
            programs_dir,
            client_cert_dir,
            supervisor,
            handler,
            retired_executions,
        })
    }

    pub async fn run(&self, cancellation: CancellationToken) -> Result<(), StandingControlError> {
        let mut cursor = load_cursor(&self.events_dir)?;
        let mut interval = tokio::time::interval(CONTROL_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut events = self.supervisor.subscribe();
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = interval.tick() => { self.poll_one(&mut cursor)?; },
                event = events.recv() => match event {
                    Ok(event) if is_async_lifecycle_event(&event) => self.write_async_event(event)?,
                    Ok(_) => {},
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        return Err(StandingControlError::InvalidCommand("lost lifecycle event".to_owned()));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }

    fn poll_one(&self, cursor: &mut u64) -> Result<(), StandingControlError> {
        if *cursor > 1 {
            remove_file_if_exists(&self.command_path(*cursor - 1))?;
        }
        let path = self.command_path(*cursor);
        if !path.is_file() {
            return Ok(());
        }
        let event = match read_bounded_control_file(&path)? {
            BoundedControlFile::Oversized(size) => StandingControlOutcomeV1::Rejected {
                error: format!(
                    "command file is {size} bytes; maximum is {MAX_STANDING_CONTROL_FILE_BYTES}"
                ),
            },
            BoundedControlFile::Bytes(bytes) => match serde_json::from_slice(&bytes) {
                Ok(command) => self.handle_command(command),
                Err(error) => StandingControlOutcomeV1::Rejected {
                    error: format!("malformed command: {error}"),
                },
            },
        };
        self.write_event(*cursor, event)?;
        remove_file_if_exists(&path)?;
        *cursor = cursor
            .checked_add(1)
            .ok_or_else(|| StandingControlError::InvalidCommand("sequence exhausted".to_owned()))?;
        Ok(())
    }

    fn command_path(&self, sequence: u64) -> PathBuf {
        self.commands_dir.join(format!("{sequence:020}.json"))
    }

    fn handle_command(&self, command: StandingControlCommandV1) -> StandingControlOutcomeV1 {
        match self.dispatch_command(command) {
            Ok(event) => StandingControlOutcomeV1::Event { event },
            Err(error) => StandingControlOutcomeV1::Rejected { error },
        }
    }

    fn dispatch_command(&self, command: StandingControlCommandV1) -> Result<NodeEvent, String> {
        match command {
            StandingControlCommandV1::Cancel { execution_id } => {
                let execution_id =
                    parse_execution_id(&execution_id).map_err(|error| error.to_string())?;
                self.supervisor
                    .cancel(execution_id)
                    .map_err(|error| error.to_string())
            }
            StandingControlCommandV1::Prepare { admission } => {
                let resolved = self
                    .resolve_admission(admission)
                    .map_err(|error| error.to_string())?;
                let id = resolved.execution_id;
                if self.retired_executions.join(id.to_string()).is_file() {
                    return Err(format!("execution {id} is retired"));
                }
                retire_execution(&self.retired_executions, id)
                    .map_err(|error| error.to_string())?;
                let spec = ExecutionSpecV1::new(id, resolved.program_id);
                let handler = Arc::clone(&self.handler);
                self.supervisor
                    .prepare(spec, move |context| handler.prepare(resolved, context))
                    .map_err(|error| error.to_string())
            }
        }
    }

    fn resolve_admission(
        &self,
        admission: StandingExecutionAdmissionV1,
    ) -> Result<ResolvedStandingExecutionAdmissionV1, StandingControlError> {
        let execution_id = parse_execution_id(&admission.execution_id)?;
        if execution_id.is_zero() {
            return Err(StandingControlError::InvalidCommand(
                "execution_id must be nonzero".to_owned(),
            ));
        }
        let program_id = parse_digest(&admission.program_id, "program_id")?;
        for client in &admission.clients {
            let name = &client.certificate;
            if name.is_empty() || Path::new(name).components().count() != 1 {
                return Err(StandingControlError::InvalidCommand(format!(
                    "identity artifact must be a leaf filename, got {name:?}"
                )));
            }
        }
        let program_path = self
            .programs_dir
            .join(format!("{}.stflb", admission.program_id));
        let bytes = fs::read(&program_path).map_err(|source| io_error(&program_path, source))?;
        if program_id_from_bytes(&bytes) != program_id {
            return Err(StandingControlError::InvalidCommand(format!(
                "program artifact {} does not match content address {}",
                program_path.display(),
                admission.program_id
            )));
        }
        let (client_io_manifest, _, _) = validate_standing_program(&bytes, Some(&admission.entry))?;
        validate_client_io_admission(&admission.clients, &client_io_manifest)?;

        let mut expected_client_identities = Vec::with_capacity(admission.clients.len());
        let mut unique_client_identities = HashSet::with_capacity(admission.clients.len());
        for client in &admission.clients {
            let path = self.client_cert_dir.join(&client.certificate);
            let cert_der = fs::read(&path).map_err(|source| io_error(&path, source))?;
            if cert_der.len() > MAX_STANDING_CONTROL_FILE_BYTES {
                return Err(StandingControlError::InvalidCommand(format!(
                    "client certificate {} exceeds {} bytes",
                    path.display(),
                    MAX_STANDING_CONTROL_FILE_BYTES
                )));
            }
            let (remainder, parsed) = X509Certificate::from_der(&cert_der).map_err(|error| {
                StandingControlError::InvalidCommand(format!(
                    "parse expected client certificate {}: {error}",
                    path.display()
                ))
            })?;
            if !remainder.is_empty() {
                return Err(StandingControlError::InvalidCommand(format!(
                    "expected client certificate {} has trailing bytes",
                    path.display()
                )));
            }
            let identity = NodePublicKey(parsed.public_key().raw.to_vec()).certificate_identity();
            if !unique_client_identities.insert(identity) {
                return Err(StandingControlError::InvalidCommand(format!(
                    "standing client roster contains duplicate SPKI identity at {:?}",
                    client.certificate
                )));
            }
            expected_client_identities.push(identity);
        }

        let canonical = serde_json::to_vec(&admission)
            .map_err(|error| StandingControlError::InvalidCommand(error.to_string()))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"stoffel-standing-admission-v1");
        hasher.update(&canonical);
        hasher.update(&(expected_client_identities.len() as u64).to_le_bytes());
        for identity in &expected_client_identities {
            hasher.update(identity.as_bytes());
        }
        let config_digest = *hasher.finalize().as_bytes();

        Ok(ResolvedStandingExecutionAdmissionV1 {
            execution_id,
            program_id,
            entry: admission.entry,
            clients: admission.clients,
            expected_client_identities,
            config_digest,
        })
    }

    fn write_event(
        &self,
        sequence: u64,
        mut event: StandingControlOutcomeV1,
    ) -> Result<(), StandingControlError> {
        sanitize_standing_control_event(&mut event);
        atomic_write_json(
            &self.events_dir.join(format!("{sequence:020}.json")),
            &event,
        )
    }

    fn write_async_event(&self, event: NodeEvent) -> Result<(), StandingControlError> {
        let id = event.execution_id;
        let phase = event_phase_name(&event);
        let mut file = StandingControlOutcomeV1::Event { event };
        sanitize_standing_control_event(&mut file);
        atomic_write_json(
            &self.events_dir.join(format!("async-{id}-{phase}.json")),
            &file,
        )?;
        Ok(())
    }
}

/// Parse and validate an artifact accepted by a standing node. When an entry
/// is supplied, also require that function to exist.
pub fn validate_standing_program(
    bytes: &[u8],
    entry: Option<&str>,
) -> Result<(ClientIoManifest, MpcBackendKind, MpcCurveConfig), StandingControlError> {
    let mut reader = BufReader::new(bytes);
    let mut entry_found = entry.is_none();
    let (functions, version, manifest) =
        CompiledBinary::try_for_each_vm_function_from_reader(&mut reader, |function| {
            entry_found |= entry == Some(function.name());
            Ok(())
        })
        .map_err(|error| {
            StandingControlError::InvalidCommand(format!("invalid program: {error:?}"))
        })?;
    if functions == 0 {
        return Err(StandingControlError::InvalidCommand(
            "compiled program contains no functions".to_owned(),
        ));
    }
    if !entry_found {
        return Err(StandingControlError::InvalidCommand(format!(
            "admitted entry function {:?} is absent from compiled program",
            entry.unwrap()
        )));
    }
    validate_standing_preprocessing_manifest(version, &manifest.preprocessing_demand)
        .map_err(StandingControlError::InvalidCommand)?;
    let backend = MpcBackendKind::from(manifest.mpc_backend);
    let curve = MpcCurveConfig::from(manifest.mpc_curve);
    curve
        .validate_for_backend(backend)
        .map_err(|error| StandingControlError::InvalidCommand(error.to_string()))?;
    Ok((manifest, backend, curve))
}

fn validate_standing_preprocessing_manifest(
    artifact_version: u16,
    demand: &PreprocessingDemand,
) -> Result<(), String> {
    if artifact_version < PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION {
        return Err(format!(
            "standing execution requires artifact format version {PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION} or newer; version {artifact_version} has no complete preprocessing manifest"
        ));
    }
    if demand.dynamic {
        return Err(
            "standing execution requires statically bounded preprocessing demand".to_owned(),
        );
    }
    Ok(())
}

/// Require the authenticated client-to-slot mapping to cover the compiled
/// client manifest exactly. Input-bearing slots and their per-client counts are
/// deliberately not repeated in the admission: execution setup derives them
/// from this same content-addressed manifest.
fn validate_client_io_admission(
    clients: &[StandingClientAdmissionV1],
    manifest: &ClientIoManifest,
) -> Result<(), StandingControlError> {
    if clients.len() > usize::from(u8::MAX) + 1 {
        return Err(StandingControlError::InvalidCommand(format!(
            "{} clients exceed the one-byte MPC client index domain",
            clients.len()
        )));
    }
    let mut roster_slots = HashSet::with_capacity(clients.len());
    for client in clients {
        if !roster_slots.insert(client.manifest_slot) {
            return Err(StandingControlError::InvalidCommand(format!(
                "standing clients contain duplicate manifest slot {}",
                client.manifest_slot
            )));
        }
    }

    let mut manifest_slots = HashSet::with_capacity(manifest.clients.len());
    for schema in &manifest.clients {
        let slot = usize::try_from(schema.client_slot).map_err(|_| {
            StandingControlError::InvalidCommand(format!(
                "program client slot {} exceeds this node's usize range",
                schema.client_slot
            ))
        })?;
        if !manifest_slots.insert(slot) {
            return Err(StandingControlError::InvalidCommand(format!(
                "program client IO manifest contains duplicate client slot {slot}"
            )));
        }
    }

    if roster_slots != manifest_slots {
        let mut admitted = roster_slots.into_iter().collect::<Vec<_>>();
        let mut compiled = manifest_slots.into_iter().collect::<Vec<_>>();
        admitted.sort_unstable();
        compiled.sort_unstable();
        return Err(StandingControlError::InvalidCommand(format!(
            "standing client slots {admitted:?} do not match program manifest slots {compiled:?}"
        )));
    }
    manifest.clients.iter().try_fold(0usize, |total, schema| {
        total.checked_add(schema.inputs.len()).ok_or_else(|| {
            StandingControlError::InvalidCommand(
                "program client input total exceeds this node's usize range".to_owned(),
            )
        })
    })?;
    Ok(())
}

fn parse_execution_id(value: &str) -> Result<ExecutionId, StandingControlError> {
    value.parse().map_err(|error| {
        StandingControlError::InvalidCommand(format!("invalid execution_id: {error}"))
    })
}

fn parse_digest(value: &str, name: &str) -> Result<[u8; 32], StandingControlError> {
    if value.len() != 64 {
        return Err(StandingControlError::InvalidCommand(format!(
            "{name} must contain exactly 64 hexadecimal characters"
        )));
    }
    let decoded = hex::decode(value).map_err(|error| {
        StandingControlError::InvalidCommand(format!("invalid {name}: {error}"))
    })?;
    decoded.try_into().map_err(|_| {
        StandingControlError::InvalidCommand(format!("{name} must decode to 32 bytes"))
    })
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), StandingControlError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| StandingControlError::InvalidCommand(error.to_string()))?;
    if bytes.len() > MAX_STANDING_CONTROL_FILE_BYTES {
        return Err(StandingControlError::InvalidCommand(format!(
            "durable standing control state for {} exceeds {MAX_STANDING_CONTROL_FILE_BYTES} bytes",
            path.display()
        )));
    }
    atomic_write_bytes(path, &bytes)
}

fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), StandingControlError> {
    let parent = path.parent().ok_or_else(|| {
        StandingControlError::InvalidCommand(format!(
            "durable standing control path {} has no parent",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    // One control task owns this party's event directory, so each destination
    // needs only one stable temporary sibling. A stale file from a crash is
    // safely overwritten before the atomic rename.
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|source| io_error(&temporary, source))?;
    fs::rename(&temporary, path).map_err(|source| io_error(path, source))
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    label: &str,
) -> Result<T, StandingControlError> {
    let bytes = match read_bounded_control_file(path)? {
        BoundedControlFile::Bytes(bytes) => bytes,
        BoundedControlFile::Oversized(size_hint) => {
            return Err(StandingControlError::InvalidCommand(format!(
                "durable standing control {label} {} is {size_hint} bytes; maximum is {MAX_STANDING_CONTROL_FILE_BYTES} bytes",
                path.display()
            )))
        }
    };
    serde_json::from_slice(&bytes).map_err(|error| {
        StandingControlError::InvalidCommand(format!(
            "malformed durable standing control {label} {}: {error}",
            path.display()
        ))
    })
}

fn remove_file_if_exists(path: &Path) -> Result<(), StandingControlError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn read_bounded_control_file(path: &Path) -> Result<BoundedControlFile, StandingControlError> {
    let metadata = fs::metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.len() > MAX_STANDING_CONTROL_FILE_BYTES as u64 {
        return Ok(BoundedControlFile::Oversized(metadata.len()));
    }

    // The metadata check avoids reading known-large files. `take` also keeps
    // the allocation bounded if a publisher violates the atomic-rename
    // contract and grows/replaces a file between metadata and open.
    let file = fs::File::open(path).map_err(|source| io_error(path, source))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_STANDING_CONTROL_FILE_BYTES)
            .min(MAX_STANDING_CONTROL_FILE_BYTES),
    );
    file.take((MAX_STANDING_CONTROL_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() > MAX_STANDING_CONTROL_FILE_BYTES {
        return Ok(BoundedControlFile::Oversized(
            metadata.len().max(bytes.len() as u64),
        ));
    }
    Ok(BoundedControlFile::Bytes(bytes))
}

fn bounded_standing_event_text(mut value: String) -> String {
    if value.len() <= MAX_STANDING_EVENT_TEXT_BYTES {
        return value;
    }
    let original_len = value.len();
    let digest = blake3::hash(value.as_bytes()).to_hex();
    let suffix = format!("...[truncated bytes={original_len} blake3={digest}]");
    let mut keep = MAX_STANDING_EVENT_TEXT_BYTES.saturating_sub(suffix.len());
    while keep > 0 && !value.is_char_boundary(keep) {
        keep -= 1;
    }
    value.truncate(keep);
    value.push_str(&suffix);
    value
}

fn sanitize_node_event(event: &mut NodeEvent) {
    if let NodeEventKind::Failed { error } = &mut event.kind {
        *error = bounded_standing_event_text(std::mem::take(error));
    }
}

fn sanitize_standing_control_event(event: &mut StandingControlOutcomeV1) {
    match event {
        StandingControlOutcomeV1::Rejected { error } => {
            *error = bounded_standing_event_text(std::mem::take(error));
        }
        StandingControlOutcomeV1::Event { event } => sanitize_node_event(event),
    }
}

fn is_async_lifecycle_event(event: &NodeEvent) -> bool {
    matches!(
        event.kind,
        NodeEventKind::Ready
            | NodeEventKind::Completed { .. }
            | NodeEventKind::Failed { .. }
            | NodeEventKind::Cancelled
    )
}

fn event_phase_name(event: &NodeEvent) -> &'static str {
    match event.kind {
        NodeEventKind::Ready => "ready",
        NodeEventKind::Completed { .. } => "completed",
        NodeEventKind::Failed { .. } => "failed",
        NodeEventKind::Cancelled => "cancelled",
        _ => "event",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoffel_vm_types::compiled_binary::ClientIoSchema;

    fn client(certificate: &str, manifest_slot: usize) -> StandingClientAdmissionV1 {
        StandingClientAdmissionV1 {
            certificate: certificate.to_owned(),
            manifest_slot,
        }
    }

    fn manifest(slots: &[u64]) -> ClientIoManifest {
        ClientIoManifest {
            clients: slots
                .iter()
                .map(|slot| ClientIoSchema {
                    client_slot: *slot,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                })
                .collect(),
            ..ClientIoManifest::default()
        }
    }

    #[test]
    fn retired_execution_ids_are_durable_and_rejected_after_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let retired = temporary.path().join("retired");
        let execution_id = ExecutionId::from([7; 32]);

        retire_execution(&retired, execution_id).unwrap();
        assert!(retired.join(execution_id.to_string()).is_file());
    }

    #[test]
    fn standing_client_bindings_cover_manifest_exactly() {
        let admission = vec![client("client1.crt", 1), client("client0.crt", 0)];
        validate_client_io_admission(&admission, &manifest(&[0, 1])).unwrap();

        let duplicate_slot = vec![client("client0.crt", 0), client("client1.crt", 0)];
        assert!(validate_client_io_admission(&duplicate_slot, &manifest(&[0, 1])).is_err());

        let missing_slot = vec![client("client0.crt", 0)];
        assert!(validate_client_io_admission(&missing_slot, &manifest(&[0, 1])).is_err());

        let too_many = (0..257)
            .map(|slot| client("client.crt", slot))
            .collect::<Vec<_>>();
        assert!(validate_client_io_admission(&too_many, &ClientIoManifest::default()).is_err());
    }

    #[test]
    fn standing_preprocessing_requires_a_current_bounded_manifest() {
        let fixed = PreprocessingDemand::default();
        let old_version = validate_standing_preprocessing_manifest(
            PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION - 1,
            &fixed,
        )
        .unwrap_err();
        assert!(old_version.contains("no complete preprocessing manifest"));

        let dynamic = PreprocessingDemand {
            dynamic: true,
            ..PreprocessingDemand::default()
        };
        let unbounded = validate_standing_preprocessing_manifest(
            PREPROCESSING_DEMAND_MANIFEST_FORMAT_VERSION,
            &dynamic,
        )
        .unwrap_err();
        assert!(unbounded.contains("statically bounded"));
    }

    #[test]
    fn removed_standing_admission_fields_are_rejected() {
        let old_backend = serde_json::json!({
            "execution_id": "01",
            "program_id": "02",
            "entry": "main",
            "backend": "honeybadger",
            "curve": "bls12-381",
            "clients": []
        });
        assert!(serde_json::from_value::<StandingExecutionAdmissionV1>(old_backend).is_err());

        let old_parallel_client_fields = serde_json::json!({
            "execution_id": "01",
            "program_id": "02",
            "entry": "main",
            "client_io": {
                "expected_client_certificates": [],
                "client_roster": [],
                "client_input_slots": [],
                "client_input_count": 0,
                "client_input_total": 0
            }
        });
        assert!(
            serde_json::from_value::<StandingExecutionAdmissionV1>(old_parallel_client_fields)
                .is_err()
        );
    }
}
