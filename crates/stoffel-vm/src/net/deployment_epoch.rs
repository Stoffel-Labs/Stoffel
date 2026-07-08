use crate::net::deployment_manifest::DeploymentId;
use crate::storage::preproc::{PreprocStore, PreprocStoreError};
use serde::{Deserialize, Serialize};

const EPOCH_NS: &[u8] = b"epoch:";
const RUNSTATE_NS: &[u8] = b"runstate:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunPhase {
    Prepared,
    InProgress,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunState {
    pub run_id: u64,
    pub phase: RunPhase,
}

fn deployment_program_key(
    prefix: &str,
    deployment_id: &DeploymentId,
    program_hash: &[u8; 32],
) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + deployment_id.as_str().len() + 1 + 64);
    key.extend_from_slice(prefix.as_bytes());
    key.extend_from_slice(deployment_id.as_str().as_bytes());
    key.push(b':');
    key.extend_from_slice(hex::encode(program_hash).as_bytes());
    key
}

fn observed_key(deployment_id: &DeploymentId, program_hash: &[u8; 32], party_id: usize) -> Vec<u8> {
    let mut key = deployment_program_key("last_observed:", deployment_id, program_hash);
    key.push(b':');
    key.extend_from_slice(party_id.to_string().as_bytes());
    key
}

fn runstate_key(
    program_hash: &[u8; 32],
    persistent_identity: [u8; 32],
    party_id: usize,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 32 + 8);
    key.extend_from_slice(program_hash);
    key.extend_from_slice(&persistent_identity);
    key.extend_from_slice(&party_id.to_le_bytes());
    key
}

fn decode_u64(raw: Option<Vec<u8>>) -> Result<u64, PreprocStoreError> {
    match raw {
        Some(raw) => {
            if raw.len() != 8 {
                return Err(PreprocStoreError::Deserialization(format!(
                    "epoch value has {} bytes, expected 8",
                    raw.len()
                )));
            }
            Ok(u64::from_le_bytes(raw.as_slice().try_into().map_err(
                |_| PreprocStoreError::Deserialization("bad epoch bytes".into()),
            )?))
        }
        None => Ok(0),
    }
}

pub async fn allocate_epoch_and_record(
    store: &dyn PreprocStore,
    deployment_id: &DeploymentId,
    program_hash: &[u8; 32],
) -> Result<(u64, bool), PreprocStoreError> {
    let next_key = deployment_program_key("next:", deployment_id, program_hash);
    let announced_key = deployment_program_key("announced:", deployment_id, program_hash);
    let next = decode_u64(store.load_blob(EPOCH_NS, &next_key).await?)?;
    let announced = decode_u64(store.load_blob(EPOCH_NS, &announced_key).await?)?;
    if next > announced {
        return Ok((announced + 1, true));
    }
    let allocated = store.atomic_increment(EPOCH_NS, &next_key).await?;
    Ok((allocated, false))
}

pub async fn record_announced_epoch(
    store: &dyn PreprocStore,
    deployment_id: &DeploymentId,
    program_hash: &[u8; 32],
    epoch: u64,
) -> Result<(), PreprocStoreError> {
    let announced_key = deployment_program_key("announced:", deployment_id, program_hash);
    store
        .store_blob(EPOCH_NS, &announced_key, &epoch.to_le_bytes())
        .await
}

pub async fn reconcile_announced_epochs(
    store: &dyn PreprocStore,
    deployment_id: &DeploymentId,
    program_hash: &[u8; 32],
    party_id: usize,
) -> Result<u64, PreprocStoreError> {
    let announced_key = deployment_program_key("announced:", deployment_id, program_hash);
    let last_key = observed_key(deployment_id, program_hash, party_id);
    let announced = decode_u64(store.load_blob(EPOCH_NS, &announced_key).await?)?;
    let last_observed = decode_u64(store.load_blob(EPOCH_NS, &last_key).await?)?;
    Ok(announced.max(last_observed))
}

pub async fn record_observed_epoch(
    store: &dyn PreprocStore,
    deployment_id: &DeploymentId,
    program_hash: &[u8; 32],
    party_id: usize,
    epoch: u64,
) -> Result<(), PreprocStoreError> {
    let last_key = observed_key(deployment_id, program_hash, party_id);
    let last = decode_u64(store.load_blob(EPOCH_NS, &last_key).await?)?;
    if epoch < last {
        return Err(PreprocStoreError::Serialization(format!(
            "stale epoch {epoch} is below last observed {last}"
        )));
    }
    store
        .store_blob(EPOCH_NS, &last_key, &epoch.to_le_bytes())
        .await
}

pub async fn write_runstate(
    store: &dyn PreprocStore,
    program_hash: &[u8; 32],
    persistent_identity: [u8; 32],
    party_id: usize,
    state: RunState,
) -> Result<(), PreprocStoreError> {
    let key = runstate_key(program_hash, persistent_identity, party_id);
    let data = bincode::serialize(&state)?;
    store.store_blob(RUNSTATE_NS, &key, &data).await
}

pub async fn read_runstate(
    store: &dyn PreprocStore,
    program_hash: &[u8; 32],
    persistent_identity: [u8; 32],
    party_id: usize,
) -> Result<Option<RunState>, PreprocStoreError> {
    let key = runstate_key(program_hash, persistent_identity, party_id);
    store
        .load_blob(RUNSTATE_NS, &key)
        .await?
        .map(|data| bincode::deserialize(&data).map_err(PreprocStoreError::from))
        .transpose()
}
