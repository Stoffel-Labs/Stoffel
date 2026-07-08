use crate::net::backend::MpcBackendKind;
use crate::net::curve::{MpcCurveConfig, MpcFieldKind};
use crate::net::engine_config::DeploymentMode;
use crate::net::mpc_engine::DurableIdentityDigest;
use crate::storage::preproc::PoolAvailability;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeploymentId(String);

impl DeploymentId {
    pub fn new(value: impl Into<String>) -> Result<Self, DeploymentManifestError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DeploymentManifestError::InvalidDeploymentId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentTimeouts {
    pub quorum_timeout_secs: u64,
    pub cursor_sync_timeout_secs: u64,
    pub readiness_timeout_secs: u64,
}

impl Default for DeploymentTimeouts {
    fn default() -> Self {
        Self {
            quorum_timeout_secs: 30,
            cursor_sync_timeout_secs: 10,
            readiness_timeout_secs: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentManifest {
    pub deployment_id: DeploymentId,
    pub backend: MpcBackendKind,
    pub program_hash: [u8; 32],
    pub program_source: String,
    pub curve: MpcCurveConfig,
    pub field: MpcFieldKind,
    pub n: usize,
    pub t: usize,
    pub deployment_mode: DeploymentMode,
    pub persistent_identity: Vec<DurableIdentityDigest>,
    pub node_addresses: Vec<SocketAddr>,
    pub coordinator_rpc: SocketAddr,
    pub preproc_targets: PoolAvailability,
    pub preproc_low_watermark: PoolAvailability,
    pub capacity: u64,
    pub timeouts: DeploymentTimeouts,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeploymentManifestError {
    #[error("deployment id must not be empty")]
    InvalidDeploymentId,
    #[error("persistent deployment manifests must use Standing mode")]
    NotStanding,
    #[error(
        "manifest party count mismatch: n={n}, identities={identities}, node_addresses={addresses}"
    )]
    PartyCountMismatch {
        n: usize,
        identities: usize,
        addresses: usize,
    },
    #[error("manifest threshold {threshold} must be less than party count {n}")]
    ThresholdOutOfRange { threshold: usize, n: usize },
    #[error("manifest field {field:?} does not match curve {curve:?}")]
    FieldCurveMismatch {
        field: MpcFieldKind,
        curve: MpcCurveConfig,
    },
    #[error("manifest backend {backend:?} does not support curve {curve:?}: {reason}")]
    BackendCurveUnsupported {
        backend: MpcBackendKind,
        curve: MpcCurveConfig,
        reason: String,
    },
}

impl DeploymentManifest {
    pub fn validate(&self) -> Result<(), DeploymentManifestError> {
        if self.deployment_mode != DeploymentMode::Standing {
            return Err(DeploymentManifestError::NotStanding);
        }
        if self.persistent_identity.len() != self.n || self.node_addresses.len() != self.n {
            return Err(DeploymentManifestError::PartyCountMismatch {
                n: self.n,
                identities: self.persistent_identity.len(),
                addresses: self.node_addresses.len(),
            });
        }
        if self.t >= self.n {
            return Err(DeploymentManifestError::ThresholdOutOfRange {
                threshold: self.t,
                n: self.n,
            });
        }
        if self.curve.field_kind() != self.field {
            return Err(DeploymentManifestError::FieldCurveMismatch {
                field: self.field,
                curve: self.curve,
            });
        }
        self.curve
            .validate_for_backend(self.backend)
            .map_err(|error| DeploymentManifestError::BackendCurveUnsupported {
                backend: self.backend,
                curve: self.curve,
                reason: error.to_string(),
            })?;
        Ok(())
    }
}
