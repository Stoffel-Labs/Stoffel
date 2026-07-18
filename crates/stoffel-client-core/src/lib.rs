//! Portable Stoffel participant-client domain state.
//!
//! This crate deliberately contains no network implementation. [`Transport`]
//! carries opaque bytes so an adapter can encode the existing coordinator/node
//! protocol without pulling native QUIC, Tokio networking, the compiler, or VM
//! into browser builds.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::future::Future;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRole {
    Coordinator,
    Node,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ParticipantEndpoint {
    pub role: EndpointRole,
    pub url: String,
}

impl ParticipantEndpoint {
    pub fn new(role: EndpointRole, url: impl Into<String>) -> Self {
        Self {
            role,
            url: url.into(),
        }
    }

    pub fn validate(&self) -> Result<(), ClientError> {
        let url = self.url.trim();
        let authority = ["https://", "http://", "wss://", "ws://"]
            .iter()
            .find_map(|scheme| url.strip_prefix(scheme));
        let Some(authority) = authority else {
            return Err(ClientError::InvalidConfiguration(
                "participant endpoint must be an absolute http(s) or ws(s) URL".to_owned(),
            ));
        };
        let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() || authority.chars().any(char::is_whitespace) {
            return Err(ClientError::InvalidConfiguration(
                "participant endpoint URL must contain a non-empty authority".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ParticipantConfig {
    pub participant_id: String,
    pub session_id: String,
    pub coordinator: ParticipantEndpoint,
    pub nodes: Vec<ParticipantEndpoint>,
    pub request_timeout_ms: u32,
}

impl ParticipantConfig {
    pub fn validate(&self) -> Result<(), ClientError> {
        validate_identifier("participant_id", &self.participant_id)?;
        validate_identifier("session_id", &self.session_id)?;
        if self.coordinator.role != EndpointRole::Coordinator {
            return Err(ClientError::InvalidConfiguration(
                "coordinator endpoint must have the coordinator role".to_owned(),
            ));
        }
        self.coordinator.validate()?;
        if self.nodes.is_empty() {
            return Err(ClientError::InvalidConfiguration(
                "participant requires at least one node endpoint".to_owned(),
            ));
        }
        if self.request_timeout_ms == 0 {
            return Err(ClientError::InvalidConfiguration(
                "request_timeout_ms must be greater than zero".to_owned(),
            ));
        }

        let mut urls = BTreeSet::new();
        urls.insert(self.coordinator.url.trim());
        for endpoint in &self.nodes {
            if endpoint.role != EndpointRole::Node {
                return Err(ClientError::InvalidConfiguration(
                    "every node endpoint must have the node role".to_owned(),
                ));
            }
            endpoint.validate()?;
            if !urls.insert(endpoint.url.trim()) {
                return Err(ClientError::InvalidConfiguration(format!(
                    "duplicate participant endpoint '{}'",
                    endpoint.url
                )));
            }
        }
        Ok(())
    }
}

fn validate_identifier(name: &str, value: &str) -> Result<(), ClientError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ClientError::InvalidConfiguration(format!(
            "{name} must not be empty"
        )));
    }
    if value.len() > 255 {
        return Err(ClientError::InvalidConfiguration(format!(
            "{name} must not exceed 255 bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ClientError::InvalidConfiguration(format!(
            "{name} must not contain control characters"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientState {
    Initialized,
    TransportReady,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SensitivePayload(Vec<u8>);

impl SensitivePayload {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SensitivePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitivePayload")
            .field("bytes", &"[REDACTED]")
            .field("length", &self.0.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolRequest {
    endpoint: ParticipantEndpoint,
    payload: SensitivePayload,
    timeout_ms: u32,
}

impl ProtocolRequest {
    pub fn new(endpoint: ParticipantEndpoint, payload: SensitivePayload, timeout_ms: u32) -> Self {
        Self {
            endpoint,
            payload,
            timeout_ms,
        }
    }

    pub fn endpoint(&self) -> &ParticipantEndpoint {
        &self.endpoint
    }

    pub fn payload(&self) -> &SensitivePayload {
        &self.payload
    }

    pub fn into_payload(self) -> SensitivePayload {
        self.payload
    }

    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolResponse {
    payload: SensitivePayload,
}

impl ProtocolResponse {
    pub fn new(payload: SensitivePayload) -> Self {
        Self { payload }
    }

    pub fn payload(&self) -> &SensitivePayload {
        &self.payload
    }

    pub fn into_payload(self) -> SensitivePayload {
        self.payload
    }
}

/// Transport adapter contract for the existing coordinator/node wire protocol.
///
/// Implementations are responsible for authentication, protocol framing, and
/// proving delivery. The portable core does not report network submission.
pub trait Transport {
    type Error;
    type Exchange<'a>: Future<Output = Result<ProtocolResponse, Self::Error>>
    where
        Self: 'a;

    fn exchange<'a>(&'a self, request: ProtocolRequest) -> Self::Exchange<'a>;
}

#[derive(Debug, Clone)]
pub struct ParticipantClient {
    config: ParticipantConfig,
    state: ClientState,
}

impl ParticipantClient {
    pub fn new(config: ParticipantConfig) -> Result<Self, ClientError> {
        config.validate()?;
        Ok(Self {
            config,
            state: ClientState::Initialized,
        })
    }

    pub fn config(&self) -> &ParticipantConfig {
        &self.config
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Records readiness established by a concrete transport adapter.
    /// This method does not connect or claim network delivery.
    pub fn mark_transport_ready(&mut self) {
        self.state = ClientState::TransportReady;
    }

    pub fn mark_transport_unavailable(&mut self) {
        self.state = ClientState::Initialized;
    }

    pub fn protocol_request(
        &self,
        role: EndpointRole,
        payload: SensitivePayload,
    ) -> Result<ProtocolRequest, ClientError> {
        if self.state != ClientState::TransportReady {
            return Err(ClientError::TransportNotReady);
        }
        let endpoint = match role {
            EndpointRole::Coordinator => self.config.coordinator.clone(),
            EndpointRole::Node => self.config.nodes[0].clone(),
        };
        Ok(ProtocolRequest::new(
            endpoint,
            payload,
            self.config.request_timeout_ms,
        ))
    }

    pub fn node_protocol_request(
        &self,
        node_index: usize,
        payload: SensitivePayload,
    ) -> Result<ProtocolRequest, ClientError> {
        if self.state != ClientState::TransportReady {
            return Err(ClientError::TransportNotReady);
        }
        let endpoint =
            self.config
                .nodes
                .get(node_index)
                .cloned()
                .ok_or(ClientError::InvalidConfiguration(format!(
                    "node endpoint index {node_index} is out of bounds"
                )))?;
        Ok(ProtocolRequest::new(
            endpoint,
            payload,
            self.config.request_timeout_ms,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    InvalidConfiguration(String),
    TransportNotReady,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => f.write_str(message),
            Self::TransportNotReady => f.write_str(
                "transport is not ready; a concrete adapter must establish connectivity first",
            ),
        }
    }
}

impl Error for ClientError {}
