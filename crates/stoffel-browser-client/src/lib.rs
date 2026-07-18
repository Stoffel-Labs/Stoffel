//! Browser-native Stoffel participant client.
//!
//! Private values are masked inside this WASM module. The browser connects
//! directly to capability-authenticated coordinator and MPC-party WSS
//! endpoints; no Tauri command, loopback bridge, sidecar, or application
//! backend receives the values.

#![forbid(unsafe_code)]

use std::cell::Cell;

#[cfg(target_arch = "wasm32")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use stoffel_client_core::{ClientState, ParticipantClient, ParticipantConfig};
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use hpke::{kem::DhP256HkdfSha256, Kem, Serializable};

#[cfg(target_arch = "wasm32")]
type BrowserPrivateKey = <DhP256HkdfSha256 as Kem>::PrivateKey;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InitializationSummary<'a> {
    participant_id: &'a str,
    session_id: &'a str,
    client_slot: u8,
    node_count: usize,
    state: ClientState,
    transport_connected: bool,
    identity_public_key: &'a str,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmissionReceipt<'a> {
    session_id: &'a str,
    client_slot: u8,
    input_start_index: u64,
    input_count: u64,
    state: &'static str,
}

#[wasm_bindgen]
pub struct BrowserParticipantClient {
    inner: ParticipantClient,
    #[cfg(target_arch = "wasm32")]
    origin: String,
    identity_public_key: String,
    transport_connected: Cell<bool>,
    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    identity_private_key: BrowserPrivateKey,
}

#[wasm_bindgen]
impl BrowserParticipantClient {
    /// Validate configuration, capture the real page origin, and create an
    /// ephemeral P-256 HPKE identity from Web Crypto entropy.
    #[wasm_bindgen(js_name = initialize)]
    pub fn initialize(config: JsValue) -> Result<BrowserParticipantClient, JsValue> {
        let config: ParticipantConfig = serde_wasm_bindgen::from_value(config)
            .map_err(|error| js_error(format!("invalid participant config: {error}")))?;
        let inner = ParticipantClient::new(config).map_err(|error| js_error(error.to_string()))?;

        #[cfg(target_arch = "wasm32")]
        {
            let window = web_sys::window().ok_or_else(|| js_error("window is unavailable"))?;
            let origin = window
                .location()
                .origin()
                .map_err(|_| js_error("page origin is unavailable"))?;
            let crypto = window
                .crypto()
                .map_err(|_| js_error("Web Crypto is unavailable"))?;
            let mut seed = [0_u8; 32];
            crypto
                .get_random_values_with_u8_array(&mut seed)
                .map_err(|_| js_error("Web Crypto failed to generate identity entropy"))?;
            let (identity_private_key, identity_public_key) =
                DhP256HkdfSha256::derive_keypair(&seed);
            seed.fill(0);
            let identity_public_key =
                URL_SAFE_NO_PAD.encode(identity_public_key.to_bytes().as_slice());
            return Ok(Self {
                inner,
                origin,
                identity_public_key,
                transport_connected: Cell::new(false),
                identity_private_key,
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = inner;
            Err(js_error(
                "BrowserParticipantClient can only initialize in wasm32 browser builds",
            ))
        }
    }

    #[wasm_bindgen(js_name = initializationSummary)]
    pub fn initialization_summary(&self) -> Result<JsValue, JsValue> {
        let config = self.inner.config();
        serde_wasm_bindgen::to_value(&InitializationSummary {
            participant_id: &config.participant_id,
            session_id: &config.session_id,
            client_slot: config.client_slot,
            node_count: config.nodes.len(),
            state: self.inner.state(),
            transport_connected: self.transport_connected.get(),
            identity_public_key: &self.identity_public_key,
        })
        .map_err(|error| js_error(error.to_string()))
    }

    /// Public HPKE identity to bind into the server-signed browser capability.
    /// The corresponding private key stays inside this WASM instance.
    #[wasm_bindgen(getter, js_name = identityPublicKey)]
    pub fn identity_public_key(&self) -> String {
        self.identity_public_key.clone()
    }

    #[wasm_bindgen(getter, js_name = transportConnected)]
    pub fn transport_connected(&self) -> bool {
        self.transport_connected.get()
    }

    /// Submit exactly four private nonnegative integers through the browser's
    /// direct MPC client path. The returned receipt is deliberately value-free.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = submitPrivateInputs)]
    pub async fn submit_private_inputs(
        &self,
        capability: String,
        inputs: JsValue,
    ) -> Result<JsValue, JsValue> {
        let inputs: [u64; 4] = serde_wasm_bindgen::from_value(inputs)
            .map_err(|error| js_error(format!("expected four private u64 inputs: {error}")))?;
        let reservation = transport::submit(self.inner.config(), &self.origin, &capability, inputs)
            .await
            .map_err(js_error)?;
        self.transport_connected.set(true);
        serde_wasm_bindgen::to_value(&SubmissionReceipt {
            session_id: &self.inner.config().session_id,
            client_slot: self.inner.config().client_slot,
            input_start_index: reservation.input_start_index,
            input_count: reservation.input_count,
            state: "submitted",
        })
        .map_err(|error| js_error(error.to_string()))
    }
}

fn js_error(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}

/// True only when executing in a browser global with `window` available.
#[wasm_bindgen(js_name = browserRuntimeAvailable)]
pub fn browser_runtime_available() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window().is_some()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}

#[cfg(target_arch = "wasm32")]
mod transport {
    use std::{collections::BTreeMap, time::Duration};

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use gloo_timers::future::TimeoutFuture;
    use jsonrpsee_core::{client::ClientT, rpc_params};
    use jsonrpsee_wasm_client::{Client, WasmClientBuilder};
    use serde::Deserialize;
    use stoffel_client_core::{
        bn254::{decode_robust_share, mask_u64_input, reconstruct_mask, RobustShare},
        ParticipantConfig,
    };

    #[derive(Clone, Debug, Deserialize)]
    pub struct BrowserInputReservation {
        pub input_start_index: u64,
        pub input_count: u64,
    }

    #[derive(Clone, Debug, Deserialize)]
    pub struct BrowserMaskShare {
        pub reserved_index: u64,
        pub share: String,
    }

    pub async fn submit(
        config: &ParticipantConfig,
        origin: &str,
        capability: &str,
        inputs: [u64; 4],
    ) -> Result<BrowserInputReservation, String> {
        validate_wss(&config.coordinator.url)?;
        for node in &config.nodes {
            validate_wss(&node.url)?;
        }

        let timeout = Duration::from_millis(config.request_timeout_ms.into());
        let coordinator = WasmClientBuilder::default()
            .request_timeout(timeout)
            .build(&config.coordinator.url)
            .await
            .map_err(|error| format!("coordinator WSS connection failed: {error}"))?;
        let reservation: BrowserInputReservation = coordinator
            .request(
                "browser_reserve_input_range",
                rpc_params![capability, origin],
            )
            .await
            .map_err(|error| format!("input-range reservation failed: {error}"))?;
        if reservation.input_count != inputs.len() as u64 {
            return Err(format!(
                "capability reserved {} inputs, browser requires {}",
                reservation.input_count,
                inputs.len()
            ));
        }

        let mut parties: Vec<Client> = Vec::with_capacity(config.nodes.len());
        for node in &config.nodes {
            parties.push(
                WasmClientBuilder::default()
                    .request_timeout(timeout)
                    .build(&node.url)
                    .await
                    .map_err(|error| format!("party WSS connection failed: {error}"))?,
            );
        }

        let masks = poll_masks(
            &parties,
            capability,
            origin,
            reservation.input_start_index,
            reservation.input_count,
            config.request_timeout_ms,
        )
        .await?;
        let mut masked_inputs = Vec::with_capacity(inputs.len());
        for (input, mask) in inputs.into_iter().zip(masks.iter()) {
            let bytes = mask_u64_input(input, mask)
                .map_err(|error| format!("input masking failed: {error}"))?;
            masked_inputs.push(URL_SAFE_NO_PAD.encode(bytes));
        }
        coordinator
            .request::<(), _>(
                "browser_submit_masked_inputs",
                rpc_params![capability, origin, masked_inputs],
            )
            .await
            .map_err(|error| format!("masked-input submission failed: {error}"))?;
        Ok(reservation)
    }

    async fn poll_masks(
        parties: &[Client],
        capability: &str,
        origin: &str,
        input_start: u64,
        input_count: u64,
        timeout_ms: u32,
    ) -> Result<Vec<ark_bn254::Fr>, String> {
        let deadline = js_sys::Date::now() + f64::from(timeout_ms);
        loop {
            let mut grouped: BTreeMap<u64, Vec<RobustShare>> = BTreeMap::new();
            let mut every_party_ready = true;
            for party in parties {
                let response: Option<Vec<BrowserMaskShare>> = party
                    .request(
                        "browser_obtain_mask_shares",
                        rpc_params![capability, origin],
                    )
                    .await
                    .map_err(|error| format!("mask-share request failed: {error}"))?;
                let Some(shares) = response else {
                    every_party_ready = false;
                    continue;
                };
                for share in shares {
                    let end = input_start
                        .checked_add(input_count)
                        .ok_or_else(|| "reserved input range overflowed".to_owned())?;
                    if share.reserved_index < input_start || share.reserved_index >= end {
                        return Err(
                            "party returned a mask share outside the capability range".into()
                        );
                    }
                    let bytes = URL_SAFE_NO_PAD
                        .decode(share.share)
                        .map_err(|_| "party returned invalid base64url mask bytes".to_owned())?;
                    let decoded = decode_robust_share(&bytes).map_err(|error| {
                        format!("party returned an invalid mask share: {error}")
                    })?;
                    grouped
                        .entry(share.reserved_index)
                        .or_default()
                        .push(decoded);
                }
            }

            if every_party_ready && grouped.len() == input_count as usize {
                let mut masks = Vec::with_capacity(input_count as usize);
                for index in input_start..input_start + input_count {
                    let shares = grouped
                        .remove(&index)
                        .ok_or_else(|| format!("mask share set for index {index} is missing"))?;
                    masks.push(reconstruct_mask(&shares, parties.len()).map_err(|error| {
                        format!("mask reconstruction for index {index} failed: {error}")
                    })?);
                }
                return Ok(masks);
            }
            if js_sys::Date::now() >= deadline {
                return Err("timed out waiting for assigned mask shares".into());
            }
            TimeoutFuture::new(50).await;
        }
    }

    fn validate_wss(url: &str) -> Result<(), String> {
        if url.starts_with("wss://") {
            Ok(())
        } else {
            Err("browser MPC endpoints must use wss://".to_owned())
        }
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod browser_tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn initializes_with_ephemeral_browser_identity() {
        let config = js_sys::JSON::parse(
            r#"{
                "participantId":"browser-1",
                "sessionId":"session-1",
                "clientSlot":0,
                "coordinator":{"role":"coordinator","url":"wss://coordinator.example.test/mpc"},
                "nodes":[{"role":"node","url":"wss://node.example.test/mpc"}],
                "requestTimeoutMs":30000
            }"#,
        )
        .unwrap();
        let first = BrowserParticipantClient::initialize(config.clone()).unwrap();
        let second = BrowserParticipantClient::initialize(config).unwrap();
        assert!(browser_runtime_available());
        assert!(!first.transport_connected());
        assert!(!first.identity_public_key().is_empty());
        assert_ne!(first.identity_public_key(), second.identity_public_key());
    }
}
