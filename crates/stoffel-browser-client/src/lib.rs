//! Browser/WASM initialization boundary for a Stoffel participant.
//!
//! This gate validates participant configuration and creates portable client
//! state. It intentionally does **not** claim to connect or submit: a browser
//! transport and browser-compatible identity protocol still need to implement
//! `stoffel_client_core::Transport` against the deployed coordinator/node wire
//! protocol.

#![forbid(unsafe_code)]

use serde::Serialize;
use stoffel_client_core::{ClientState, ParticipantClient, ParticipantConfig};
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InitializationSummary<'a> {
    participant_id: &'a str,
    session_id: &'a str,
    node_count: usize,
    state: ClientState,
    transport_connected: bool,
}

#[wasm_bindgen]
pub struct BrowserParticipantClient {
    inner: ParticipantClient,
}

#[wasm_bindgen]
impl BrowserParticipantClient {
    /// Validate JS configuration and initialize Rust/WASM participant state.
    /// No network connection is made by this method.
    #[wasm_bindgen(js_name = initialize)]
    pub fn initialize(config: JsValue) -> Result<BrowserParticipantClient, JsValue> {
        let config: ParticipantConfig = serde_wasm_bindgen::from_value(config)
            .map_err(|error| JsValue::from_str(&format!("invalid participant config: {error}")))?;
        let inner = ParticipantClient::new(config)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = initializationSummary)]
    pub fn initialization_summary(&self) -> Result<JsValue, JsValue> {
        let config = self.inner.config();
        serde_wasm_bindgen::to_value(&InitializationSummary {
            participant_id: &config.participant_id,
            session_id: &config.session_id,
            node_count: config.nodes.len(),
            state: self.inner.state(),
            transport_connected: false,
        })
        .map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen(getter, js_name = transportConnected)]
    pub fn transport_connected(&self) -> bool {
        false
    }
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

#[cfg(all(test, target_arch = "wasm32"))]
mod browser_tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn initializes_in_browser_without_claiming_transport() {
        let config = js_sys::JSON::parse(
            r#"{
                "participantId":"browser-1",
                "sessionId":"session-1",
                "coordinator":{"role":"coordinator","url":"wss://coordinator.example.test/mpc"},
                "nodes":[{"role":"node","url":"wss://node.example.test/mpc"}],
                "requestTimeoutMs":30000
            }"#,
        )
        .unwrap();
        let client = BrowserParticipantClient::initialize(config).unwrap();
        assert!(browser_runtime_available());
        assert!(!client.transport_connected());
    }
}
