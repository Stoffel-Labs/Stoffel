use std::future::{ready, Ready};

use stoffel_client_core::{
    ClientState, EndpointRole, ParticipantClient, ParticipantConfig, ParticipantEndpoint,
    ProtocolRequest, ProtocolResponse, SensitivePayload, Transport,
};

fn valid_config() -> ParticipantConfig {
    ParticipantConfig {
        participant_id: "browser-7".to_owned(),
        session_id: "session-42".to_owned(),
        coordinator: ParticipantEndpoint::new(
            EndpointRole::Coordinator,
            "wss://coordinator.example.test/mpc",
        ),
        nodes: vec![ParticipantEndpoint::new(
            EndpointRole::Node,
            "wss://node-0.example.test/mpc",
        )],
        request_timeout_ms: 30_000,
    }
}

#[test]
fn validates_browser_addressable_participant_configuration() {
    valid_config().validate().unwrap();

    let mut duplicate = valid_config();
    duplicate.nodes.push(duplicate.nodes[0].clone());
    assert!(duplicate
        .validate()
        .unwrap_err()
        .to_string()
        .contains("duplicate"));

    let mut native_socket = valid_config();
    native_socket.nodes[0].url = "127.0.0.1:9000".to_owned();
    assert!(native_socket
        .validate()
        .unwrap_err()
        .to_string()
        .contains("absolute http(s) or ws(s) URL"));
}

#[test]
fn state_changes_only_after_transport_is_explicitly_marked_ready() {
    let mut client = ParticipantClient::new(valid_config()).unwrap();
    assert_eq!(client.state(), ClientState::Initialized);
    assert!(client
        .protocol_request(
            EndpointRole::Coordinator,
            SensitivePayload::new(vec![1, 2, 3]),
        )
        .is_err());

    client.mark_transport_ready();
    assert_eq!(client.state(), ClientState::TransportReady);
    let request = client
        .protocol_request(
            EndpointRole::Coordinator,
            SensitivePayload::new(vec![1, 2, 3]),
        )
        .unwrap();
    assert_eq!(request.payload().as_bytes(), &[1, 2, 3]);
}

#[test]
fn sensitive_payload_debug_never_prints_bytes() {
    let payload = SensitivePayload::new(b"private-value".to_vec());
    let rendered = format!("{payload:?}");
    assert!(!rendered.contains("private-value"));
    assert!(rendered.contains("REDACTED"));
}

struct EchoTransport;

impl Transport for EchoTransport {
    type Error = &'static str;
    type Exchange<'a> = Ready<Result<ProtocolResponse, Self::Error>>;

    fn exchange<'a>(&'a self, request: ProtocolRequest) -> Self::Exchange<'a> {
        ready(Ok(ProtocolResponse::new(request.into_payload())))
    }
}

#[test]
fn transport_contract_carries_opaque_protocol_bytes_without_claiming_submission() {
    let transport = EchoTransport;
    let request = ProtocolRequest::new(
        ParticipantEndpoint::new(EndpointRole::Node, "wss://node.example.test/rpc"),
        SensitivePayload::new(vec![9, 8, 7]),
        1_000,
    );
    let response = futures_executor::block_on(transport.exchange(request)).unwrap();
    assert_eq!(response.into_payload().into_bytes(), vec![9, 8, 7]);
}
