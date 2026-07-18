use stoffel::prelude::*;

#[test]
fn public_server_api_expresses_three_clients_with_four_inputs_each() -> stoffel::Result<()> {
    let topology = ClientInputTopology::new([0, 1, 2], 4)?;
    let server = StoffelServer::builder(0)
        .bind("127.0.0.1:1")
        .expected_clients(3)
        .client_input_topology(topology.clone())
        .build()?;

    assert_eq!(topology.client_count(), 3);
    assert_eq!(topology.total_input_count(), 12);
    assert_eq!(topology.inputs_per_client(), 4);
    assert_eq!(topology.client_slots().collect::<Vec<_>>(), vec![0, 1, 2]);
    assert_eq!(server.client_input_topology(), &topology);
    assert_eq!(server.summary().client_input_topology, topology);
    Ok(())
}

#[test]
fn topology_rejects_duplicate_invalid_and_mismatched_layouts() {
    assert!(ClientInputTopology::new([0, 0], 4).is_err());
    assert!(ClientInputTopology::new([0], 0).is_err());

    let mismatch = StoffelServer::builder(0)
        .bind("127.0.0.1:1")
        .expected_clients(3)
        .client_input_topology(ClientInputTopology::new([0, 1], 4).unwrap())
        .build()
        .unwrap_err();
    assert!(mismatch.to_string().contains("contains 2 slots"));

    let invalid_slot = StoffelServer::builder(0)
        .bind("127.0.0.1:1")
        .expected_clients(3)
        .client_input_topology(ClientInputTopology::new([0, 1, 3], 4).unwrap())
        .build()
        .unwrap_err();
    assert!(invalid_slot
        .to_string()
        .contains("outside the expected client roster"));
}

#[test]
fn expected_clients_keeps_legacy_one_input_per_client_default() -> stoffel::Result<()> {
    let server = StoffelServer::builder(0)
        .bind("127.0.0.1:1")
        .expected_clients(3)
        .build()?;

    assert_eq!(
        server
            .client_input_topology()
            .client_slots()
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(server.client_input_topology().total_input_count(), 3);
    assert_eq!(server.client_input_topology().inputs_per_client(), 1);
    Ok(())
}
