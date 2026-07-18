use ark_bn254::Fr;
use ark_ff::Field;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::CanonicalSerialize;
use stoffel_client_core::bn254::{decode_robust_share, reconstruct_mask, CryptoError};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare as RealRobustShare;

fn real_shares(secret: Fr, coefficient: Fr, parties: usize) -> Vec<Vec<u8>> {
    let domain = GeneralEvaluationDomain::<Fr>::new(parties).unwrap();
    (0..parties)
        .map(|id| {
            let x = domain.element(id);
            let real = RealRobustShare::new(secret + coefficient * x, id, 1);
            let mut bytes = Vec::new();
            real.serialize_compressed(&mut bytes).unwrap();
            bytes
        })
        .collect()
}

#[test]
fn decodes_real_stoffelcrypto_bytes_and_reconstructs() {
    let secret = Fr::from(123_456_u64);
    let encoded = real_shares(secret, Fr::from(77_u64), 4);
    let shares: Vec<_> = encoded
        .iter()
        .map(|bytes| decode_robust_share(bytes).unwrap())
        .collect();
    assert_eq!(reconstruct_mask(&shares, 4).unwrap(), secret);
}

#[test]
fn rejects_malformed_duplicate_mixed_sparse_and_inconsistent_shares() {
    let encoded = real_shares(Fr::from(9_u64), Fr::from(2_u64), 4);
    let mut shares: Vec<_> = encoded
        .iter()
        .map(|bytes| decode_robust_share(bytes).unwrap())
        .collect();

    let mut trailing = encoded[0].clone();
    trailing.push(0);
    assert_eq!(
        decode_robust_share(&trailing),
        Err(CryptoError::InvalidCanonicalShare)
    );

    shares[1].id = shares[0].id;
    assert!(matches!(
        reconstruct_mask(&shares, 4),
        Err(CryptoError::DuplicateId(_))
    ));

    let mut shares: Vec<_> = encoded
        .iter()
        .map(|bytes| decode_robust_share(bytes).unwrap())
        .collect();
    shares[1].degree = 2;
    assert_eq!(reconstruct_mask(&shares, 4), Err(CryptoError::MixedDegree));

    let one = vec![decode_robust_share(&encoded[0]).unwrap()];
    assert!(matches!(
        reconstruct_mask(&one, 4),
        Err(CryptoError::TooFewShares { .. })
    ));

    let mut shares: Vec<_> = encoded
        .iter()
        .map(|bytes| decode_robust_share(bytes).unwrap())
        .collect();
    shares[3].value += Fr::ONE;
    assert!(matches!(
        reconstruct_mask(&shares, 4),
        Err(CryptoError::InconsistentShare(3))
    ));
}
