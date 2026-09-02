//! Browser-side cryptographic boundary for coordinator-mediated Stoffel client I/O.
//!
//! Network requests remain in JavaScript so browsers can use their native WebSocket
//! implementation. This crate owns every operation involving clear client values:
//! authenticating requests, reconstructing masks, masking inputs, decrypting output
//! shares, and reconstructing the final result.

use ark_bls12_381::Fr;
use ark_ff::{FftField, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{DhP256HkdfSha256, Kem},
    single_shot_open, Deserializable, OpModeR,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePrivateKey,
    SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;
use wasm_bindgen::prelude::*;

const AUTH_DOMAIN: &[u8] = b"stoffel-browser-rpc-auth-v1";
const OUTPUT_HPKE_DOMAIN: &[u8] = b"StoffelOutputShareEncryption";
const MAX_PARTIES: usize = 32;
const MAX_THRESHOLD: usize = 8;

type KemImpl = DhP256HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = AesGcm256;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid P-256 PKCS#8 private key")]
    InvalidPrivateKey,
    #[error("execution ID must contain exactly 64 hexadecimal characters")]
    InvalidExecutionId,
    #[error("unsupported topology n={n}, t={t}")]
    InvalidTopology { n: usize, t: usize },
    #[error("failed to deserialize a coordinator share")]
    InvalidShare,
    #[error("share set contains inconsistent metadata")]
    InconsistentShares,
    #[error("not enough valid shares to reconstruct a value")]
    InsufficientShares,
    #[error("failed to decrypt an output share")]
    OutputDecryption,
    #[error("output party returned {actual} values, expected {expected}")]
    OutputArity { expected: usize, actual: usize },
    #[error("field value is outside the signed 64-bit client range")]
    OutputRange,
    #[error("JavaScript value conversion failed: {0}")]
    Js(String),
}

impl From<ClientError> for JsValue {
    fn from(value: ClientError) -> Self {
        js_sys::Error::new(&value.to_string()).into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedBrowserRequest {
    pub public_key: Vec<u8>,
    pub nonce: u64,
    pub signature: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssignedMaskShare {
    pub reserved_index: u64,
    pub share_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaskedInput {
    pub reserved_index: u64,
    pub masked_input: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedOutputShare {
    pub encapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Canonical-serialization-compatible projection of HoneyBadger's
/// `RobustShare<F>`. The marker is zero-sized on the wire.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
struct RobustShare<F: FftField> {
    share: [F; 1],
    id: usize,
    degree: usize,
    marker: PhantomData<fn()>,
}

impl<F: FftField> RobustShare<F> {
    #[cfg(test)]
    fn new(value: F, id: usize, degree: usize) -> Self {
        Self {
            share: [value],
            id,
            degree,
            marker: PhantomData,
        }
    }
}

/// Stateful identity and topology used by one browser client.
#[wasm_bindgen]
pub struct StoffelWasmClient {
    signing_key: SigningKey,
    secret_key: SecretKey,
    public_key: Vec<u8>,
    parties: usize,
    threshold: usize,
}

#[wasm_bindgen]
impl StoffelWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        private_key_pkcs8: &[u8],
        parties: usize,
        threshold: usize,
    ) -> Result<Self, JsValue> {
        console_error_panic_hook::set_once();
        Self::from_pkcs8(private_key_pkcs8, parties, threshold).map_err(Into::into)
    }

    /// SEC1 uncompressed P-256 public key. This is the same byte string stored
    /// in the subjectPublicKey field of the existing demo client certificate.
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Produce the signed envelope expected by the browser RPC endpoints.
    pub fn sign_request(
        &self,
        method: &str,
        execution_id: &str,
        nonce: u64,
        body: &[u8],
    ) -> Result<JsValue, JsValue> {
        let execution_id = parse_execution_id(execution_id)?;
        let message = authentication_message(method, &execution_id, nonce, body);
        let signature: Signature = self.signing_key.sign(&message);
        let request = SignedBrowserRequest {
            public_key: self.public_key.clone(),
            nonce,
            signature: signature.to_bytes().to_vec(),
            body: body.to_vec(),
        };
        serde_wasm_bindgen::to_value(&request)
            .map_err(|error| ClientError::Js(error.to_string()).into())
    }

    /// Reconstruct one mask per input from independently fetched node shares,
    /// then return the serialized masked field values accepted by the coordinator.
    pub fn mask_inputs(
        &self,
        first_reserved_index: u64,
        clear_inputs: Box<[i64]>,
        node_responses: JsValue,
    ) -> Result<JsValue, JsValue> {
        let responses: Vec<Vec<AssignedMaskShare>> = serde_wasm_bindgen::from_value(node_responses)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let masked = self
            .mask_inputs_core(first_reserved_index, &clear_inputs, &responses)
            .map_err(JsValue::from)?;
        serde_wasm_bindgen::to_value(&masked)
            .map_err(|error| ClientError::Js(error.to_string()).into())
    }

    /// Decrypt and robustly reconstruct HoneyBadger output shares returned by
    /// the coordinator. Clear outputs exist only inside this WASM instance.
    pub fn decrypt_outputs(
        &self,
        execution_id: &str,
        output_count: usize,
        encrypted_shares: JsValue,
    ) -> Result<Box<[i64]>, JsValue> {
        let execution_id = parse_execution_id(execution_id)?;
        let encrypted: Vec<EncryptedOutputShare> = serde_wasm_bindgen::from_value(encrypted_shares)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        self.decrypt_outputs_core(&execution_id, output_count, &encrypted)
            .map(Vec::into_boxed_slice)
            .map_err(Into::into)
    }
}

impl StoffelWasmClient {
    pub fn from_pkcs8(
        private_key_pkcs8: &[u8],
        parties: usize,
        threshold: usize,
    ) -> Result<Self, ClientError> {
        validate_topology(parties, threshold)?;
        let secret_key = SecretKey::from_pkcs8_der(private_key_pkcs8)
            .map_err(|_| ClientError::InvalidPrivateKey)?;
        Self::from_secret_key(secret_key, parties, threshold)
    }

    fn from_secret_key(
        secret_key: SecretKey,
        parties: usize,
        threshold: usize,
    ) -> Result<Self, ClientError> {
        validate_topology(parties, threshold)?;
        let signing_key = SigningKey::from(secret_key.clone());
        let public_key = secret_key
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Ok(Self {
            signing_key,
            secret_key,
            public_key,
            parties,
            threshold,
        })
    }

    fn mask_inputs_core(
        &self,
        first_reserved_index: u64,
        clear_inputs: &[i64],
        node_responses: &[Vec<AssignedMaskShare>],
    ) -> Result<Vec<MaskedInput>, ClientError> {
        let mut shares_by_index: BTreeMap<u64, Vec<RobustShare<Fr>>> = BTreeMap::new();
        for response in node_responses {
            for assigned in response {
                let share =
                    RobustShare::<Fr>::deserialize_compressed(assigned.share_bytes.as_slice())
                        .map_err(|_| ClientError::InvalidShare)?;
                shares_by_index
                    .entry(assigned.reserved_index)
                    .or_default()
                    .push(share);
            }
        }

        clear_inputs
            .iter()
            .enumerate()
            .map(|(offset, clear)| {
                let reserved_index = first_reserved_index
                    .checked_add(offset as u64)
                    .ok_or(ClientError::OutputRange)?;
                let shares = shares_by_index
                    .get(&reserved_index)
                    .ok_or(ClientError::InsufficientShares)?;
                let mask = recover_robust_secret(shares, self.parties, self.threshold)?;
                let value = field_from_i64(*clear) + mask;
                let mut masked_input = Vec::new();
                value
                    .serialize_compressed(&mut masked_input)
                    .map_err(|_| ClientError::InvalidShare)?;
                Ok(MaskedInput {
                    reserved_index,
                    masked_input,
                })
            })
            .collect()
    }

    fn decrypt_outputs_core(
        &self,
        execution_id: &[u8; 32],
        output_count: usize,
        encrypted_shares: &[EncryptedOutputShare],
    ) -> Result<Vec<i64>, ClientError> {
        let raw_secret = self.secret_key.to_bytes();
        let hpke_secret = <KemImpl as Kem>::PrivateKey::from_bytes(&raw_secret)
            .map_err(|_| ClientError::InvalidPrivateKey)?;
        let info = output_encryption_info(execution_id);
        let mut by_output = vec![Vec::<RobustShare<Fr>>::new(); output_count];

        for encrypted in encrypted_shares {
            let encapped = <KemImpl as Kem>::EncappedKey::from_bytes(&encrypted.encapped_key)
                .map_err(|_| ClientError::OutputDecryption)?;
            let plaintext = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                &OpModeR::Base,
                &hpke_secret,
                &encapped,
                &info,
                &encrypted.ciphertext,
                b"",
            )
            .map_err(|_| ClientError::OutputDecryption)?;
            let shares = Vec::<RobustShare<Fr>>::deserialize_compressed(plaintext.as_slice())
                .map_err(|_| ClientError::InvalidShare)?;
            if shares.len() != output_count {
                return Err(ClientError::OutputArity {
                    expected: output_count,
                    actual: shares.len(),
                });
            }
            for (index, share) in shares.into_iter().enumerate() {
                by_output[index].push(share);
            }
        }

        by_output
            .iter()
            .map(|shares| recover_robust_secret(shares, self.parties, self.threshold))
            .map(|result| result.and_then(field_to_i64))
            .collect()
    }
}

pub fn authentication_message(
    method: &str,
    execution_id: &[u8; 32],
    nonce: u64,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut message = Vec::with_capacity(AUTH_DOMAIN.len() + method.len() + 1 + 32 + 8 + 32);
    message.extend_from_slice(AUTH_DOMAIN);
    message.push(0);
    message.extend_from_slice(method.as_bytes());
    message.push(0);
    message.extend_from_slice(execution_id);
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(&body_hash);
    message
}

fn output_encryption_info(execution_id: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(OUTPUT_HPKE_DOMAIN.len() + execution_id.len());
    info.extend_from_slice(OUTPUT_HPKE_DOMAIN);
    info.extend_from_slice(execution_id);
    info
}

fn validate_topology(n: usize, t: usize) -> Result<(), ClientError> {
    if n == 0 || n > MAX_PARTIES || t == 0 || t > MAX_THRESHOLD || n < 3 * t + 1 {
        return Err(ClientError::InvalidTopology { n, t });
    }
    Ok(())
}

fn parse_execution_id(value: &str) -> Result<[u8; 32], ClientError> {
    if value.len() != 64 {
        return Err(ClientError::InvalidExecutionId);
    }
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ClientError::InvalidExecutionId)
}

fn field_from_i64(value: i64) -> Fr {
    if value >= 0 {
        Fr::from(value as u64)
    } else {
        -Fr::from(value.unsigned_abs())
    }
}

fn field_to_i64(value: Fr) -> Result<i64, ClientError> {
    let bigint = value.into_bigint();
    let negated = (-value).into_bigint();
    let to_u64 = |number: &<Fr as PrimeField>::BigInt| {
        let limbs = number.as_ref();
        limbs
            .iter()
            .skip(1)
            .all(|limb| *limb == 0)
            .then(|| limbs.first().copied().unwrap_or(0))
    };
    if !value.is_zero() && negated < bigint {
        let magnitude = to_u64(&negated).ok_or(ClientError::OutputRange)?;
        if magnitude == 1u64 << 63 {
            Ok(i64::MIN)
        } else {
            i64::try_from(magnitude)
                .map(|magnitude| -magnitude)
                .map_err(|_| ClientError::OutputRange)
        }
    } else {
        to_u64(&bigint)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(ClientError::OutputRange)
    }
}

fn recover_robust_secret(
    shares: &[RobustShare<Fr>],
    n: usize,
    t: usize,
) -> Result<Fr, ClientError> {
    if shares.is_empty() {
        return Err(ClientError::InsufficientShares);
    }
    let degree = shares[0].degree;
    if degree > t
        || shares
            .iter()
            .any(|share| share.degree != degree || share.id >= n)
    {
        return Err(ClientError::InconsistentShares);
    }
    let mut ids = HashSet::new();
    if shares.iter().any(|share| !ids.insert(share.id)) {
        return Err(ClientError::InconsistentShares);
    }
    let required = degree + t + 1;
    if shares.len() < required {
        return Err(ClientError::InsufficientShares);
    }
    let domain =
        Radix2EvaluationDomain::<Fr>::new(n).ok_or(ClientError::InvalidTopology { n, t })?;
    let subset_size = degree + 1;
    let mut best: Option<(usize, Fr)> = None;
    for_each_combination(shares.len(), subset_size, |indices| {
        let points = indices
            .iter()
            .map(|index| (domain.element(shares[*index].id), shares[*index].share[0]))
            .collect::<Vec<_>>();
        let secret = lagrange_evaluate(&points, Fr::zero());
        let agreement = shares
            .iter()
            .filter(|share| lagrange_evaluate(&points, domain.element(share.id)) == share.share[0])
            .count();
        if best.is_none_or(|(best_agreement, _)| agreement > best_agreement) {
            best = Some((agreement, secret));
        }
    });
    match best {
        Some((agreement, secret)) if agreement >= required => Ok(secret),
        _ => Err(ClientError::InsufficientShares),
    }
}

fn lagrange_evaluate(points: &[(Fr, Fr)], at: Fr) -> Fr {
    points
        .iter()
        .enumerate()
        .fold(Fr::zero(), |sum, (j, (xj, yj))| {
            let basis = points
                .iter()
                .enumerate()
                .filter(|(m, _)| *m != j)
                .fold(Fr::from(1u64), |product, (_, (xm, _))| {
                    product * (at - xm) / (*xj - *xm)
                });
            sum + (*yj * basis)
        })
}

fn for_each_combination(n: usize, k: usize, mut visit: impl FnMut(&[usize])) {
    if k == 0 || k > n {
        return;
    }
    let mut indices = (0..k).collect::<Vec<_>>();
    loop {
        visit(&indices);
        let mut position = k;
        while position > 0 {
            position -= 1;
            if indices[position] != position + n - k {
                break;
            }
        }
        if position == 0 && indices[0] == n - k {
            break;
        }
        indices[position] += 1;
        for next in position + 1..k {
            indices[next] = indices[next - 1] + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{single_shot_seal, OpModeS, Serializable};
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    use rand::{rngs::StdRng, SeedableRng};
    use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare as ProtocolRobustShare;

    fn shares(secret: Fr, n: usize, degree: usize) -> Vec<RobustShare<Fr>> {
        let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
        let slope = Fr::from(19u64);
        (0..n)
            .map(|id| {
                let x = domain.element(id);
                RobustShare::new(secret + slope * x, id, degree)
            })
            .collect()
    }

    #[test]
    fn reconstructs_with_one_corrupt_share() {
        let secret = field_from_i64(-41);
        let mut values = shares(secret, 5, 1);
        values[4].share[0] += Fr::from(7u64);
        assert_eq!(recover_robust_secret(&values, 5, 1).unwrap(), secret);
    }

    #[test]
    fn canonical_share_projection_round_trips() {
        let share = shares(Fr::from(9u64), 5, 1).remove(0);
        let mut bytes = Vec::new();
        share.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(
            RobustShare::<Fr>::deserialize_compressed(bytes.as_slice()).unwrap(),
            share
        );
    }

    #[test]
    fn canonical_share_projection_matches_the_protocol_type() {
        let protocol_share = ProtocolRobustShare::new(Fr::from(29u64), 3, 1);
        let mut bytes = Vec::new();
        protocol_share.serialize_compressed(&mut bytes).unwrap();

        let projected = RobustShare::<Fr>::deserialize_compressed(bytes.as_slice()).unwrap();
        assert_eq!(projected.share, protocol_share.share);
        assert_eq!(projected.id, protocol_share.id);
        assert_eq!(projected.degree, protocol_share.degree);

        let mut projected_bytes = Vec::new();
        projected
            .serialize_compressed(&mut projected_bytes)
            .unwrap();
        let decoded =
            ProtocolRobustShare::<Fr>::deserialize_compressed(projected_bytes.as_slice()).unwrap();
        assert_eq!(decoded, protocol_share);
    }

    #[test]
    fn decrypts_protocol_output_batches_with_the_coordinator_domain() {
        let secret_key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let client = StoffelWasmClient::from_secret_key(secret_key, 5, 1).unwrap();
        let execution_id = [0x42; 32];
        let hpke_public = <KemImpl as Kem>::PublicKey::from_bytes(&client.public_key).unwrap();
        let domain = Radix2EvaluationDomain::<Fr>::new(5).unwrap();
        let expected = [17i64, -9, 120, 3];
        let mut encrypted = Vec::new();
        let mut rng = StdRng::seed_from_u64(41);

        for party_id in 0..3 {
            let x = domain.element(party_id);
            let shares = expected
                .iter()
                .enumerate()
                .map(|(output, value)| {
                    let evaluation = field_from_i64(*value) + Fr::from((output + 5) as u64) * x;
                    ProtocolRobustShare::new(evaluation, party_id, 1)
                })
                .collect::<Vec<_>>();
            let mut plaintext = Vec::new();
            shares.serialize_compressed(&mut plaintext).unwrap();
            let (encapped_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
                &OpModeS::Base,
                &hpke_public,
                &output_encryption_info(&execution_id),
                &plaintext,
                b"",
                &mut rng,
            )
            .unwrap();
            encrypted.push(EncryptedOutputShare {
                encapped_key: encapped_key.to_bytes().to_vec(),
                ciphertext,
            });
        }

        assert_eq!(
            client
                .decrypt_outputs_core(&execution_id, expected.len(), &encrypted)
                .unwrap(),
            expected
        );
    }

    #[test]
    fn authentication_message_is_signed_by_the_client_identity() {
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let client = StoffelWasmClient::from_secret_key(secret, 5, 1).unwrap();
        let execution = [3u8; 32];
        let message = authentication_message("browser_round", &execution, 4, b"body");
        let signature: Signature = client.signing_key.sign(&message);
        let verifier = VerifyingKey::from_sec1_bytes(&client.public_key).unwrap();
        verifier.verify(&message, &signature).unwrap();
    }

    #[test]
    fn signed_field_values_decode_both_directions() {
        for expected in [i64::MIN, -100, -1, 0, 1, 100, i64::MAX] {
            assert_eq!(field_to_i64(field_from_i64(expected)).unwrap(), expected);
        }
    }
}
