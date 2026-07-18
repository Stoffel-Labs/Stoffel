//! Minimal, portable codec and arithmetic for browser input masking.
//!
//! Stoffel's HoneyBadger shares are evaluations over an FFT domain. The wire
//! representation below deliberately mirrors only the serialized fields of
//! `stoffelcrypto::RobustShare<ark_bn254::Fr>`; it does not import the native
//! MPC stack.

use std::{collections::BTreeSet, fmt, marker::PhantomData};

use ark_bn254::Fr;
use ark_ff::{FftField, Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
struct WireRobustShare {
    share: [Fr; 1],
    id: usize,
    degree: usize,
    marker: PhantomData<fn()>,
}

/// The portable subset of a Stoffel robust share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RobustShare {
    pub value: Fr,
    pub id: usize,
    pub degree: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidCanonicalShare,
    InvalidCanonicalField,
    EmptyShareSet,
    MixedDegree,
    DuplicateId(usize),
    ShareIdOutOfRange { id: usize, party_count: usize },
    TooFewShares { provided: usize, required: usize },
    InvalidPartyCount,
    InconsistentShare(usize),
    Serialization,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCanonicalShare => f.write_str("invalid canonical RobustShare bytes"),
            Self::InvalidCanonicalField => f.write_str("invalid canonical BN254 field bytes"),
            Self::EmptyShareSet => f.write_str("no mask shares were provided"),
            Self::MixedDegree => f.write_str("mask shares have mixed polynomial degrees"),
            Self::DuplicateId(id) => write!(f, "duplicate mask share id {id}"),
            Self::ShareIdOutOfRange { id, party_count } => write!(
                f,
                "mask share id {id} is out of range for {party_count} parties"
            ),
            Self::TooFewShares { provided, required } => write!(
                f,
                "too few mask shares: received {provided}, require {required}"
            ),
            Self::InvalidPartyCount => f.write_str("party count has no BN254 FFT domain"),
            Self::InconsistentShare(id) => {
                write!(f, "mask share {id} is inconsistent with the polynomial")
            }
            Self::Serialization => f.write_str("failed to serialize canonical BN254 bytes"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Decode exactly one canonical compressed Stoffel `RobustShare<Fr>`.
pub fn decode_robust_share(bytes: &[u8]) -> Result<RobustShare, CryptoError> {
    let mut remaining = bytes;
    let wire = WireRobustShare::deserialize_compressed(&mut remaining)
        .map_err(|_| CryptoError::InvalidCanonicalShare)?;
    if !remaining.is_empty() {
        return Err(CryptoError::InvalidCanonicalShare);
    }
    let mut canonical = Vec::new();
    wire.serialize_compressed(&mut canonical)
        .map_err(|_| CryptoError::Serialization)?;
    if canonical != bytes {
        return Err(CryptoError::InvalidCanonicalShare);
    }
    Ok(RobustShare {
        value: wire.share[0],
        id: wire.id,
        degree: wire.degree,
    })
}

fn fft_domain_size(party_count: usize) -> Result<usize, CryptoError> {
    let size = party_count
        .checked_next_power_of_two()
        .ok_or(CryptoError::InvalidPartyCount)?;
    Fr::get_root_of_unity(size as u64)
        .map(|_| size)
        .ok_or(CryptoError::InvalidPartyCount)
}

fn evaluation_point(id: usize, domain_size: usize) -> Result<Fr, CryptoError> {
    let generator =
        Fr::get_root_of_unity(domain_size as u64).ok_or(CryptoError::InvalidPartyCount)?;
    Ok(generator.pow([id as u64]))
}

/// Evaluate the unique polynomial through `basis` at `point` using Lagrange interpolation.
fn interpolate_at(basis: &[(Fr, Fr)], point: Fr) -> Fr {
    basis
        .iter()
        .enumerate()
        .fold(Fr::zero(), |sum, (j, &(xj, yj))| {
            let (numerator, denominator) = basis
                .iter()
                .enumerate()
                .filter(|(m, _)| *m != j)
                .fold((Fr::one(), Fr::one()), |(num, den), (_, &(xm, _))| {
                    (num * (point - xm), den * (xj - xm))
                });
            sum + yj * numerator * denominator.inverse().expect("distinct share ids")
        })
}

/// Reconstruct a mask at x=0 and reject every extra share that is not on the
/// same degree-d polynomial. `party_count` is the number used to create the
/// Stoffel FFT evaluation domain and is normally the number of party WSS URLs.
pub fn reconstruct_mask(shares: &[RobustShare], party_count: usize) -> Result<Fr, CryptoError> {
    let first = shares.first().ok_or(CryptoError::EmptyShareSet)?;
    let degree = first.degree;
    if shares.iter().any(|share| share.degree != degree) {
        return Err(CryptoError::MixedDegree);
    }
    let required = degree
        .checked_add(1)
        .ok_or(CryptoError::InvalidPartyCount)?;
    if shares.len() < required {
        return Err(CryptoError::TooFewShares {
            provided: shares.len(),
            required,
        });
    }
    if party_count < shares.len() {
        return Err(CryptoError::InvalidPartyCount);
    }
    let mut ids = BTreeSet::new();
    for share in shares {
        if share.id >= party_count {
            return Err(CryptoError::ShareIdOutOfRange {
                id: share.id,
                party_count,
            });
        }
        if !ids.insert(share.id) {
            return Err(CryptoError::DuplicateId(share.id));
        }
    }

    let domain_size = fft_domain_size(party_count)?;
    let mut ordered = shares.to_vec();
    ordered.sort_by_key(|share| share.id);
    let basis: Vec<_> = ordered[..required]
        .iter()
        .map(|share| evaluation_point(share.id, domain_size).map(|point| (point, share.value)))
        .collect::<Result<_, _>>()?;
    for share in &ordered[required..] {
        let point = evaluation_point(share.id, domain_size)?;
        if interpolate_at(&basis, point) != share.value {
            return Err(CryptoError::InconsistentShare(share.id));
        }
    }
    Ok(interpolate_at(&basis, Fr::zero()))
}

pub fn encode_field(value: &Fr) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|_| CryptoError::Serialization)?;
    Ok(bytes)
}

pub fn decode_field(bytes: &[u8]) -> Result<Fr, CryptoError> {
    let mut remaining = bytes;
    let value = Fr::deserialize_compressed(&mut remaining)
        .map_err(|_| CryptoError::InvalidCanonicalField)?;
    if !remaining.is_empty() || encode_field(&value)? != bytes {
        return Err(CryptoError::InvalidCanonicalField);
    }
    Ok(value)
}

/// Encode a nonnegative private integer as a canonical compressed BN254 scalar.
pub fn encode_u64_input(input: u64) -> Result<Vec<u8>, CryptoError> {
    encode_field(&Fr::from(input))
}

/// Add an input to a reconstructed mask and return canonical compressed bytes.
pub fn mask_u64_input(input: u64, mask: &Fr) -> Result<Vec<u8>, CryptoError> {
    encode_field(&(Fr::from(input) + mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_and_masked_values_are_canonical() {
        let encoded = encode_u64_input(u64::MAX).unwrap();
        assert_eq!(decode_field(&encoded).unwrap(), Fr::from(u64::MAX));

        let mask = Fr::from(99_u64);
        let masked = mask_u64_input(7, &mask).unwrap();
        assert_eq!(decode_field(&masked).unwrap(), Fr::from(106_u64));

        let mut trailing = masked;
        trailing.push(0);
        assert_eq!(
            decode_field(&trailing),
            Err(CryptoError::InvalidCanonicalField)
        );
    }
}
