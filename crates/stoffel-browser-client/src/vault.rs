use aes_gcm::{aead::Aead, aead::Payload, Aes128Gcm, KeyInit};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use hpke::{
    aead::AesGcm128, kdf::HkdfSha256, kem::DhP256HkdfSha256, setup_sender, Deserializable, Kem,
    OpModeS, Serializable,
};
use js_sys::{Array, Object, Reflect, Uint8Array};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

pub type PublicKey = <DhP256HkdfSha256 as Kem>::PublicKey;

const USER_STATE_VERSION: u8 = 1;
const HPKE_KEM: &str = "DHKEM(P-256,HKDF-SHA256)";
const HPKE_KDF: &str = "HKDF-SHA256";
const HPKE_AEAD: &str = "AES-128-GCM";
const USER_STATE_INFO: &[u8] = b"stoffel-browser-user-state/v1";
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x10";
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x01";
const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";

fn hpke_rng() -> Result<ChaCha20Rng, JsValue> {
    use hpke::rand_core::SeedableRng;

    let window = web_sys::window().ok_or_else(|| JsValue::from_str("window is unavailable"))?;
    let crypto = window
        .crypto()
        .map_err(|_| JsValue::from_str("Web Crypto is unavailable"))?;
    let mut seed = [0_u8; 32];
    crypto
        .get_random_values_with_u8_array(&mut seed)
        .map_err(|_| JsValue::from_str("Web Crypto randomness is unavailable"))?;
    let rng = ChaCha20Rng::from_seed(seed);
    seed.fill(0);
    Ok(rng)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UserStateEnvelope {
    version: u8,
    kem: String,
    kdf: String,
    aead: String,
    encapsulated_key: String,
    ciphertext: String,
}

fn subtle_crypto() -> Result<SubtleCrypto, JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("window is unavailable"))?;
    Ok(window
        .crypto()
        .map_err(|_| JsValue::from_str("Web Crypto is unavailable"))?
        .subtle())
}

fn ecdh_algorithm() -> Result<Object, JsValue> {
    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"ECDH".into())?;
    Reflect::set(&algorithm, &"namedCurve".into(), &"P-256".into())?;
    Ok(algorithm)
}

fn derive_algorithm(public_key: &CryptoKey) -> Result<Object, JsValue> {
    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"ECDH".into())?;
    Reflect::set(&algorithm, &"public".into(), public_key.as_ref())?;
    Ok(algorithm)
}

fn empty_usages() -> Array {
    Array::new()
}

fn derive_bits_usages() -> Array {
    let usages = Array::new();
    usages.push(&"deriveBits".into());
    usages
}

pub fn public_key_string(public_key: &PublicKey) -> String {
    URL_SAFE_NO_PAD.encode(public_key.to_bytes().as_slice())
}

pub fn parse_public_key(encoded: &str) -> Result<PublicKey, JsValue> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| JsValue::from_str("identity public key is not valid base64url"))?;
    PublicKey::from_bytes(&bytes)
        .map_err(|_| JsValue::from_str("identity public key is not a valid P-256 point"))
}

async fn import_public_key(raw: &[u8]) -> Result<CryptoKey, JsValue> {
    let raw = Uint8Array::from(raw);
    let promise = subtle_crypto()?
        .import_key_with_object(
            "raw",
            raw.as_ref(),
            &ecdh_algorithm()?,
            true,
            empty_usages().as_ref(),
        )
        .map_err(|_| JsValue::from_str("identity public-key import failed"))?;
    JsFuture::from(promise)
        .await
        .map_err(|_| JsValue::from_str("identity public-key import failed"))?
        .dyn_into()
        .map_err(|_| JsValue::from_str("identity public-key import returned no CryptoKey"))
}

pub async fn generate_identity() -> Result<(CryptoKey, PublicKey), JsValue> {
    let promise = subtle_crypto()?
        .generate_key_with_object(&ecdh_algorithm()?, false, derive_bits_usages().as_ref())
        .map_err(|_| JsValue::from_str("Web Crypto failed to generate P-256 identity"))?;
    let pair = JsFuture::from(promise)
        .await
        .map_err(|_| JsValue::from_str("Web Crypto failed to generate P-256 identity"))?;
    let private_key: CryptoKey = Reflect::get(&pair, &"privateKey".into())?
        .dyn_into()
        .map_err(|_| JsValue::from_str("Web Crypto returned no private identity key"))?;
    let public_key: CryptoKey = Reflect::get(&pair, &"publicKey".into())?
        .dyn_into()
        .map_err(|_| JsValue::from_str("Web Crypto returned no public identity key"))?;
    let exported = JsFuture::from(
        subtle_crypto()?
            .export_key("raw", &public_key)
            .map_err(|_| JsValue::from_str("identity public-key export failed"))?,
    )
    .await
    .map_err(|_| JsValue::from_str("identity public-key export failed"))?;
    let public_key = PublicKey::from_bytes(&Uint8Array::new(&exported).to_vec())
        .map_err(|_| JsValue::from_str("Web Crypto generated an invalid P-256 public key"))?;
    validate_identity(&private_key, &public_key).await?;
    Ok((private_key, public_key))
}

pub fn identity_value(private_key: &CryptoKey, public_key: &PublicKey) -> Result<JsValue, JsValue> {
    let identity = Object::new();
    Reflect::set(&identity, &"privateKey".into(), private_key.as_ref())?;
    Reflect::set(
        &identity,
        &"publicKey".into(),
        &JsValue::from_str(&public_key_string(public_key)),
    )?;
    Ok(identity.into())
}

pub fn identity_parts(identity: JsValue) -> Result<(CryptoKey, PublicKey), JsValue> {
    if !identity.is_object() || identity.is_null() {
        return Err(JsValue::from_str("persistent identity must be an object"));
    }
    let private_key = Reflect::get(&identity, &"privateKey".into())?
        .dyn_into::<CryptoKey>()
        .map_err(|_| JsValue::from_str("persistent identity privateKey must be a CryptoKey"))?;
    let public_key = Reflect::get(&identity, &"publicKey".into())?
        .as_string()
        .ok_or_else(|| JsValue::from_str("persistent identity publicKey must be a string"))?;
    Ok((private_key, parse_public_key(&public_key)?))
}

pub async fn validate_identity(
    private_key: &CryptoKey,
    public_key: &PublicKey,
) -> Result<(), JsValue> {
    if private_key.extractable() {
        return Err(JsValue::from_str(
            "identity private key must be non-extractable",
        ));
    }
    if private_key.type_() != "private" {
        return Err(JsValue::from_str(
            "identity private key must be a private key",
        ));
    }
    let algorithm = private_key.algorithm()?;
    let name = Reflect::get(&algorithm, &"name".into())?
        .as_string()
        .unwrap_or_default();
    let curve = Reflect::get(&algorithm, &"namedCurve".into())?
        .as_string()
        .unwrap_or_default();
    if name != "ECDH" || curve != "P-256" {
        return Err(JsValue::from_str(
            "identity private key must use Web Crypto ECDH P-256",
        ));
    }
    if !private_key
        .usages()
        .iter()
        .any(|usage| usage.as_string().as_deref() == Some("deriveBits"))
    {
        return Err(JsValue::from_str(
            "identity private key must allow deriveBits",
        ));
    }

    // Prove that the non-extractable private key corresponds to the supplied
    // public point. Derive one secret in each direction against a temporary
    // non-extractable key pair and compare them. Only ECDH shared secrets are
    // materialized; private-key bytes never are.
    let supplied_public_key = import_public_key(public_key.to_bytes().as_slice()).await?;
    let temporary = JsFuture::from(
        subtle_crypto()?
            .generate_key_with_object(&ecdh_algorithm()?, false, derive_bits_usages().as_ref())
            .map_err(|_| JsValue::from_str("identity ECDH validation failed"))?,
    )
    .await
    .map_err(|_| JsValue::from_str("identity ECDH validation failed"))?;
    let temporary_private: CryptoKey =
        Reflect::get(&temporary, &"privateKey".into())?
            .dyn_into()
            .map_err(|_| JsValue::from_str("identity ECDH validation failed"))?;
    let temporary_public: CryptoKey = Reflect::get(&temporary, &"publicKey".into())?
        .dyn_into()
        .map_err(|_| JsValue::from_str("identity ECDH validation failed"))?;
    let left = derive_bits(private_key, &temporary_public).await?;
    let right = derive_bits(&temporary_private, &supplied_public_key).await?;
    if left.len() != 32 || left != right {
        return Err(JsValue::from_str("identity ECDH validation failed"));
    }
    Ok(())
}

async fn derive_bits(private_key: &CryptoKey, public_key: &CryptoKey) -> Result<Vec<u8>, JsValue> {
    let promise = subtle_crypto()?
        .derive_bits_with_object(&derive_algorithm(public_key)?, private_key, 256)
        .map_err(|_| JsValue::from_str("identity ECDH derivation failed"))?;
    let derived = JsFuture::from(promise)
        .await
        .map_err(|_| JsValue::from_str("identity ECDH derivation failed"))?;
    Ok(Uint8Array::new(&derived).to_vec())
}

pub fn seal_user_state(
    public_key: &PublicKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<JsValue, JsValue> {
    if aad.is_empty() {
        return Err(JsValue::from_str(
            "user-state associated data must not be empty",
        ));
    }
    let mut rng = hpke_rng()?;
    let (encapped_key, mut sender) = setup_sender::<AesGcm128, HkdfSha256, DhP256HkdfSha256, _>(
        &OpModeS::Base,
        public_key,
        USER_STATE_INFO,
        &mut rng,
    )
    .map_err(|_| JsValue::from_str("user-state sealing failed"))?;
    let ciphertext = sender
        .seal(plaintext, aad)
        .map_err(|_| JsValue::from_str("user-state sealing failed"))?;
    serde_wasm_bindgen::to_value(&UserStateEnvelope {
        version: USER_STATE_VERSION,
        kem: HPKE_KEM.into(),
        kdf: HPKE_KDF.into(),
        aead: HPKE_AEAD.into(),
        encapsulated_key: URL_SAFE_NO_PAD.encode(encapped_key.to_bytes()),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
    .map_err(|_| JsValue::from_str("user-state envelope serialization failed"))
}

fn labeled_extract(salt: &[u8], suite_id: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled_ikm =
        Vec::with_capacity(HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    prk.into()
}

fn labeled_expand(
    prk: &[u8],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), JsValue> {
    let length = u16::try_from(output.len())
        .map_err(|_| JsValue::from_str("HPKE output length is invalid"))?;
    let mut labeled_info = Vec::with_capacity(
        2 + HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + info.len(),
    );
    labeled_info.extend_from_slice(&length.to_be_bytes());
    labeled_info.extend_from_slice(HPKE_VERSION_LABEL);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| JsValue::from_str("HPKE key schedule failed"))?
        .expand(&labeled_info, output)
        .map_err(|_| JsValue::from_str("HPKE key schedule failed"))
}

fn receiver_key_schedule(
    dh: &[u8],
    enc: &[u8],
    recipient_public_key: &[u8],
) -> Result<([u8; 16], [u8; 12]), JsValue> {
    // RFC 9180 §4.1: DHKEM(P-256, HKDF-SHA256) ExtractAndExpand.
    let eae_prk = labeled_extract(&[], KEM_SUITE_ID, b"eae_prk", dh);
    let mut kem_context = Vec::with_capacity(enc.len() + recipient_public_key.len());
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(recipient_public_key);
    let mut shared_secret = [0_u8; 32];
    labeled_expand(
        &eae_prk,
        KEM_SUITE_ID,
        b"shared_secret",
        &kem_context,
        &mut shared_secret,
    )?;

    // RFC 9180 §5.1: base mode (mode=0), empty PSK and PSK ID.
    let psk_id_hash = labeled_extract(&[], HPKE_SUITE_ID, b"psk_id_hash", &[]);
    let info_hash = labeled_extract(&[], HPKE_SUITE_ID, b"info_hash", USER_STATE_INFO);
    let mut key_schedule_context = Vec::with_capacity(65);
    key_schedule_context.push(0);
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);
    let secret = labeled_extract(&shared_secret, HPKE_SUITE_ID, b"secret", &[]);
    shared_secret.fill(0);

    let mut key = [0_u8; 16];
    let mut base_nonce = [0_u8; 12];
    labeled_expand(
        &secret,
        HPKE_SUITE_ID,
        b"key",
        &key_schedule_context,
        &mut key,
    )?;
    labeled_expand(
        &secret,
        HPKE_SUITE_ID,
        b"base_nonce",
        &key_schedule_context,
        &mut base_nonce,
    )?;
    Ok((key, base_nonce))
}

pub async fn open_user_state(
    private_key: &CryptoKey,
    recipient_public_key: &PublicKey,
    envelope: JsValue,
    aad: &[u8],
) -> Result<Uint8Array, JsValue> {
    if aad.is_empty() {
        return Err(JsValue::from_str(
            "user-state associated data must not be empty",
        ));
    }
    let envelope: UserStateEnvelope = serde_wasm_bindgen::from_value(envelope)
        .map_err(|_| JsValue::from_str("invalid user-state envelope"))?;
    if envelope.version != USER_STATE_VERSION
        || envelope.kem != HPKE_KEM
        || envelope.kdf != HPKE_KDF
        || envelope.aead != HPKE_AEAD
    {
        return Err(JsValue::from_str("unsupported user-state envelope"));
    }
    let enc = URL_SAFE_NO_PAD
        .decode(envelope.encapsulated_key)
        .map_err(|_| JsValue::from_str("invalid user-state envelope"))?;
    let encapped_public_key = PublicKey::from_bytes(&enc)
        .map_err(|_| JsValue::from_str("invalid user-state envelope"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(envelope.ciphertext)
        .map_err(|_| JsValue::from_str("invalid user-state envelope"))?;
    if ciphertext.len() < 16 {
        return Err(JsValue::from_str("invalid user-state envelope"));
    }

    let ephemeral_key = import_public_key(encapped_public_key.to_bytes().as_slice()).await?;
    let mut dh = derive_bits(private_key, &ephemeral_key).await?;
    let recipient_public_bytes = recipient_public_key.to_bytes();
    let (mut key, nonce) = receiver_key_schedule(
        &dh,
        encapped_public_key.to_bytes().as_slice(),
        recipient_public_bytes.as_slice(),
    )?;
    dh.fill(0);
    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|_| JsValue::from_str("user-state opening failed"))?;
    let plaintext = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| JsValue::from_str("user-state opening failed"));
    key.fill(0);
    let plaintext = plaintext?;
    Ok(Uint8Array::from(plaintext.as_slice()))
}
