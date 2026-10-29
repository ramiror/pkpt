//! Firmas desprendidas y cifrado (firmar, después cifrar con age).

use std::io::{Read, Write};

use age::x25519;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::devicelist::SignedDeviceList;
use crate::error::{Error, Result};
use crate::identity::DeviceKey;

const SIG_DOMAIN: &[u8] = b"pkpt detached signature v1\0";
const SEAL_DOMAIN: &[u8] = b"pkpt sealed message v1\0";
const ARMOR_BEGIN: &str = "-----BEGIN PKPT SIGNATURE-----";
const ARMOR_END: &str = "-----END PKPT SIGNATURE-----";

/// Firma desprendida. Lleva la device list del firmante: la firma la cubre,
/// así que nadie puede quitarla ni reemplazarla.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DetachedSignature {
    pub signer: SignedDeviceList,
    pub device_pk: [u8; 32],
    sig: Vec<u8>,
}

/// Quién firmó, una vez verificado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub root: [u8; 32],
    pub device_name: String,
    pub list_version: u64,
}

fn signed_bytes(domain: &[u8], signer: &SignedDeviceList, context: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = domain.to_vec();
    m.extend(postcard::to_stdvec(signer).expect("serializar a memoria no falla"));
    m.extend_from_slice(context);
    m.extend_from_slice(&Sha256::digest(data));
    m
}

fn sign_with(
    device: &DeviceKey,
    own_list: &SignedDeviceList,
    domain: &[u8],
    context: &[u8],
    data: &[u8],
) -> Result<DetachedSignature> {
    let entry = device.entry();
    own_list.list.device(&entry.sign_pk).ok_or(Error::UnknownDevice)?;
    let sig = device.sign(&signed_bytes(domain, own_list, context, data));
    Ok(DetachedSignature {
        signer: own_list.clone(),
        device_pk: entry.sign_pk,
        sig: sig.to_bytes().to_vec(),
    })
}

impl DetachedSignature {
    pub fn sign(device: &DeviceKey, own_list: &SignedDeviceList, data: &[u8]) -> Result<Self> {
        sign_with(device, own_list, SIG_DOMAIN, &[], data)
    }

    pub fn verify(&self, data: &[u8], now: u64) -> Result<Verified> {
        self.verify_with(SIG_DOMAIN, &[], data, now)
    }

    fn verify_with(&self, domain: &[u8], context: &[u8], data: &[u8], now: u64) -> Result<Verified> {
        let list = self.signer.verify(now)?;
        let device = list.device(&self.device_pk).ok_or(Error::UnknownDevice)?;
        let sig: [u8; 64] = self.sig.as_slice().try_into().map_err(|_| Error::BadSignature)?;
        VerifyingKey::from_bytes(&self.device_pk)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(
                &signed_bytes(domain, &self.signer, context, data),
                &Signature::from_bytes(&sig),
            )
            .map_err(|_| Error::BadSignature)?;
        Ok(Verified {
            root: list.root,
            device_name: device.name.clone(),
            list_version: list.version,
        })
    }

    pub fn to_armored(&self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(postcard::to_stdvec(self).unwrap());
        let mut out = format!("{ARMOR_BEGIN}\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str(ARMOR_END);
        out.push('\n');
        out
    }

    pub fn from_armored(s: &str) -> Result<Self> {
        let body: String = s
            .trim()
            .strip_prefix(ARMOR_BEGIN)
            .and_then(|s| s.strip_suffix(ARMOR_END))
            .ok_or_else(|| Error::Encoding("armadura inválida".into()))?
            .split_whitespace()
            .collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|e| Error::Encoding(e.to_string()))?;
        Ok(postcard::from_bytes(&bytes)?)
    }
}

/// Contenido del `.age`: la firma cubre también la lista de destinatarios, para que un
/// destinatario no pueda re-cifrarlo a un tercero haciéndolo pasar por dirigido a él.
#[derive(Serialize, Deserialize)]
struct Sealed {
    recipients: Vec<[u8; 32]>,
    signature: DetachedSignature,
    payload: Vec<u8>,
}

/// Mensaje abierto: contenido + firmante verificado.
#[derive(Debug)]
pub struct Opened {
    pub plaintext: Vec<u8>,
    pub signer: Verified,
    /// Device list del firmante, para pasarle a `ContactBook::observe`.
    pub signer_list: SignedDeviceList,
}

/// Firma y cifra para todos los dispositivos de cada destinatario.
/// No cifra para los dispositivos propios (ver ARCHITECTURE.md).
pub fn encrypt(
    sender: &DeviceKey,
    sender_list: &SignedDeviceList,
    recipients: &[&SignedDeviceList],
    plaintext: &[u8],
    now: u64,
) -> Result<Vec<u8>> {
    let mut age_recipients: Vec<x25519::Recipient> = Vec::new();
    let mut roots = Vec::new();
    for r in recipients {
        let list = r.verify(now)?;
        roots.push(list.root);
        for d in &list.devices {
            age_recipients.push(
                d.age_recipient
                    .parse()
                    .map_err(|e: &str| Error::Encoding(e.into()))?,
            );
        }
    }
    if age_recipients.is_empty() {
        return Err(Error::NoRecipients);
    }

    let context = postcard::to_stdvec(&roots)?;
    let signature = sign_with(sender, sender_list, SEAL_DOMAIN, &context, plaintext)?;
    let inner = postcard::to_stdvec(&Sealed {
        recipients: roots,
        signature,
        payload: plaintext.to_vec(),
    })?;

    let encryptor = age::Encryptor::with_recipients(age_recipients.iter().map(|r| r as &dyn age::Recipient))
        .map_err(|e| Error::Encrypt(e.to_string()))?;
    let mut out = Vec::new();
    let mut w = encryptor
        .wrap_output(&mut out)
        .map_err(|e| Error::Encrypt(e.to_string()))?;
    w.write_all(&inner).map_err(|e| Error::Encrypt(e.to_string()))?;
    w.finish().map_err(|e| Error::Encrypt(e.to_string()))?;
    Ok(out)
}

/// Descifra, verifica la firma y que yo (`my_root`) sea destinatario.
pub fn decrypt(me: &DeviceKey, my_root: &[u8; 32], ciphertext: &[u8], now: u64) -> Result<Opened> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(|e| Error::Decrypt(e.to_string()))?;
    let mut r = decryptor
        .decrypt(std::iter::once(me.age_identity() as &dyn age::Identity))
        .map_err(|e| Error::Decrypt(e.to_string()))?;
    let mut inner = Vec::new();
    r.read_to_end(&mut inner)
        .map_err(|e| Error::Decrypt(e.to_string()))?;

    let sealed: Sealed = postcard::from_bytes(&inner)?;
    if !sealed.recipients.contains(my_root) {
        return Err(Error::NotARecipient);
    }
    let context = postcard::to_stdvec(&sealed.recipients)?;
    let signer = sealed
        .signature
        .verify_with(SEAL_DOMAIN, &context, &sealed.payload, now)?;
    Ok(Opened {
        plaintext: sealed.payload,
        signer,
        signer_list: sealed.signature.signer,
    })
}
