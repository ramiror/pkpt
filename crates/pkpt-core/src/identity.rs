//! Root key (derivada de 24 palabras) y device keys.

use age::secrecy::ExposeSecret;
use age::x25519;
use bip39::Mnemonic;
use ed25519_dalek::{Signature, Signer, SigningKey};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::devicelist::{DeviceEntry, DeviceList, LIST_TTL_SECS, SignedDeviceList};
use crate::error::{Error, Result};

const ROOT_HKDF_SALT: &[u8] = b"pkpt";
const ROOT_HKDF_INFO: &[u8] = b"pkpt root ed25519 v1";

/// Clave raíz de la identidad. Solo firma cambios de la device list.
pub struct RootKey {
    signing: SigningKey,
}

impl RootKey {
    /// Genera una identidad nueva. Devuelve las 24 palabras para el backup en papel.
    pub fn generate() -> (String, RootKey) {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("32 bytes es entropía válida");
        let root = Self::from_mnemonic(&mnemonic);
        (mnemonic.to_string(), root)
    }

    /// Regenera la root a partir de las 24 palabras.
    pub fn from_phrase(phrase: &str) -> Result<RootKey> {
        let mnemonic = Mnemonic::parse(phrase).map_err(|_| Error::InvalidPhrase)?;
        Ok(Self::from_mnemonic(&mnemonic))
    }

    fn from_mnemonic(mnemonic: &Mnemonic) -> RootKey {
        let seed = mnemonic.to_seed("");
        let mut sk = [0u8; 32];
        Hkdf::<Sha256>::new(Some(ROOT_HKDF_SALT), &seed)
            .expand(ROOT_HKDF_INFO, &mut sk)
            .expect("32 bytes entra en HKDF-SHA256");
        RootKey {
            signing: SigningKey::from_bytes(&sk),
        }
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Firma una device list nueva. Vence a los 30 días; los dispositivos la re-firman solos.
    // TODO: 2-de-N dispositivos / time-lock de 72 h para cambios sin la root.
    pub fn sign_device_list(&self, version: u64, now: u64, devices: Vec<DeviceEntry>) -> SignedDeviceList {
        let list = DeviceList {
            root: self.public(),
            version,
            expires_at: now + LIST_TTL_SECS,
            devices,
        };
        let sig = self.signing.sign(&list.signed_bytes());
        SignedDeviceList {
            list,
            sig: sig.to_bytes().to_vec(),
        }
    }
}

/// Clave de un dispositivo: Ed25519 para firmar, X25519 (age) para recibir cifrado.
pub struct DeviceKey {
    name: String,
    signing: SigningKey,
    age: x25519::Identity,
}

/// Forma serializable de una device key, para el keystore.
// TODO: nunca guardarla en claro; envolverla con una KEK atada a hardware.
#[derive(Serialize, Deserialize)]
pub struct DeviceSecret {
    pub name: String,
    pub sign_seed: [u8; 32],
    pub age_secret: String,
}

impl DeviceKey {
    pub fn generate(name: impl Into<String>) -> DeviceKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        DeviceKey {
            name: name.into(),
            signing: SigningKey::from_bytes(&seed),
            age: x25519::Identity::generate(),
        }
    }

    pub fn entry(&self) -> DeviceEntry {
        DeviceEntry {
            name: self.name.clone(),
            sign_pk: self.signing.verifying_key().to_bytes(),
            age_recipient: self.age.to_public().to_string(),
        }
    }

    pub fn export(&self) -> DeviceSecret {
        DeviceSecret {
            name: self.name.clone(),
            sign_seed: self.signing.to_bytes(),
            age_secret: self.age.to_string().expose_secret().to_string(),
        }
    }

    pub fn import(secret: &DeviceSecret) -> Result<DeviceKey> {
        Ok(DeviceKey {
            name: secret.name.clone(),
            signing: SigningKey::from_bytes(&secret.sign_seed),
            age: secret
                .age_secret
                .parse()
                .map_err(|e: &str| Error::Encoding(e.into()))?,
        })
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    pub(crate) fn age_identity(&self) -> &x25519::Identity {
        &self.age
    }
}
