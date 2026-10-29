//! Device list: la identidad pública, firmada por la root.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const DOMAIN: &[u8] = b"pkpt device list v1\0";
pub const LIST_TTL_SECS: u64 = 30 * 24 * 3600;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceEntry {
    pub name: String,
    pub sign_pk: [u8; 32],
    pub age_recipient: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeviceList {
    pub root: [u8; 32],
    /// Contador monótono: nunca se acepta una versión menor a la conocida.
    pub version: u64,
    pub expires_at: u64,
    pub devices: Vec<DeviceEntry>,
}

impl DeviceList {
    pub(crate) fn signed_bytes(&self) -> Vec<u8> {
        let mut m = DOMAIN.to_vec();
        m.extend(postcard::to_stdvec(self).expect("serializar a memoria no falla"));
        m
    }

    pub fn device(&self, sign_pk: &[u8; 32]) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| &d.sign_pk == sign_pk)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedDeviceList {
    pub list: DeviceList,
    pub(crate) sig: Vec<u8>,
}

impl SignedDeviceList {
    /// Verifica la firma de la root y que no esté vencida.
    pub fn verify(&self, now: u64) -> Result<&DeviceList> {
        let sig: [u8; 64] = self.sig.as_slice().try_into().map_err(|_| Error::BadSignature)?;
        VerifyingKey::from_bytes(&self.list.root)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(&self.list.signed_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| Error::BadSignature)?;
        if now >= self.list.expires_at {
            return Err(Error::Expired);
        }
        Ok(&self.list)
    }

    pub fn root(&self) -> [u8; 32] {
        self.list.root
    }
}
