//! Contactos: codificación `pkpt1…`, palabras de seguridad y agenda con contador monótono.

use std::collections::HashMap;

use bech32::{Bech32m, Hrp};
use bip39::Language;
use sha2::{Digest, Sha256};

use crate::devicelist::SignedDeviceList;
use crate::error::{Error, Result};

const HRP: &str = "pkpt";
const SAFETY_DOMAIN: &[u8] = b"pkpt safety words v1\0";

/// Codifica una identidad pública como `pkpt1…` (Bech32m).
pub fn encode(list: &SignedDeviceList) -> Result<String> {
    let data = postcard::to_stdvec(list)?;
    bech32::encode::<Bech32m>(Hrp::parse(HRP).unwrap(), &data).map_err(|e| Error::Encoding(e.to_string()))
}

/// Decodifica `pkpt1…` (sin importar mayúsculas) y verifica la firma de la root.
pub fn decode(s: &str, now: u64) -> Result<SignedDeviceList> {
    let (hrp, data) = bech32::decode(s.trim()).map_err(|e| Error::Encoding(e.to_string()))?;
    if hrp != Hrp::parse(HRP).unwrap() {
        return Err(Error::Encoding(format!("prefijo inesperado: {hrp}")));
    }
    let list: SignedDeviceList = postcard::from_bytes(&data)?;
    list.verify(now)?;
    Ok(list)
}

/// 6 palabras BIP39 (66 bits) derivadas de la root, para comparar por teléfono.
pub fn safety_words(root: &[u8; 32]) -> [&'static str; 6] {
    let mut h = Sha256::new();
    h.update(SAFETY_DOMAIN);
    h.update(root);
    let digest = h.finalize();
    let bits = u128::from_be_bytes(digest[..16].try_into().unwrap());
    let words = Language::English.word_list();
    std::array::from_fn(|i| words[((bits >> (128 - 11 * (i + 1))) & 0x7ff) as usize])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Agregado por link; falta comparar palabras de seguridad.
    Unverified,
    /// QR escaneado en persona o palabras comparadas.
    Verified,
}

#[derive(Clone, Debug)]
pub struct Contact {
    /// Apodo local: el nombre lo pone cada uno.
    pub petname: String,
    pub trust: Trust,
    pub list: SignedDeviceList,
}

#[derive(Default)]
pub struct ContactBook {
    contacts: HashMap<[u8; 32], Contact>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Update {
    Updated { from: u64, to: u64 },
    Unchanged,
}

impl ContactBook {
    pub fn add(
        &mut self,
        petname: impl Into<String>,
        list: SignedDeviceList,
        trust: Trust,
        now: u64,
    ) -> Result<()> {
        list.verify(now)?;
        let root = list.root();
        if let Some(existing) = self.contacts.get(&root)
            && list.list.version < existing.list.list.version
        {
            return Err(Error::Stale {
                have: existing.list.list.version,
                got: list.list.version,
            });
        }
        self.contacts.insert(
            root,
            Contact {
                petname: petname.into(),
                trust,
                list,
            },
        );
        Ok(())
    }

    pub fn get(&self, root: &[u8; 32]) -> Option<&Contact> {
        self.contacts.get(root)
    }

    pub fn verify(&mut self, root: &[u8; 32]) {
        if let Some(c) = self.contacts.get_mut(root) {
            c.trust = Trust::Verified;
        }
    }

    /// Incorpora una device list recibida (adjunta a un mensaje o por gossip).
    /// Solo para contactos conocidos; gana la versión más alta.
    pub fn observe(&mut self, list: &SignedDeviceList, now: u64) -> Result<Update> {
        // Una lista vencida igual puede traer una revocación: se acepta si es más nueva,
        // pero no se usa para cifrar hasta que llegue una vigente.
        match list.verify(now) {
            Ok(_) | Err(Error::Expired) => {}
            Err(e) => return Err(e),
        }
        let contact = self.contacts.get_mut(&list.root()).ok_or(Error::WrongIdentity)?;
        let (have, got) = (contact.list.list.version, list.list.version);
        if got < have {
            return Err(Error::Stale { have, got });
        }
        if got == have {
            return Ok(Update::Unchanged);
        }
        contact.list = list.clone();
        Ok(Update::Updated { from: have, to: got })
    }
}
