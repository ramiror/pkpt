//! pkpt-core: identidades, device lists, contactos, firmas y cifrado.
//!
//! Ver `docs/ARCHITECTURE.md` para el modelo completo.

pub mod contact;
pub mod devicelist;
pub mod error;
pub mod identity;
pub mod message;

pub use contact::{Contact, ContactBook, Trust};
pub use devicelist::{DeviceEntry, DeviceList, SignedDeviceList};
pub use error::{Error, Result};
pub use identity::{DeviceKey, DeviceSecret, RootKey};
pub use message::{DetachedSignature, Opened, Verified, decrypt, encrypt};

/// Segundos desde epoch. Todas las APIs reciben `now` explícito para ser testeables.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("reloj antes de 1970")
        .as_secs()
}
