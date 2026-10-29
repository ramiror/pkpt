#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("frase de recuperación inválida")]
    InvalidPhrase,
    #[error("firma inválida")]
    BadSignature,
    #[error("el dispositivo no está en la device list del firmante")]
    UnknownDevice,
    #[error("device list vencida")]
    Expired,
    #[error("device list vieja: tengo v{have}, llegó v{got}")]
    Stale { have: u64, got: u64 },
    #[error("la device list pertenece a otra identidad")]
    WrongIdentity,
    #[error("no soy destinatario de este mensaje")]
    NotARecipient,
    #[error("sin destinatarios")]
    NoRecipients,
    #[error("codificación: {0}")]
    Encoding(String),
    #[error("cifrado: {0}")]
    Encrypt(String),
    #[error("descifrado: {0}")]
    Decrypt(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<postcard::Error> for Error {
    fn from(e: postcard::Error) -> Self {
        Error::Encoding(e.to_string())
    }
}
