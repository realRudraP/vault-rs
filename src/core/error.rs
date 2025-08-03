use serde_json;
use std::io;

use crate::core::crypto::CryptoError;
#[derive(Debug)]
pub enum VaultError {
    Io(io::Error),
    Serialization,
    Crypto(String),
    VaultAlreadyExists,
    VaultNotFound,
    NotImplementedError,
    InvalidURI,
    UnableToAccessLocation(String),
    Generic(String),
    Unknown(String),
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        VaultError::Crypto(e.to_string())
    }
}

impl From<std::io::Error> for VaultError {
    fn from(value: std::io::Error) -> Self {
        VaultError::Io(value)
    }
}
