use thiserror::Error;
use std::io;

use crate::core::crypto::CryptoError;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("failed to serialize or deserialize data")]
    Serialization,

    #[error("cryptography error: {0}")]
    Crypto(String),

    #[error("vault cache is inconsistent with stored state")]
    CacheInconsistent,

    #[error("a vault with this name already exists")]
    VaultAlreadyExists,

    #[error("vault not found")]
    VaultNotFound,

    #[error("requested resource not found")]
    ResourceNotFound,

    #[error("no active vault is currently unlocked")]
    NoActiveVault,

    #[error("this feature is not yet implemented")]
    NotImplemented,

    #[error("invalid URI provided")]
    InvalidURI,

    #[error("invalid file path provided")]
    InvalidPath,

    #[error("unable to access location: {0}")]
    UnableToAccessLocation(String),

    #[error("storage backend error: {0}")]
    Storage(String),

    #[error("shell command failed")]
    ShellError,

    #[error("{0}")]
    Generic(String),

    #[error("unknown error: {0}")]
    Unknown(String),
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        VaultError::Crypto(e.to_string())
    }
}
