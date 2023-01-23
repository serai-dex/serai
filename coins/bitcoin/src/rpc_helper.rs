use thiserror::Error;
use bitcoin::{
    self, secp256k1,
    hashes::{
        hex::{self},
    },
};
use serde::{Deserialize, Serialize};

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Read error")]
    ReadError { source: std::io::Error },

    #[error("Serialization error")]
    BitcoinSerialization(#[from] bitcoin::consensus::encode::Error),

    #[error("reqwest error")]
    ReqWestError(#[from] reqwest::Error),

    #[error("serde error")]
    SerdeError(#[from] serde_json::error::Error),

    #[error("parsing error")]
    ParsingError,

    #[error("Hex error")]
    HexError(#[from] hex::Error),

    #[error("Bitcoin amount error")]
    ParseAmountError(#[from] bitcoin::util::amount::ParseAmountError),

    #[error("Secp256k1 error")]
    Secp256k1Error(#[from] secp256k1::Error),

    #[error("custom : {0}")]
    CustomError(String),
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct RpcResponseError {
    pub(crate) code: i64,
    pub(crate) message: String,
}

impl Default for RpcResponseError {
    fn default() -> Self {
        RpcResponseError {
            code: -1,
            message: String::from(""),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct RpcResponse<T> {
    pub(crate) result: Option<T>,
    #[serde(default)]
    pub(crate) id: Option<i64>,
    #[serde(default)]
    pub(crate) error: Option<RpcResponseError>,
}

#[derive(Serialize)]
pub(crate) struct RpcParams<T> {
    pub(crate) jsonrpc: String,
    pub(crate) id: (),
    pub(crate) method: String,
    pub(crate) params: T,
}
