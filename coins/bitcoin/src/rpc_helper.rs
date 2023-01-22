use thiserror::Error;
use bitcoin::{
    self, Transaction,
    hashes::{
        hex::{self, ToHex},
    },
    secp256k1,
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

// Code originally thanks to https://github.com/rust-bitcoin/rust-bitcoincore-rpc (Line 78-135)
pub(crate) fn handle_defaults<'a, 'b>(
    args: &'a mut [serde_json::Value],
    defaults: &'b [serde_json::Value],
) -> &'a [serde_json::Value] {
    assert!(args.len() >= defaults.len());

    // Pass over the optional arguments in backwards order, filling in defaults after the first
    // non-null optional argument has been observed.
    let mut first_non_null_optional_idx = None;
    for i in 0..defaults.len() {
        let args_i = args.len() - 1 - i;
        let defaults_i = defaults.len() - 1 - i;
        if args[args_i] == serde_json::Value::Null {
            if first_non_null_optional_idx.is_some() {
                if defaults[defaults_i] == serde_json::Value::Null {
                    panic!("Missing `default` for argument idx {}", args_i);
                }
                args[args_i] = defaults[defaults_i].clone();
            }
        } else if first_non_null_optional_idx.is_none() {
            first_non_null_optional_idx = Some(args_i);
        }
    }

    let required_num = args.len() - defaults.len();

    if let Some(i) = first_non_null_optional_idx {
        &args[..i + 1]
    } else {
        &args[..required_num]
    }
}


pub(crate) fn into_json<T>(val: T) -> Result<serde_json::Value, RpcError>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

pub(crate) fn opt_into_json<T>(opt: Option<T>) -> Result<serde_json::Value, RpcError>
where
    T: serde::ser::Serialize,
{
    Ok(into_json(Some(opt))?)
}

pub trait RawTx: Sized + Clone {
    fn raw_hex(self) -> String;
}

impl<'a> RawTx for &'a Transaction {
    fn raw_hex(self) -> String {
        bitcoin::consensus::encode::serialize(self).to_vec().to_hex()
    }
}
