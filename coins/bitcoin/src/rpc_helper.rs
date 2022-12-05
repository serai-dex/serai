use std::{
    error,
    fmt::{self, Display},
    io, result,
};
use thiserror::Error;

use bitcoin::{
    self,
    hashes::{
        hex::{self, FromHex, ToHex},
    },
    secp256k1, OutPoint, Transaction,
};
use serde::{de::Error as SerdeError, ser, Deserialize, Serialize};
#[derive(Deserialize, Debug)]
pub struct RpcResponseError {
    pub code: i64,
    pub message: String,
}

impl Default for RpcResponseError {
    fn default() -> Self {
        RpcResponseError {
            code: -1,
            message: String::from(""),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct RpcResponse<T> {
    pub result: Option<T>,
    #[serde(default)]
    pub id: Option<i64>,
    #[serde(default)]
    pub error: Option<RpcResponseError>,
}

#[derive(Serialize)]
pub struct RpcParams<'a, T> {
    pub jsonrpc: &'a str,
    pub id: (),
    pub method: &'a str,
    pub params: T,
}

/// The error type for errors produced in this library.
#[derive(Debug)]
pub enum RpcError {
    Hex(hex::Error),
    Json(serde_json::error::Error),
    BitcoinSerialization(bitcoin::consensus::encode::Error),
    Secp256k1(secp256k1::Error),
    Io(io::Error),
    InvalidAmount(bitcoin::util::amount::ParseAmountError),
    InvalidCookieFile,
    /// The JSON result had an unexpected structure.
    UnexpectedStructure,
    /// The daemon returned an error string.
    ReturnedError(String),
}

impl From<hex::Error> for RpcError {
    fn from(e: hex::Error) -> RpcError {
        RpcError::Hex(e)
    }
}

impl From<serde_json::error::Error> for RpcError {
    fn from(e: serde_json::error::Error) -> RpcError {
        RpcError::Json(e)
    }
}

impl From<bitcoin::consensus::encode::Error> for RpcError {
    fn from(e: bitcoin::consensus::encode::Error) -> RpcError {
        RpcError::BitcoinSerialization(e)
    }
}

impl From<secp256k1::Error> for RpcError {
    fn from(e: secp256k1::Error) -> RpcError {
        RpcError::Secp256k1(e)
    }
}

impl From<io::Error> for RpcError {
    fn from(e: io::Error) -> RpcError {
        RpcError::Io(e)
    }
}

impl From<bitcoin::util::amount::ParseAmountError> for RpcError {
    fn from(e: bitcoin::util::amount::ParseAmountError) -> RpcError {
        RpcError::InvalidAmount(e)
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RpcError::Hex(ref e) => write!(f, "hex decode error: {}", e),
            RpcError::Json(ref e) => write!(f, "JSON error: {}", e),
            RpcError::BitcoinSerialization(ref e) => write!(f, "Bitcoin serialization error: {}", e),
            RpcError::Secp256k1(ref e) => write!(f, "secp256k1 error: {}", e),
            RpcError::Io(ref e) => write!(f, "I/O error: {}", e),
            RpcError::InvalidAmount(ref e) => write!(f, "invalid amount: {}", e),
            RpcError::InvalidCookieFile => write!(f, "invalid cookie file"),
            RpcError::UnexpectedStructure => write!(f, "the JSON result had an unexpected structure"),
            RpcError::ReturnedError(ref s) => write!(f, "the daemon returned an error string: {}", s),
        }
    }
}

impl error::Error for RpcError {
    fn description(&self) -> &str {
        "bitcoincore-rpc error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            RpcError::Hex(ref e) => Some(e),
            RpcError::Json(ref e) => Some(e),
            RpcError::BitcoinSerialization(ref e) => Some(e),
            RpcError::Secp256k1(ref e) => Some(e),
            RpcError::Io(ref e) => Some(e),
            _ => None,
        }
    }
}
/// specific Error type;
pub type Result<T> = result::Result<T, RpcError>;

/// Shorthand for converting a variable into a serde_json::Value.
pub fn into_json<T>(val: T) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
pub fn opt_into_json<T>(opt: Option<T>) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(into_json(val)?),
        None => Ok(serde_json::Value::Null),
    }
}

impl ser::Error for RpcError {
    fn custom<T: Display>(msg: T) -> Self {
        RpcError::ReturnedError(msg.to_string())
    }
}

/// deserialize_hex_array_opt deserializes a vector of hex-encoded byte arrays.
pub fn deserialize_hex_array_opt<'de, D>(
    deserializer: D,
) -> result::Result<Option<Vec<Vec<u8>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    //TODO(stevenroose) Revisit when issue is fixed:
    // https://github.com/serde-rs/serde/issues/723

    let v: Vec<String> = Vec::deserialize(deserializer)?;
    let mut res = Vec::new();
    for h in v.into_iter() {
        res.push(FromHex::from_hex(&h).map_err(D::Error::custom)?);
    }
    Ok(Some(res))
}

pub fn null() -> serde_json::Value {
    serde_json::Value::Null
}

pub fn empty_obj() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
}

pub fn empty_arr() -> serde_json::Value {
    serde_json::Value::Array(vec![])
}

#[derive(Clone, Error, Debug)]
pub enum RpcConnectionError {
    #[error("connection error")]
    ConnectionError,
    #[error("parsing error")]
    ParsingError,
    #[error("result error")]
    ResultError(String),
}

pub fn handle_defaults<'a, 'b>(
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

pub trait RawTx: Sized + Clone {
    fn raw_hex(self) -> String;
}

impl<'a> RawTx for &'a Transaction {
    fn raw_hex(self) -> String {
        bitcoin::consensus::encode::serialize(self).to_vec().to_hex()
    }
}

impl<'a> RawTx for &'a [u8] {
    fn raw_hex(self) -> String {
        self.to_hex()
    }
}

impl<'a> RawTx for &'a Vec<u8> {
    fn raw_hex(self) -> String {
        self.to_hex()
    }
}

impl<'a> RawTx for &'a str {
    fn raw_hex(self) -> String {
        self.to_owned()
    }
}

impl RawTx for String {
    fn raw_hex(self) -> String {
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonOutPoint {
    pub txid: bitcoin::Txid,
    pub vout: u32,
}

impl From<OutPoint> for JsonOutPoint {
    fn from(o: OutPoint) -> JsonOutPoint {
        JsonOutPoint {
            txid: o.txid,
            vout: o.vout,
        }
    }
}

impl From<JsonOutPoint> for OutPoint {
    fn from(jop: JsonOutPoint) -> OutPoint {
        OutPoint {
            txid: jop.txid,
            vout: jop.vout,
        }
    }
}
