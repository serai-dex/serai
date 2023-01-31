// Code originally thanks to https://github.com/rust-bitcoin/rust-bitcoincore-rpc
use crate::rpc_helper::*;

pub(crate) fn opt_into_json<T>(opt: Option<T>) -> Result<serde_json::Value, RpcError>
where
  T: serde::ser::Serialize,
{
  into_json(Some(opt))
}
